//! Owned disposable VM. All management exec uses non-autostarting MCP.
use crate::{
    guest_transport::{self, Companion, Management},
    host_io::{self, command},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::process::Child;

pub(crate) struct VmInputs<'a> {
    pub izanagi: &'a Path,
    pub image: &'a Path,
    pub python: &'a Path,
    pub companion: &'a Path,
    pub maximum_evidence_file_bytes: u64,
}
pub(crate) struct Vm {
    pub directory: PathBuf,
    pub workspace: PathBuf,
    pub hmac: PathBuf,
    maximum_evidence_file_bytes: u64,
    config: PathBuf,
    izanagi: PathBuf,
    up: Option<Child>,
    group: Option<u32>,
    boot_nonce: String,
    session_fingerprint: Option<String>,
    poisoned: bool,
    companion: Option<Companion>,
    management: Option<Management>,
    authorization: Option<String>,
    pub daemon_identity: Option<Value>,
}
impl Drop for Vm {
    fn drop(&mut self) {
        // Last-resort cleanup for a cancelled boot/run, before any receipt exists.
        if let Some(group) = self.group {
            unsafe {
                libc::kill(-(group as i32), libc::SIGKILL);
            }
        }
        let _ = fs::remove_file(&self.hmac);
        let _ = fs::remove_dir_all(self.workspace.join(".tempest-control"));
    }
}
impl Vm {
    pub fn izanagi_path(&self) -> &Path {
        &self.izanagi
    }
    pub async fn inspect_image(&mut self) -> io::Result<Value> {
        self.ensure_alive()?;
        let (text, error) = self
            .management
            .as_mut()
            .unwrap()
            .exec(
                "/bin/cat",
                &["/etc/tempest/image.json"],
                Duration::from_secs(10),
            )
            .await?;
        if error {
            return Err(io::Error::other("image metadata unavailable"));
        }
        let metadata: Value = serde_json::from_str(&text)?;
        let paths = [
            "/usr/local/bin/lws",
            "/usr/local/libexec/tempest-guest-native",
            "/usr/local/libexec/tempest-mailbox",
            "/usr/local/libexec/tempest-quiesce",
        ];
        let (actual, error) = self
            .management
            .as_mut()
            .unwrap()
            .exec("/usr/bin/sha256sum", &paths, Duration::from_secs(10))
            .await?;
        if error {
            return Err(io::Error::other("image binary digest failed"));
        }
        let lines: Vec<_> = actual.lines().collect();
        if lines.len() != paths.len() {
            return Err(io::Error::other("image digest output mismatch"));
        }
        for (path, line) in paths.iter().zip(lines) {
            let (digest, name) = line
                .split_once("  ")
                .ok_or_else(|| io::Error::other("invalid image digest"))?;
            if name != *path || metadata["installed_sha256"][path] != digest {
                return Err(io::Error::other("installed binary mismatch"));
            }
        }
        Ok(metadata)
    }
    pub async fn boot(directory: &Path, inputs: VmInputs<'_>) -> io::Result<Self> {
        host_io::directory(&directory.join("evidence"))?;
        let workspace = directory.join("sandbox");
        let hmac = directory.join("transport-hmac");
        host_io::write_new(
            &hmac,
            format!("{}{}", host_io::random_hex()?, host_io::random_hex()?).as_bytes(),
        )?;
        let config = directory.join("izanagi.toml");
        let template = include_str!("../../../tools/m0/izanagi.example.toml");
        host_io::write_new(
            &config,
            template
                .replace(
                    "image = \"default\"",
                    &format!("image = {}", serde_json::to_string(inputs.image)?),
                )
                .as_bytes(),
        )?;
        let companion = Companion::start(
            inputs.python,
            inputs.companion,
            &workspace,
            &directory.join("companion.stderr"),
        )
        .await?;
        let boot_nonce = host_io::random_hex()?;
        let up = command(inputs.izanagi)
            .arg("--config")
            .arg(&config)
            .arg("up")
            .current_dir(&workspace)
            .env("IZANAGI_SECRET_FILE", &hmac)
            .stdout(Stdio::from(crate::proxy_cli::private_new(
                &directory.join("up.stdout"),
            )?))
            .stderr(Stdio::from(crate::proxy_cli::private_new(
                &directory.join("up.stderr"),
            )?))
            .process_group(0)
            .kill_on_drop(true)
            .spawn()?;
        let group = up.id().unwrap();
        let mut vm = Self {
            directory: directory.to_owned(),
            workspace,
            hmac,
            maximum_evidence_file_bytes: inputs.maximum_evidence_file_bytes,
            config,
            izanagi: inputs.izanagi.to_owned(),
            up: Some(up),
            group: Some(group),
            boot_nonce,
            session_fingerprint: None,
            poisoned: false,
            companion: Some(companion),
            management: None,
            authorization: None,
            daemon_identity: None,
        };
        host_io::json_new(&directory.join("vm-owner.json"), &vm.binding_metadata())?;
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            vm.ensure_alive()?;
            if String::from_utf8_lossy(&fs::read(directory.join("up.stdout"))?)
                .contains("サンドボックスを起動しました")
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other("VM boot deadline"));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        vm.management = Some(
            Management::start(
                inputs.izanagi,
                &vm.workspace,
                &vm.hmac,
                &directory.join("management.stderr"),
            )
            .await?,
        );
        if !vm.management.as_mut().unwrap().running(group).await? {
            return Err(io::Error::other("VM session owner mismatch"));
        }
        let session_path = vm.instance_path()?.join("session.json");
        let session: Value = serde_json::from_slice(&fs::read(&session_path)?)?;
        if session["pid"] != group {
            return Err(io::Error::other("persisted VM owner mismatch"));
        }
        vm.session_fingerprint = Some(host_io::digest(&session_path)?);
        host_io::json_replace(&directory.join("vm-owner.json"), &vm.binding_metadata())?;
        let (ready, error) = vm
            .management
            .as_mut()
            .unwrap()
            .exec("/bin/echo", &["tempest-ready"], Duration::from_secs(10))
            .await?;
        if error || ready.trim() != "tempest-ready" {
            return Err(io::Error::other("VM readiness failed"));
        }
        // Verify the actual root-private mapping rather than trusting host xattrs alone.
        let code = "import os,stat,errno\np='/workspace/.tempest-control'; m=os.stat(p); assert m.st_uid==0 and stat.S_IMODE(m.st_mode)==0o700; assert not os.access(p,os.R_OK)\np='/workspace/.tempest-readonly-probe'; assert stat.S_IMODE(os.stat(p).st_mode)==0o666\ntry:\n fd=os.open(p,os.O_WRONLY|os.O_TRUNC)\nexcept OSError as e:\n assert e.errno==errno.EROFS\nelse:\n os.close(fd);raise AssertionError('share writable')\nfor name in ['token','secret']:\n try:\n  fd=os.open('/sys/firmware/qemu_fw_cfg/by_name/opt/izanagi.'+name+'/raw',os.O_RDONLY)\n except OSError as e:\n  assert e.errno in (errno.EACCES,errno.EPERM)\n else:\n  os.close(fd);raise AssertionError('fw_cfg readable')";
        let (_, error) = vm
            .management
            .as_mut()
            .unwrap()
            .exec("/usr/bin/python3", &["-c", code], Duration::from_secs(10))
            .await?;
        if error {
            return Err(io::Error::other("guest mailbox mapping failed"));
        }
        fs::remove_file(vm.workspace.join(".tempest-readonly-probe"))?;
        vm.call("ping", json!({})).await?;
        let claimed = vm.call("claim", json!({})).await?;
        vm.authorization = Some(
            claimed["token"]
                .as_str()
                .ok_or_else(|| io::Error::other("claim response missing authorization"))?
                .to_owned(),
        );
        vm.daemon_identity = Some(vm.call("attest", json!({})).await?);
        Ok(vm)
    }
    fn ensure_alive(&mut self) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other("VM is discard-only; reconnect forbidden"));
        }
        let alive = self
            .up
            .as_mut()
            .ok_or_else(|| io::Error::other("VM not owned"))
            .and_then(|up| up.try_wait())
            .map(|status| status.is_none());
        if !matches!(alive, Ok(true)) {
            self.poisoned = true;
            return Err(io::Error::other(
                "VM supervisor unavailable; do not reconnect",
            ));
        }
        if let Some(expected) = self.session_fingerprint.clone() {
            let current = self
                .instance_path()
                .and_then(|path| host_io::digest(&path.join("session.json")));
            if !matches!(current, Ok(actual) if actual == expected) {
                self.poisoned = true;
                return Err(io::Error::other("VM session changed; reconnect forbidden"));
            }
        }
        Ok(())
    }
    pub fn discard_only(&mut self) {
        self.poisoned = true;
    }
    pub fn binding_metadata(&self) -> Value {
        json!({"supervisor_pid":self.group,"boot_nonce":self.boot_nonce,"session_fingerprint":self.session_fingerprint,"companion":self.companion.as_ref().map(|v|&v.info)})
    }
    fn instance_path(&self) -> io::Result<PathBuf> {
        Ok(std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::other("HOME required"))?
            .join(".izanagi/instances")
            .join(format!(
                "{:x}",
                Sha256::digest(self.workspace.as_os_str().as_encoded_bytes())
            )))
    }
    pub async fn call(&mut self, operation: &str, mut fields: Value) -> io::Result<Value> {
        self.ensure_alive()?;
        if let Some(authorization) = &self.authorization {
            fields["authorization"] = authorization.clone().into();
        }
        let result = guest_transport::call(
            self.companion.as_mut().unwrap(),
            self.management.as_mut().unwrap(),
            operation,
            fields,
        )
        .await;
        let result = match result {
            Ok(value) => value,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        self.ensure_alive()?;
        Ok(result)
    }
    pub async fn clock(&mut self, group: &str, file: &mut fs::File) -> io::Result<()> {
        self.ensure_alive()?;
        if let Err(error) =
            guest_transport::clock(self.management.as_mut().unwrap(), group, file).await
        {
            self.discard_only();
            return Err(error);
        }
        self.ensure_alive()
    }
    pub async fn export(&mut self, evidence: &Path) -> io::Result<Value> {
        let mut exported = self
            .call("export", json!({"daemon_identity":self.daemon_identity}))
            .await?;
        host_io::json_new(&evidence.join("export-index.json"), &exported)?;
        let id = exported["export_id"]
            .as_str()
            .ok_or_else(|| io::Error::other("missing export ID"))?
            .to_owned();
        let files = exported["files"]
            .as_object()
            .cloned()
            .ok_or_else(|| io::Error::other("missing export files"))?;
        if files.keys().any(|name| {
            !matches!(
                name.as_str(),
                "api.jsonl" | "capture.pcap" | "manifest.json"
            )
        }) {
            return Err(io::Error::other("unexpected export file"));
        }
        let mut collection = json!({"export_id":id,"complete":false,"files":{}});
        for name in ["api.jsonl", "capture.pcap", "manifest.json"] {
            let metadata = files.get(name).cloned().unwrap_or(Value::Null);
            collection["files"][name] = json!({"verified":false,"received_bytes":0,"expected_bytes":metadata["bytes"],"expected_sha256":metadata["sha256"],"reason":"not_started"});
        }
        host_io::json_new(&evidence.join("collection.json"), &collection)?;
        for name in ["api.jsonl", "capture.pcap", "manifest.json"] {
            let metadata = files.get(name).cloned().unwrap_or(Value::Null);
            let mut record = json!({"verified":false,"received_bytes":0,"expected_bytes":metadata["bytes"],"expected_sha256":metadata["sha256"]});
            let result = if self.poisoned {
                Err(crate::collection::error("upstream_aborted"))
            } else if metadata.is_null() {
                Err(crate::collection::error("missing_from_export"))
            } else {
                self.collect_file(evidence, &id, name, &metadata, &mut record)
                    .await
            };
            if let Err(error) = result {
                record["reason"] = crate::collection::reason(&error).into();
                let partial = evidence.join(format!(".{name}.partial"));
                if partial.exists() && fs::remove_file(partial).is_err() {
                    record["partial_cleanup_failed"] = true.into();
                }
            }
            collection["files"][name] = record;
            host_io::json_replace(&evidence.join("collection.json"), &collection)?;
        }
        collection["complete"] = collection["files"]
            .as_object()
            .is_some_and(|files| files.values().all(|record| record["verified"] == true))
            .into();
        host_io::json_replace(&evidence.join("collection.json"), &collection)?;
        exported["collection_complete"] = collection["complete"].clone();
        Ok(exported)
    }
    async fn collect_file(
        &mut self,
        evidence: &Path,
        id: &str,
        name: &str,
        metadata: &Value,
        record: &mut Value,
    ) -> io::Result<()> {
        use crate::collection::error;
        let size = metadata["bytes"]
            .as_u64()
            .ok_or_else(|| error("invalid_index"))?;
        if size > self.maximum_evidence_file_bytes {
            return Err(error("file_size_limit"));
        }
        let expected = metadata["sha256"]
            .as_str()
            .filter(|s| crate::collection::valid_hash(s))
            .ok_or_else(|| error("invalid_index"))?;
        let partial = evidence.join(format!(".{name}.partial"));
        let mut file = crate::proxy_cli::private_new(&partial)?;
        let mut hash = Sha256::new();
        let mut offset = 0;
        let deadline = Instant::now() + Duration::from_secs(300);
        while offset < size {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| error("transfer_deadline"))?;
            let reply = tokio::time::timeout(
                remaining,
                self.call(
                    "fetch",
                    json!({"export_id":id,"file":name,"offset":offset,"max_bytes":32768}),
                ),
            )
            .await;
            let reply = match reply {
                Ok(Ok(value)) => value,
                Ok(Err(_)) => return Err(error("transport_error")),
                Err(_) => {
                    self.discard_only();
                    return Err(error("transfer_deadline"));
                }
            };
            let data = match crate::collection::chunk(&reply, id, name, offset, size, expected) {
                Ok(data) => data,
                Err(error) => {
                    self.discard_only();
                    return Err(error);
                }
            };
            file.write_all(&data)?;
            hash.update(&data);
            offset += data.len() as u64;
            record["received_bytes"] = offset.into();
        }
        file.sync_all()?;
        let observed = format!("{:x}", hash.finalize());
        record["observed_sha256"] = observed.clone().into();
        if observed != expected {
            self.discard_only();
            return Err(error("file_hash_mismatch"));
        }
        fs::rename(partial, evidence.join(name))?;
        record["verified"] = true.into();
        Ok(())
    }
    pub async fn shutdown(&mut self) -> io::Result<Value> {
        let management_ok = match self.management.take() {
            Some(value) => value.stop().await.is_ok(),
            None => true,
        };
        let companion_ok = match self.companion.take() {
            Some(value) => value.stop().await.is_ok(),
            None => true,
        };
        let down = command(&self.izanagi)
            .arg("--config")
            .arg(&self.config)
            .arg("down")
            .current_dir(&self.workspace)
            .env("IZANAGI_SECRET_FILE", &self.hmac)
            .stdout(Stdio::from(crate::proxy_cli::private_new(
                &self.directory.join("down.stdout"),
            )?))
            .stderr(Stdio::from(crate::proxy_cli::private_new(
                &self.directory.join("down.stderr"),
            )?))
            .kill_on_drop(true)
            .spawn()?;
        let down_ok = tokio::time::timeout(Duration::from_secs(30), down.wait_with_output())
            .await
            .is_ok_and(|status| status.is_ok_and(|s| s.status.success()));
        let mut forced = false;
        let mut up_ok = false;
        if let Some(up) = &mut self.up {
            match tokio::time::timeout(Duration::from_secs(30), up.wait()).await {
                Ok(status) => {
                    up_ok = status?.success();
                }
                Err(_) => {
                    forced = true;
                    if let Some(group) = self.group {
                        unsafe {
                            libc::kill(-(group as i32), libc::SIGKILL);
                        }
                    }
                    tokio::time::timeout(Duration::from_secs(5), up.wait())
                        .await
                        .map_err(|_| io::Error::other("VM did not stop"))??;
                }
            }
        }
        self.up.take();
        self.group = None;
        if self.hmac.exists() {
            fs::remove_file(&self.hmac)?;
        }
        let inbox = self.workspace.join(".tempest-control");
        if inbox.exists() {
            fs::remove_dir_all(inbox)?;
        }
        let mut partial_files_removed = Vec::new();
        let evidence = self.directory.join("evidence");
        if evidence.is_dir() {
            for entry in fs::read_dir(&evidence)? {
                let entry = entry?;
                let name = entry.file_name();
                let text = name.to_string_lossy();
                if entry.file_type()?.is_file()
                    && text.starts_with('.')
                    && text.ends_with(".partial")
                {
                    fs::remove_file(entry.path())?;
                    partial_files_removed.push(text.into_owned());
                }
            }
        }
        let logs = self.directory.join("evidence/izanagi");
        host_io::directory(&logs)?;
        let instance = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::other("HOME required"))?
            .join(".izanagi/instances")
            .join(format!(
                "{:x}",
                Sha256::digest(self.workspace.as_os_str().as_encoded_bytes())
            ))
            .join("logs");
        let mut missing = Vec::new();
        for name in ["events.log", "alerts.log"] {
            if instance.join(name).is_file() {
                host_io::private_copy(&instance.join(name), &logs.join(name))?;
            } else {
                missing.push(name);
            }
        }
        Ok(
            json!({"management_stopped":management_ok,"companion_stopped":companion_ok,"down_succeeded":down_ok,"up_exited_successfully":up_ok,"forced_group_stop":forced,"missing_logs":missing,"partial_files_removed":partial_files_removed}),
        )
    }
}
