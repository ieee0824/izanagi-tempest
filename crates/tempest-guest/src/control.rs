use crate::{config::Config, proxy, seed};
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tempest_model::guest::{ApiRecord, ProbeRequest, SeedBundle};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    process::Child,
    signal::unix::{SignalKind, signal},
};

const CONTROL_LIMIT: u64 = 16 * 1024;
const FILE_LIMIT: u64 = 8 * 1024 * 1024;
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Claim,
    Seed { file: PathBuf },
    Probe { file: PathBuf },
    Seal,
    Export { directory: PathBuf },
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub token: Option<String>,
    pub operation: Operation,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Unclaimed,
    Claimed,
    Seeding,
    Seeded,
    Sealing,
    Sealed,
    Finalizing,
    Exported,
    Failed,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    phase: Phase,
    token_digest: Option<String>,
    #[serde(default)]
    transitions: Vec<Phase>,
    #[serde(default)]
    failed_operations: std::collections::BTreeMap<String, u64>,
}
#[derive(Default, Serialize)]
struct CaptureStats {
    captured: Option<u64>,
    dropped: Option<u64>,
    read_failed: bool,
}
struct Controller {
    config: Config,
    state: State,
    lws: Option<Child>,
    proxy: Option<Child>,
    capture: Option<Child>,
    capture_stats: Option<tokio::task::JoinHandle<CaptureStats>>,
    setup: Option<SeedBundle>,
    access_keys: tempest_model::guest::AccessKeys,
    client: proxy::HttpClient,
    manifest: Option<Value>,
    capture_started: Option<String>,
    recorder_started: Option<String>,
}
fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
fn directory(path: &Path, uid: u32, gid: u32) -> Result<()> {
    if !path.exists() {
        fs::DirBuilder::new().recursive(true).create(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "private directory must not be a symlink"
    );
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() } || metadata.uid() == uid,
        "unexpected private directory owner"
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    if unsafe { libc::geteuid() } == 0 {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let name = CString::new(path.as_os_str().as_bytes())?;
        ensure!(
            unsafe { libc::chown(name.as_ptr(), uid, gid) } == 0,
            "set private directory owner failed"
        );
    }
    Ok(())
}
fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
fn read_private<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = read_private_bytes(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid private input JSON or shape"))
}
fn read_private_bytes(path: &Path) -> Result<Vec<u8>> {
    ensure!(path.is_absolute(), "input file path must be absolute");
    let parent = fs::metadata(path.parent().context("input parent unavailable")?)?;
    ensure!(
        parent.is_dir() && parent.uid() == unsafe { libc::geteuid() } && parent.mode() & 0o077 == 0,
        "input parent must be private and owned by controller uid"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .context("open private input")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "input must be a private regular file owned by controller uid"
    );
    let mut bytes = Vec::new();
    file.take(FILE_LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= FILE_LIMIT,
        "input exceeds 8 MiB limit"
    );
    Ok(bytes)
}
struct RemoveInput(PathBuf);
impl Drop for RemoveInput {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
impl Controller {
    fn persist(&self) -> Result<()> {
        let path = self
            .config
            .state_dir
            .join(format!("state-{}.tmp", seed::random_secret()));
        private_write(&path, &serde_json::to_vec(&self.state)?)?;
        fs::rename(&path, self.config.state_dir.join("state.json"))?;
        File::open(&self.config.state_dir)?.sync_all()?;
        Ok(())
    }
    fn transition(&mut self, phase: Phase) -> Result<()> {
        self.state.phase = phase;
        self.state.transitions.push(phase);
        self.persist()
    }
    fn authorize(&self, request: &Request) -> Result<()> {
        if matches!(request.operation, Operation::Claim) {
            return Ok(());
        }
        let candidate = request
            .token
            .as_deref()
            .filter(|s| s.len() == 64)
            .context("token required or invalid")?;
        let actual = format!("{:x}", Sha256::digest(candidate.as_bytes()));
        let expected = self
            .state
            .token_digest
            .as_deref()
            .context("claim required")?;
        let difference = actual
            .as_bytes()
            .iter()
            .zip(expected.as_bytes())
            .fold(0u8, |d, (a, b)| d | (a ^ b));
        ensure!(
            actual.len() == expected.len() && difference == 0,
            "token required or invalid"
        );
        Ok(())
    }
    async fn execute(&mut self, request: Request) -> Result<Value> {
        let operation = match &request.operation {
            Operation::Claim => "claim",
            Operation::Seed { .. } => "seed",
            Operation::Probe { .. } => "probe",
            Operation::Seal => "seal",
            Operation::Export { .. } => "export",
        };
        let authorization_failed = self.authorize(&request).is_err();
        let result = self.execute_operation(request).await;
        if result.is_err() {
            let category = if authorization_failed {
                "authorization_rejected"
            } else {
                "operation_failed"
            };
            let count = self
                .state
                .failed_operations
                .entry(format!("{operation}:{category}"))
                .or_default();
            *count = count.saturating_add(1);
            self.persist()?;
        }
        result
    }
    async fn execute_operation(&mut self, request: Request) -> Result<Value> {
        self.authorize(&request)?;
        match request.operation {
            Operation::Claim => {
                ensure!(
                    self.state.phase == Phase::Unclaimed && self.state.token_digest.is_none(),
                    "claim already consumed"
                );
                let token = seed::random_secret();
                self.state.token_digest = Some(format!("{:x}", Sha256::digest(token.as_bytes())));
                self.transition(Phase::Claimed)?;
                Ok(json!({"token":token}))
            }
            Operation::Seed { file } => {
                ensure!(
                    self.state.phase == Phase::Claimed,
                    "seed requires claimed state and is allowed only once before seal"
                );
                let bytes = read_private_bytes(&file)?;
                let remove = RemoveInput(file.clone());
                let bundle: SeedBundle = serde_json::from_slice(&bytes)
                    .map_err(|_| anyhow::anyhow!("invalid seed bundle JSON or shape"))?;
                seed::validate_setup(&bundle)?;
                ensure!(
                    fs::read_dir(&self.config.data_dir)?.next().is_none(),
                    "seed requires an empty LWS data directory"
                );
                self.transition(Phase::Seeding)?;
                let mut result = self.seed(&bundle).await;
                // Deletion is part of seed success. On failures the Drop guard still removes it.
                if result.is_ok() {
                    if let Err(e) = fs::remove_file(&file).context("remove seed bundle") {
                        result = Err(e);
                    }
                }
                drop(remove);
                match result {
                    Ok(keys) => {
                        self.setup = Some(bundle);
                        self.access_keys = keys.clone();
                        self.transition(Phase::Seeded)?;
                        Ok(
                            json!({"access_keys":keys,"admin_key_rotated":true,"new_key_verified":true,"old_key_rejected":true}),
                        )
                    }
                    Err(e) => {
                        let _ = self.transition(Phase::Failed);
                        let _ = seed::stop(&mut self.lws, libc::SIGTERM, 5).await;
                        Err(e)
                    }
                }
            }
            Operation::Probe { file } => {
                ensure!(
                    self.state.phase == Phase::Seeded,
                    "probe allowed only after seed and before seal"
                );
                self.lws_alive()?;
                let probe: ProbeRequest = read_private(&file)?;
                Ok(serde_json::to_value(
                    seed::probe(
                        &self.config,
                        &probe,
                        self.setup.as_ref().context("seed setup unavailable")?,
                        &self.client,
                        self.access_keys
                            .values()
                            .any(|key| key == &probe.access_key_id),
                    )
                    .await?,
                )?)
            }
            Operation::Seal => {
                ensure!(
                    self.state.phase == Phase::Seeded,
                    "seal requires seeded state and is allowed only once"
                );
                self.lws_alive()?;
                self.transition(Phase::Sealing)?;
                match self.seal().await {
                    Ok(()) => {
                        self.transition(Phase::Sealed)?;
                        Ok(
                            json!({"sealed":true,"capture_started":self.capture_started,"recorder_started":self.recorder_started}),
                        )
                    }
                    Err(e) => {
                        let _ = self.transition(Phase::Failed);
                        let _ = seed::stop(&mut self.proxy, libc::SIGTERM, 5).await;
                        let _ = seed::stop(&mut self.capture, libc::SIGINT, 5).await;
                        Err(e)
                    }
                }
            }
            Operation::Export { directory } => {
                ensure!(
                    matches!(self.state.phase, Phase::Sealed | Phase::Exported),
                    "export requires sealed/finalized state"
                );
                if self.state.phase == Phase::Sealed {
                    self.finalize().await?;
                }
                self.export(&directory)
            }
        }
    }
    fn lws_alive(&mut self) -> Result<()> {
        ensure!(
            self.lws
                .as_mut()
                .context("LWS not running")?
                .try_wait()?
                .is_none(),
            "LWS exited"
        );
        Ok(())
    }
    async fn seed(&mut self, bundle: &SeedBundle) -> Result<tempest_model::guest::AccessKeys> {
        let old = seed::random_secret();
        self.lws = Some(seed::start_lws(&self.config, &old, &self.client).await?);
        let keys = seed::populate(&self.config, &old, bundle).await?;
        seed::stop(&mut self.lws, libc::SIGTERM, self.config.timeout_seconds).await?;
        let new = seed::random_secret();
        ensure!(new != old, "admin rotation entropy failure");
        self.lws = Some(seed::start_lws(&self.config, &new, &self.client).await?);
        let accepted = seed::admin_check(&self.config, &new, &self.client).await?;
        let denied = seed::admin_check(&self.config, &old, &self.client).await?;
        ensure!(
            accepted.status == 200
                && accepted.complete
                && denied.status == 403
                && denied.error_code.as_deref() == Some("AccessDenied")
                && denied.complete,
            "admin key rotation verification failed"
        );
        // Same persistent data is independently checked using the new admin key.
        let users = seed::aws(&self.config, &new, &["iam".into(), "list-users".into()]).await?;
        for user in &bundle.users {
            ensure!(
                users["Users"]
                    .as_array()
                    .is_some_and(|xs| xs.iter().any(|u| u["UserName"] == user.name)),
                "seeded user missing after LWS restart"
            );
        }
        Ok(keys)
    }
    async fn seal(&mut self) -> Result<()> {
        let pcap = self.config.evidence_dir.join("capture.pcap");
        let mut command = tokio::process::Command::new(&self.config.tcpdump);
        seed::child_guard(&mut command);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .args([
                "-n",
                "-U",
                "--immediate-mode",
                "-B",
                "4096",
                "-i",
                &self.config.capture_interface,
                "-w",
            ])
            .arg(&pcap)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        // All loopback traffic, including attempted bypasses; no port filter.
        if !self.config.development {
            command.args(["-Z", "root"]);
        }
        let mut capture = command.spawn().context("start loopback capture")?;
        let stderr = capture
            .stderr
            .take()
            .context("capture readiness unavailable")?;
        self.capture = Some(capture);
        let mut reader = BufReader::new(stderr);
        let ready = tokio::time::timeout(Duration::from_secs(self.config.timeout_seconds), async {
            loop {
                let mut line = String::new();
                let n = reader.read_line(&mut line).await?;
                ensure!(
                    n > 0 && line.len() < 4096,
                    "capture exited before readiness"
                );
                if line.contains("listening on") {
                    return Ok::<_, anyhow::Error>(());
                }
            }
        })
        .await
        .context("capture readiness timeout")?;
        ready?;
        self.capture_started = Some(now());
        // Keep draining statistics so stderr cannot block tcpdump during shutdown.
        self.capture_stats = Some(tokio::spawn(async move {
            let mut stats = CaptureStats::default();
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) if line.len() <= 4096 => {
                        let line = line.trim();
                        for suffix in [" packets captured", " packet captured"] {
                            if let Some(number) = line.strip_suffix(suffix) {
                                stats.captured = number.parse().ok();
                            }
                        }
                        for suffix in [" packets dropped by kernel", " packet dropped by kernel"] {
                            if let Some(number) = line.strip_suffix(suffix) {
                                stats.dropped = number.parse().ok();
                            }
                        }
                    }
                    _ => {
                        stats.read_failed = true;
                        let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
                        break;
                    }
                }
            }
            stats
        }));
        let executable = std::env::current_exe()?;
        let mut command = seed::service_command(&executable, &self.config);
        command
            .arg("__proxy")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = command.spawn().context("start lws-uid recorder")?;
        let mut stdin = child.stdin.take().context("recorder setup pipe")?;
        stdin.write_all(&serde_json::to_vec(&self.config)?).await?;
        stdin.shutdown().await?;
        drop(stdin);
        let mut stdout = child.stdout.take().context("recorder readiness pipe")?;
        self.proxy = Some(child);
        let expected = b"{\"ready\":true}\n";
        let mut frame = vec![0; expected.len()];
        tokio::time::timeout(
            Duration::from_secs(self.config.timeout_seconds),
            stdout.read_exact(&mut frame),
        )
        .await
        .context("recorder readiness timeout")??;
        ensure!(frame == expected, "recorder failed readiness");
        ensure!(
            self.capture
                .as_mut()
                .context("capture missing")?
                .try_wait()?
                .is_none(),
            "capture exited during recorder startup"
        );
        ensure!(
            self.proxy
                .as_mut()
                .context("recorder missing")?
                .try_wait()?
                .is_none(),
            "recorder exited during readiness"
        );
        self.lws_alive()?;
        self.recorder_started = Some(now());
        Ok(())
    }
    async fn finalize(&mut self) -> Result<()> {
        self.transition(Phase::Finalizing)?;
        let mut failures = Vec::new();
        if seed::stop(
            &mut self.proxy,
            libc::SIGTERM,
            self.config.timeout_seconds + 2,
        )
        .await
        .is_err()
        {
            failures.push("recorder drain/flush failed");
        }
        let recorder_stopped = now();
        if seed::stop(&mut self.capture, libc::SIGINT, self.config.timeout_seconds)
            .await
            .is_err()
        {
            failures.push("capture shutdown failed");
        }
        let capture_stopped = now();
        let stats = if let Some(task) = self.capture_stats.take() {
            match tokio::time::timeout(Duration::from_secs(2), task).await {
                Ok(Ok(stats)) => stats,
                _ => CaptureStats {
                    read_failed: true,
                    ..Default::default()
                },
            }
        } else {
            CaptureStats::default()
        };
        if stats.read_failed || stats.captured.is_none() || stats.dropped.is_none() {
            failures.push("capture statistics unavailable");
        }
        if stats.dropped.is_some_and(|n| n > 0) {
            failures.push("capture reports packets dropped by kernel");
        }
        if self.lws_alive().is_err() {
            failures.push("LWS exited during measurement");
        }
        let mut rows = 0;
        let mut incomplete = 0;
        match File::open(self.config.evidence_dir.join("api.jsonl")) {
            Ok(file) => {
                use std::io::BufRead;
                for line in std::io::BufReader::new(file).lines() {
                    let Ok(line) = line else {
                        failures.push("API evidence read failed");
                        break;
                    };
                    match serde_json::from_str::<ApiRecord>(&line) {
                        Ok(row) => {
                            rows += 1;
                            if !row.request_complete
                                || !row.response_complete
                                || row.transport_error.is_some()
                            {
                                incomplete += 1;
                            }
                        }
                        Err(_) => failures.push("invalid API evidence row"),
                    }
                }
            }
            Err(_) => failures.push("API evidence missing"),
        }
        let pcap = self.config.evidence_dir.join("capture.pcap");
        if fs::metadata(&pcap).map_or(true, |m| m.len() < 24) {
            failures.push("capture missing or incomplete header");
        }
        if rows > 0
            && (stats.captured == Some(0) || fs::metadata(&pcap).is_ok_and(|m| m.len() == 24))
        {
            failures.push("capture has no packets for observed HTTP traffic");
        }
        if incomplete > 0 {
            failures.push("incomplete HTTP observations");
        }
        let recorder_stats = match File::open(self.config.evidence_dir.join("recorder-stats.json"))
            .ok()
            .and_then(|file| {
                serde_json::from_reader::<_, tempest_model::guest::RecorderStats>(file.take(4096))
                    .ok()
            }) {
            Some(stats) => {
                if !stats.lossless() {
                    failures.push("recorder ingress coverage loss");
                }
                Some(stats)
            }
            None => {
                failures.push("recorder statistics unavailable");
                None
            }
        };
        self.manifest = Some(
            json!({"complete":failures.is_empty(),"failures":failures,"api_rows":rows,"incomplete_rows":incomplete,"capture_started":self.capture_started,"recorder_started":self.recorder_started,"recorder_stopped":recorder_stopped,"capture_stopped":capture_stopped,"capture_interface":self.config.capture_interface,"capture_buffer_kib_requested":4096,"capture_immediate_mode":true,"capture_filter":null,"capture_contains_payloads":true,"capture_statistics":stats,"recorder_statistics":recorder_stats,"complete_scope":"recorder_internal","agent_route_enforcement":"not_verified","finalized":true}),
        );
        self.manifest.as_mut().unwrap()["control_transitions"] =
            serde_json::to_value(&self.state.transitions)?;
        self.manifest.as_mut().unwrap()["failed_control_operations"] =
            serde_json::to_value(&self.state.failed_operations)?;
        private_write(
            &self.config.evidence_dir.join("manifest.json"),
            &serde_json::to_vec_pretty(self.manifest.as_ref().unwrap())?,
        )?;
        self.transition(Phase::Exported)?;
        Ok(())
    }
    fn export(&self, directory: &Path) -> Result<Value> {
        ensure!(directory.is_absolute(), "export path must be absolute");
        // Never overwrite or follow an existing destination.
        fs::DirBuilder::new()
            .create(directory)
            .context("export destination must not exist")?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        let mut missing = Vec::new();
        for name in ["api.jsonl", "capture.pcap", "manifest.json"] {
            match File::open(self.config.evidence_dir.join(name)) {
                Ok(mut input) => {
                    let mut output = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(directory.join(name))?;
                    std::io::copy(&mut input, &mut output)?;
                    output.sync_all()?;
                }
                Err(_) => missing.push(name),
            }
        }
        File::open(directory)?.sync_all()?;
        let manifest = self
            .manifest
            .as_ref()
            .context("finalization manifest unavailable")?;
        Ok(
            json!({"directory":directory,"complete":manifest["complete"]==true && missing.is_empty(),"missing":missing,"manifest":manifest}),
        )
    }
    async fn shutdown(&mut self) {
        let _ = seed::stop(&mut self.proxy, libc::SIGTERM, 5).await;
        let _ = seed::stop(&mut self.capture, libc::SIGINT, 5).await;
        let _ = seed::stop(&mut self.lws, libc::SIGTERM, 5).await;
    }
}

pub async fn serve(config: Config) -> Result<()> {
    unsafe {
        libc::umask(0o077);
    }
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    directory(&config.state_dir, uid, gid)?;
    directory(&config.data_dir, config.service_uid, config.service_gid)?;
    directory(&config.evidence_dir, config.service_uid, config.service_gid)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(config.state_dir.join("controller.lock"))?;
    lock.try_lock_exclusive()
        .context("recorder supervisor already running")?;
    let state_path = config.state_dir.join("state.json");
    let state = if state_path.exists() {
        read_private::<State>(&state_path)?
    } else {
        State {
            phase: Phase::Unclaimed,
            token_digest: None,
            transitions: Vec::new(),
            failed_operations: std::collections::BTreeMap::new(),
        }
    };
    let mut controller = Controller {
        config,
        state,
        lws: None,
        proxy: None,
        capture: None,
        capture_stats: None,
        setup: None,
        access_keys: Default::default(),
        client: proxy::client(),
        manifest: None,
        capture_started: None,
        recorder_started: None,
    };
    if !matches!(controller.state.phase, Phase::Unclaimed | Phase::Claimed) {
        controller.state.phase = Phase::Failed;
    }
    controller.persist()?;
    let socket = controller.config.socket();
    if socket.exists() {
        fs::remove_file(&socket)?;
    }
    let listener = UnixListener::bind(&socket)?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    println!("{{\"control_ready\":true}}");
    std::io::stdout().flush()?;
    loop {
        tokio::select! {
            _=terminate.recv()=>break,
            _=interrupt.recv()=>break,
            accepted=listener.accept()=> {
                let (mut stream,_)=accepted?;
                let mut bytes=Vec::new();
                let read=tokio::time::timeout(Duration::from_secs(5),(&mut stream).take(CONTROL_LIMIT+1).read_to_end(&mut bytes)).await;
                let result=match read {
                    Ok(Ok(_)) if bytes.len() as u64<=CONTROL_LIMIT=>match serde_json::from_slice::<Request>(&bytes){Ok(request)=>controller.execute(request).await,Err(_)=>Err(anyhow::anyhow!("invalid control request"))},
                    _=>Err(anyhow::anyhow!("control input incomplete or oversized")),
                };
                let response=match result{Ok(value)=>json!({"ok":true,"result":value}),Err(error)=>json!({"ok":false,"error":error.to_string()})};
                let _=tokio::time::timeout(Duration::from_secs(5),stream.write_all(&serde_json::to_vec(&response)?)).await;
            }
        }
    }
    controller.shutdown().await;
    fs::remove_file(socket)?;
    drop(lock);
    Ok(())
}
pub async fn call(config: &Config, request: Request) -> Result<Value> {
    let mut stream = UnixStream::connect(config.socket())
        .await
        .context("recorder supervisor is not available")?;
    stream.write_all(&serde_json::to_vec(&request)?).await?;
    stream.shutdown().await?;
    let mut bytes = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(config.timeout_seconds * 20),
        stream.take(1024 * 1024 + 1).read_to_end(&mut bytes),
    )
    .await
    .context("guest control timeout")??;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "guest control response oversized"
    );
    let response: Value =
        serde_json::from_slice(&bytes).context("invalid guest control response")?;
    ensure!(
        response["ok"] == true,
        "{}",
        response["error"]
            .as_str()
            .unwrap_or("guest operation failed")
    );
    Ok(response["result"].clone())
}
