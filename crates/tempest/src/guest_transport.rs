use crate::{
    host_io::{self, command},
    proxy_cli::{SecretWriter, inherit_secret, secret_reference},
    rpc::Rpc,
};
use serde_json::{Value, json};
use std::{
    io,
    path::Path,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout},
};

const LIMIT: usize = 1024 * 1024;
pub(crate) struct Companion {
    pub info: Value,
    child: Child,
    reader: BufReader<ChildStdout>,
    writer: ChildStdin,
}
impl Companion {
    pub async fn start(
        python: &Path,
        script: &Path,
        workspace: &Path,
        stderr: &Path,
    ) -> io::Result<Self> {
        let mut child = command(python)
            .arg("-B")
            .arg("-I")
            .arg(script)
            .arg(workspace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(crate::proxy_cli::private_new(stderr)?))
            .kill_on_drop(true)
            .spawn()?;
        let mut value = Self {
            info: Value::Null,
            reader: BufReader::new(child.stdout.take().unwrap()),
            writer: child.stdin.take().unwrap(),
            child,
        };
        let info = value.receive().await?;
        if info["ready"] != true {
            return Err(io::Error::other("mailbox initialization failed"));
        }
        value.info = info;
        Ok(value)
    }
    async fn receive(&mut self) -> io::Result<Value> {
        tokio::time::timeout(Duration::from_secs(15), async {
            let bytes = crate::relay::frame(&mut self.reader, &mut Vec::new(), LIMIT)
                .await?
                .ok_or_else(|| io::Error::other("mailbox companion disconnected"))?;
            let value: Value = serde_json::from_slice(&bytes)?;
            if value["ok"] != true {
                return Err(io::Error::other("mailbox companion failed"));
            }
            value
                .get("result")
                .cloned()
                .ok_or_else(|| io::Error::other("invalid companion response"))
        })
        .await
        .map_err(|_| io::Error::other("mailbox companion deadline"))?
    }
    pub async fn exchange(&mut self, value: Value) -> io::Result<Value> {
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(io::Error::other("mailbox input too large"));
        }
        tokio::time::timeout(Duration::from_secs(15), async {
            self.writer.write_all(&bytes).await?;
            self.writer.flush().await
        })
        .await
        .map_err(|_| io::Error::other("mailbox write deadline"))??;
        self.receive().await
    }
    pub async fn stop(mut self) -> io::Result<()> {
        drop(self.writer);
        match tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await {
            Ok(status) => {
                if !status?.success() {
                    return Err(io::Error::other("companion exited unsuccessfully"));
                }
            }
            Err(_) => {
                self.child.kill().await?;
                return Err(io::Error::other("companion forced stop"));
            }
        }
        Ok(())
    }
}

pub(crate) struct Management {
    child: Child,
    pub rpc: Rpc<ChildStdout, SecretWriter<ChildStdin>>,
}
impl Management {
    pub async fn start(
        izanagi: &Path,
        workspace: &Path,
        hmac: &Path,
        stderr: &Path,
    ) -> io::Result<Self> {
        let handle = secret_reference(hmac)?;
        let cursor = handle.try_clone()?;
        let mut cmd = command(izanagi);
        inherit_secret(&mut cmd, handle);
        let mut child = cmd
            .arg("mcp")
            .current_dir(workspace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(crate::proxy_cli::private_new(stderr)?))
            .process_group(0)
            .kill_on_drop(true)
            .spawn()?;
        let rpc = Rpc::new(
            child.stdout.take().unwrap(),
            SecretWriter::new(child.stdin.take().unwrap(), Some(cursor)),
        );
        let mut management = Self { child, rpc };
        management
            .rpc
            .request("initialize", json!({}), Duration::from_secs(10))
            .await?;
        Ok(management)
    }
    async fn tool(
        &mut self,
        name: &str,
        args: Value,
        deadline: Duration,
    ) -> io::Result<(String, bool)> {
        let value = self
            .rpc
            .request(
                "tools/call",
                json!({"name":name,"arguments":args}),
                deadline,
            )
            .await?;
        let result = value
            .get("result")
            .ok_or_else(|| io::Error::other("management RPC rejected"))?;
        let content = result["content"]
            .as_array()
            .filter(|v| v.len() == 1)
            .ok_or_else(|| io::Error::other("invalid management content"))?;
        if content[0]["type"] != "text" {
            return Err(io::Error::other("invalid management content"));
        }
        let text = content[0]["text"]
            .as_str()
            .ok_or_else(|| io::Error::other("invalid management output"))?
            .to_owned();
        let error = match result.get("isError") {
            None | Some(Value::Bool(false)) => false,
            Some(Value::Bool(true)) => true,
            _ => return Err(io::Error::other("invalid management result")),
        };
        Ok((text, error))
    }
    pub async fn running(&mut self, owner: u32) -> io::Result<bool> {
        let (text, error) = self
            .tool("sandbox_status", json!({}), Duration::from_secs(10))
            .await?;
        if error {
            return Err(io::Error::other("status failed"));
        }
        let value: Value = serde_json::from_str(&text)?;
        Ok(value["running"] == true && value["pid"] == owner && value["backend"] == "qemu")
    }
    pub async fn exec(
        &mut self,
        executable: &str,
        args: &[&str],
        timeout: Duration,
    ) -> io::Result<(String, bool)> {
        self.tool(
            "sandbox_exec",
            json!({"command":executable,"args":args}),
            timeout,
        )
        .await
    }
    pub async fn stop(mut self) -> io::Result<()> {
        drop(self.rpc);
        match tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await {
            Ok(status) => {
                if !status?.success() {
                    return Err(io::Error::other("management exited unsuccessfully"));
                }
            }
            Err(_) => {
                self.child.kill().await?;
                return Err(io::Error::other("management forced stop"));
            }
        }
        Ok(())
    }
}

pub(crate) async fn call(
    companion: &mut Companion,
    management: &mut Management,
    operation: &str,
    fields: Value,
    mut audit: impl FnMut(Value) -> io::Result<()>,
) -> io::Result<Value> {
    let prepared = companion
        .exchange(json!({"command":"prepare","operation":operation,"fields":fields}))
        .await?;
    let path = prepared["guest_path"]
        .as_str()
        .ok_or_else(|| io::Error::other("missing mailbox reference"))?;
    let started = Instant::now();
    let timeout = Duration::from_secs(260);
    let mut attempt = 0_u64;
    loop {
        let remaining = timeout
            .checked_sub(started.elapsed())
            .ok_or_else(|| io::Error::other("guest response lost; discard VM"))?;
        attempt += 1;
        audit(
            json!({"state":"delivery_read_started","attempt":attempt,"host_ns":host_io::now_ns()?}),
        )?;
        let response = management
            .exec(
                "/usr/bin/doas",
                &["-n", "/usr/local/bin/tempest-guest", "deliver", path],
                remaining,
            )
            .await;
        let (text, error) = match response {
            Ok(value) => value,
            Err(error) => {
                audit(
                    json!({"state":"delivery_read_observed","attempt":attempt,"category":"rpc_uncertain","host_ns":host_io::now_ns()?}),
                )?;
                return Err(error);
            }
        };
        let pending = text.strip_suffix("\n(exit code: 1)").map(str::trim)
            == Some("{\"ok\":false,\"error\":\"reply_unavailable\"}");
        audit(
            json!({"state":"delivery_read_observed","attempt":attempt,"category":if !error {"ciphertext_received"} else if pending {"reply_unavailable"} else {"execution_error"},"host_ns":host_io::now_ns()?}),
        )?;
        if !error {
            let reply = companion
                .exchange(json!({"command":"decode","frame":text}))
                .await?;
            if reply["ok"] != true {
                return Err(io::Error::other("guest operation rejected; discard VM"));
            }
            return reply
                .get("result")
                .cloned()
                .ok_or_else(|| io::Error::other("invalid guest response"));
        }
        if !pending {
            // Keep the failure observable without copying guest-controlled output
            // (which may include credentials) into run.json diagnostics.
            let category = if text.starts_with("exec failed:") {
                "exec_failed"
            } else if text.ends_with("(exit code: -1)") {
                "exit_minus_one"
            } else if text.ends_with("(exit code: 137)") {
                "exit_137"
            } else {
                "unexpected_error_response"
            };
            return Err(io::Error::other(format!(
                "management execution uncertain ({category}); discard VM"
            )));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(crate) async fn clock(
    management: &mut Management,
    group: &str,
    file: &mut std::fs::File,
) -> io::Result<()> {
    use std::io::Write;
    for sample in 0..3 {
        let before = host_io::now_ns()?;
        let (value, error) = management
            .exec("/bin/date", &["+%s%N"], Duration::from_secs(10))
            .await?;
        let after = host_io::now_ns()?;
        if error || after < before {
            return Err(io::Error::other("clock sample failed"));
        }
        let guest = value
            .trim()
            .parse::<u64>()
            .map_err(|_| io::Error::other("invalid guest clock"))?;
        let midpoint = before + (after - before) / 2;
        let offset = i64::try_from(i128::from(guest) - i128::from(midpoint))
            .map_err(|_| io::Error::other("clock offset overflow"))?;
        serde_json::to_writer(
            &mut *file,
            &json!({"group":group,"sample":sample,"host_before_ns":before,"host_after_ns":after,"guest_ns":guest,"offset_ns":offset,"rtt_ns":after-before}),
        )?;
        file.write_all(b"\n")?;
    }
    file.sync_all()
}
