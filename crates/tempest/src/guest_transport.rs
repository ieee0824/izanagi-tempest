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

fn execution_failure_kind(text: &str) -> &'static str {
    if text.starts_with("exec failed:") {
        "exec_failed"
    } else if text.ends_with("(exit code: -1)") {
        "exit_minus_one"
    } else if text.ends_with("(exit code: 137)") {
        "exit_137"
    } else {
        "unexpected_error_response"
    }
}

pub(crate) async fn call(
    companion: &mut Companion,
    management: &mut Management,
    operation: &str,
    fields: Value,
    audit: impl FnMut(Value) -> io::Result<()>,
) -> io::Result<Value> {
    call_with_deadline(
        companion,
        management,
        operation,
        fields,
        audit,
        Duration::from_secs(if operation == "export" { 320 } else { 260 }),
    )
    .await
}

async fn call_with_deadline(
    companion: &mut Companion,
    management: &mut Management,
    operation: &str,
    fields: Value,
    mut audit: impl FnMut(Value) -> io::Result<()>,
    deadline: Duration,
) -> io::Result<Value> {
    match tokio::time::timeout(
        deadline,
        call_inner(companion, management, operation, fields, &mut audit),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            audit(json!({"state":"delivery_deadline","host_ns":host_io::now_ns()?}))?;
            Err(io::Error::other("guest response deadline; discard VM"))
        }
    }
}

async fn call_inner(
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
    // Freeze also stops the RPC daemon. Allow a read already dispatched while
    // frozen to wait through native export (240s) and the 20s barrier operations.
    // Keep each RPC below the pinned MCP server's independent 300s timeout.
    let timeout = Duration::from_secs(if operation == "export" { 320 } else { 260 });
    let mut attempt = 0_u64;
    let mut failed_reads = 0_u32;
    loop {
        let remaining = timeout
            .checked_sub(started.elapsed())
            .ok_or_else(|| io::Error::other("guest response lost; discard VM"))?;
        if attempt >= 3200 {
            return Err(io::Error::other("delivery read limit; discard VM"));
        }
        attempt += 1;
        audit(
            json!({"state":"delivery_read_started","attempt":attempt,"host_ns":host_io::now_ns()?}),
        )?;
        let response = management
            .exec(
                "/usr/bin/doas",
                &["-n", "/usr/local/bin/tempest-guest", "deliver", path],
                remaining.min(Duration::from_secs(290)),
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
        let execution_kind = (error && !pending).then(|| execution_failure_kind(&text));
        audit(
            json!({"state":"delivery_read_observed","attempt":attempt,"category":if !error {"ciphertext_received"} else if pending {"reply_unavailable"} else {"execution_error"},"execution_kind":execution_kind,"host_ns":host_io::now_ns()?}),
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
            let category = execution_kind.unwrap_or("unexpected_error_response");
            if operation == "export" && category != "unexpected_error_response" {
                failed_reads += 1;
                let retry = failed_reads < 3;
                audit(
                    json!({"state":"delivery_read_retry","attempt":attempt,"failed_reads":failed_reads,"retry_scheduled":retry,"host_ns":host_io::now_ns()?}),
                )?;
                if retry {
                    // Only re-read the same saved response. The root operation
                    // was submitted once, before this loop; never prepare again.
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    continue;
                }
            }
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

#[cfg(test)]
mod delivery_tests {
    use super::*;

    async fn peer(source: &str, mode: &str) -> Child {
        tokio::process::Command::new("python3")
            .args(["-u", "-c", source, mode])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap()
    }

    async fn exercise(operation: &str, mode: &str) -> (io::Result<Value>, Vec<Value>) {
        let mut child = peer(
            r#"import sys,json
prepared=False
for line in sys.stdin:
 m=json.loads(line)
 if m['command']=='prepare':
  assert not prepared
  prepared=True
  result={'guest_path':'/workspace/.tempest-control/'+'a'*32+'.json'}
 else:
  if sys.argv[1]=='auth':
   print(json.dumps({'ok':False}),flush=True)
   continue
  result={'ok':sys.argv[1]!='rejected','result':{'complete':True}}
 print(json.dumps({'ok':True,'result':result}),flush=True)
"#,
            mode,
        )
        .await;
        let mut companion = Companion {
            info: json!({}),
            reader: BufReader::new(child.stdout.take().unwrap()),
            writer: child.stdin.take().unwrap(),
            child,
        };
        let mut child = peer(
            r#"import sys,json,time
count=0
for line in sys.stdin:
 m=json.loads(line);count+=1
 mode=sys.argv[1]
 if mode=='silence': time.sleep(10)
 failed=mode in ('always','unknown') or (count==1 and mode=='recover')
 text='unclassified error' if mode=='unknown' else '\n(exit code: -1)' if failed else 'CIPHERTEXT'
 result={'isError':failed,'content':[{'type':'text','text':text}]}
 print(json.dumps({'jsonrpc':'2.0','id':m['id']+(1 if mode=='mismatch' else 0),'result':result}),flush=True)
"#,
            mode,
        )
        .await;
        let mut management = Management {
            rpc: Rpc::new(
                child.stdout.take().unwrap(),
                SecretWriter::new(child.stdin.take().unwrap(), None),
            ),
            child,
        };
        let mut rows = Vec::new();
        let result = call_with_deadline(
            &mut companion,
            &mut management,
            operation,
            json!({}),
            |row| {
                rows.push(row);
                Ok(())
            },
            Duration::from_millis(if mode == "silence" { 1000 } else { 5000 }),
        )
        .await;
        companion.stop().await.unwrap();
        if mode == "silence" {
            management.child.kill().await.unwrap();
            management.child.wait().await.unwrap();
        } else {
            management.stop().await.unwrap();
        }
        (result, rows)
    }

    #[tokio::test]
    async fn export_retries_only_saved_response_reads_with_a_failure_limit() {
        let (result, rows) = exercise("export", "recover").await;
        assert_eq!(result.unwrap(), json!({"complete":true}));
        assert_eq!(
            rows.iter()
                .filter(|row| row["state"] == "delivery_read_started")
                .count(),
            2
        );
        assert!(rows.iter().any(|row| row["retry_scheduled"] == true));
        let (result, rows) = exercise("export", "always").await;
        assert!(result.is_err());
        assert_eq!(
            rows.iter()
                .filter(|row| row["state"] == "delivery_read_started")
                .count(),
            3
        );
        assert_eq!(rows.last().unwrap()["retry_scheduled"], false);
    }

    #[tokio::test]
    async fn unobserved_response_hits_the_overall_deadline_without_a_retry() {
        let (result, rows) = exercise("export", "silence").await;
        assert!(result.is_err());
        assert_eq!(rows.last().unwrap()["state"], "delivery_deadline");
        assert_eq!(
            rows.iter()
                .filter(|row| row["state"] == "delivery_read_started")
                .count(),
            1
        );
        assert!(!rows.iter().any(|row| row["retry_scheduled"] == true));
    }

    #[tokio::test]
    async fn seed_uncertain_rpc_authentication_and_operation_errors_are_terminal() {
        for (operation, mode) in [
            ("seed", "recover"),
            ("export", "mismatch"),
            ("export", "auth"),
            ("export", "rejected"),
            ("export", "unknown"),
        ] {
            let (result, rows) = exercise(operation, mode).await;
            assert!(result.is_err(), "{operation}/{mode}");
            assert_eq!(
                rows.iter()
                    .filter(|row| row["state"] == "delivery_read_started")
                    .count(),
                1,
                "{operation}/{mode}"
            );
            assert!(!rows.iter().any(|row| row["retry_scheduled"] == true));
        }
    }
}
