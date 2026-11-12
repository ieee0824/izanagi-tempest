use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempest::{
    admission::CloseReason,
    relay::RelayConfig,
    supervisor::{Supervisor, SupervisorConfig},
};
use tokio::{io::AsyncWriteExt, net::UnixListener, process::Command};

struct Root(PathBuf);
static COUNTER: AtomicU64 = AtomicU64::new(0);
impl Root {
    fn new() -> Self {
        // Keep the Unix socket path below Darwin's sockaddr_un limit.
        let base = if cfg!(target_os = "macos") {
            "/private/tmp"
        } else {
            "/tmp"
        };
        let path = PathBuf::from(format!(
            "{base}/ts-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn config(&self) -> SupervisorConfig {
        SupervisorConfig {
            executable: "/usr/bin/python3".into(),
            args: vec![
                "-u".into(),
                "-c".into(),
                SERVER.into(),
                self.0.join("release").into(),
                self.0.join("trace").into(),
            ],
            cwd: self.0.clone(),
            socket: self.0.join("s"),
            log: self.0.join("mcp.jsonl"),
            stderr: self.0.join("stderr"),
            secret_file: None,
            owner_file: None,
            relay: RelayConfig {
                timeout: Duration::from_secs(5),
                drain_timeout: Duration::from_secs(2),
                ..RelayConfig::default()
            },
        }
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
const SERVER: &str = r#"
import json,sys,time,os
from pathlib import Path
with open(sys.argv[2],'w') as trace:
 if 'IZANAGI_SECRET_FILE' in os.environ:
  Path(sys.argv[1]+'.secret-ready').write_text('ready')
  while not Path(sys.argv[1]).exists(): time.sleep(.01)
  if Path(sys.argv[1]+'.verify-once').exists(): assert Path(os.environ['IZANAGI_SECRET_FILE']).read_bytes()==b'DUMMY-TRANSPORT-CANARY'
 trace.write(json.dumps({'pid':os.getpid(),'pgid':os.getpgrp(),'secret_file':os.environ.get('IZANAGI_SECRET_FILE'),'ambient_secret_inherited':'IZANAGI_SHARED_SECRET' in os.environ})+'\n');trace.flush()
 for line in sys.stdin:
  if 'IZANAGI_SECRET_FILE' in os.environ: assert Path(os.environ['IZANAGI_SECRET_FILE']).read_bytes()==b'DUMMY-TRANSPORT-CANARY'
  request=json.loads(line);trace.write(json.dumps(request)+'\n');trace.flush()
  while not Path(sys.argv[1]).exists(): time.sleep(.01)
  print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{'content':[{'type':'text','text':'done'}],'isError':False}}),flush=True)
"#;
async fn logged(root: &Root, event: &str) {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if fs::read_to_string(root.0.join("mcp.jsonl"))
                .unwrap_or_default()
                .contains(event)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
fn call(id: u64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"sandbox_exec","arguments":{"command":"/bin/echo"}}})
}

#[tokio::test]
async fn killing_bridge_group_closes_queued_admission_but_keeps_upstream_drain_alive() {
    let root = Root::new();
    let supervisor = Supervisor::start(root.config()).unwrap();
    assert_eq!(
        root.0.join("s").metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut bridge = Command::new(env!("CARGO_BIN_EXE_tempest"))
        .arg("mcp-connect")
        .arg(root.0.join("s"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let bridge_pid = bridge.id().unwrap();
    let mut input = bridge.stdin.take().unwrap();
    input
        .write_all(format!("{}\n", call(1)).as_bytes())
        .await
        .unwrap();
    logged(&root, "forwarded").await;
    input
        .write_all(format!("{}\n", call(2)).as_bytes())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while fs::read_to_string(root.0.join("mcp.jsonl"))
            .unwrap()
            .lines()
            .filter(|line| line.contains("\"event\":\"queued\""))
            .count()
            < 2
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let trace = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(trace) = fs::read_to_string(root.0.join("trace")) {
                if trace.lines().count() >= 2 {
                    break trace;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let identity: Value = serde_json::from_str(trace.lines().next().unwrap()).unwrap();
    assert_ne!(identity["pgid"].as_u64().unwrap(), u64::from(bridge_pid));
    assert_eq!(
        unsafe { libc::kill(-(bridge_pid as i32), libc::SIGKILL) },
        0
    );
    assert!(!bridge.wait().await.unwrap().success());
    drop(input);
    // EOF alone must close admission. Do not call finish until the relay closes.
    fs::write(root.0.join("release"), b"go").unwrap();
    logged(&root, "relay_closed").await;
    let outcome = supervisor.finish(CloseReason::AgentFinished).await.unwrap();
    assert!(outcome.verified_rpc_drain());
    assert_eq!(
        (outcome.relay.admitted_calls, outcome.relay.completed_calls),
        (1, 1)
    );
    let requests: Vec<Value> = fs::read_to_string(root.0.join("trace"))
        .unwrap()
        .lines()
        .skip(1)
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["id"], 1);
    assert!(!root.0.join("s").exists());
}

#[tokio::test]
async fn owner_can_close_without_a_bridge_and_no_request_is_forwarded() {
    let root = Root::new();
    let supervisor = Supervisor::start(root.config()).unwrap();
    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        supervisor.finish(CloseReason::Cancelled),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(outcome.verified_rpc_drain());
    assert_eq!(outcome.relay.admitted_calls, 0);
    assert!(!root.0.join("s").exists());
}

#[tokio::test]
async fn server_eof_exits_bridge_even_when_agent_stdin_is_still_open() {
    let root = Root::new();
    let listener = UnixListener::bind(root.0.join("s")).unwrap();
    let mut bridge = Command::new(env!("CARGO_BIN_EXE_tempest"))
        .arg("mcp-connect")
        .arg(root.0.join("s"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let _held_input = bridge.stdin.take().unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    drop(stream);
    assert!(
        tokio::time::timeout(Duration::from_secs(3), bridge.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn public_socket_parent_is_rejected_before_upstream_starts() {
    let root = Root::new();
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Supervisor::start(root.config()).is_err());
    assert!(!root.0.join("trace").exists());
    assert!(!root.0.join("s").exists());
}

#[tokio::test]
async fn absent_bridge_expires_without_renewing_the_budget() {
    let root = Root::new();
    let mut config = root.config();
    config.relay.timeout = Duration::from_millis(30);
    let supervisor = Supervisor::start(config).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(3), supervisor.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(outcome.verified_rpc_drain());
    assert_eq!(
        outcome.relay.drain.unwrap().closed_reason(),
        CloseReason::Timeout
    );
    assert_eq!(outcome.relay.admitted_calls, 0);
}

#[test]
fn explicit_private_secret_reference_reaches_only_the_upstream_environment() {
    let root = Root::new();
    let hmac_path = root.0.join("secret");
    fs::write(&hmac_path, b"DUMMY-TRANSPORT-CANARY").unwrap();
    fs::set_permissions(&hmac_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(root.0.join("release"), b"go").unwrap();
    fs::write(root.0.join("release.verify-once"), b"go").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tempest"))
        .arg("mcp-session")
        .arg(root.0.join("s"))
        .arg("--log")
        .arg(root.0.join("mcp.jsonl"))
        .arg("--summary")
        .arg(root.0.join("summary.json"))
        .arg("--stderr")
        .arg(root.0.join("stderr"))
        .arg("--secret-file")
        .arg(&hmac_path)
        .args([
            "--timeout-ms",
            "10",
            "--",
            "/usr/bin/python3",
            "-u",
            "-c",
            SERVER,
        ])
        .arg(root.0.join("release"))
        .arg(root.0.join("trace"))
        .env("IZANAGI_SHARED_SECRET", "UNRELATED-AMBIENT-CANARY")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let trace: Value = serde_json::from_str(
        fs::read_to_string(root.0.join("trace"))
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert!(
        trace["secret_file"]
            .as_str()
            .unwrap()
            .starts_with("/dev/fd/")
    );
    assert_eq!(trace["ambient_secret_inherited"], false);
    assert!(
        !fs::read_to_string(root.0.join("mcp.jsonl"))
            .unwrap()
            .contains("DUMMY-TRANSPORT-CANARY")
    );
}

#[tokio::test]
async fn unsafe_secret_files_are_rejected_before_binding_or_spawning() {
    let root = Root::new();
    let hmac_path = root.0.join("secret");
    fs::write(&hmac_path, b"DUMMY").unwrap();
    fs::set_permissions(&hmac_path, fs::Permissions::from_mode(0o644)).unwrap();
    let mut config = root.config();
    config.secret_file = Some(hmac_path.clone());
    assert!(Supervisor::start(config).is_err());
    fs::set_permissions(&hmac_path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = root.0.join("link");
    std::os::unix::fs::symlink(&hmac_path, &link).unwrap();
    let mut config = root.config();
    config.secret_file = Some(link);
    assert!(Supervisor::start(config).is_err());
    let unsafe_parent = root.0.join("unsafe");
    fs::create_dir(&unsafe_parent).unwrap();
    fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o770)).unwrap();
    fs::write(unsafe_parent.join("secret"), b"DUMMY").unwrap();
    fs::set_permissions(
        unsafe_parent.join("secret"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut config = root.config();
    config.secret_file = Some(unsafe_parent.join("secret"));
    assert!(Supervisor::start(config).is_err());
    let fifo = root.0.join("fifo");
    let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let mut config = root.config();
    config.secret_file = Some(fifo);
    assert!(Supervisor::start(config).is_err());
    assert!(!root.0.join("trace").exists());
    assert!(!root.0.join("s").exists());
}

#[tokio::test]
async fn replacing_the_secret_path_after_validation_cannot_change_the_inherited_file() {
    let root = Root::new();
    let hmac_path = root.0.join("secret");
    fs::write(&hmac_path, b"DUMMY-TRANSPORT-CANARY").unwrap();
    fs::set_permissions(&hmac_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(root.0.join("release.verify-once"), b"go").unwrap();
    let mut config = root.config();
    config.secret_file = Some(hmac_path.clone());
    let supervisor = Supervisor::start(config).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !root.0.join("release.secret-ready").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // An independently exec'd agent fixture must not inherit the owner's
    // retained cursor FD (nor the upstream's explicit secret environment).
    let isolated = std::process::Command::new("/usr/bin/python3")
        .args([
            "-c",
            r#"
import os,stat
assert 'IZANAGI_SECRET_FILE' not in os.environ
for name in os.listdir('/dev/fd'):
 if not name.isdigit() or int(name)<3: continue
 fd=int(name)
 try:
  if stat.S_ISREG(os.fstat(fd).st_mode): assert os.pread(fd,4096,0)!=b'DUMMY-TRANSPORT-CANARY'
 except OSError: pass
"#,
        ])
        .env_clear()
        .output()
        .unwrap();
    assert!(isolated.status.success());
    fs::rename(&hmac_path, root.0.join("old-secret")).unwrap();
    let attacker = root.0.join("replacement");
    fs::write(&attacker, b"ATTACKER-REPLACEMENT").unwrap();
    std::os::unix::fs::symlink(&attacker, &hmac_path).unwrap();
    fs::write(root.0.join("release"), b"go").unwrap();
    let outcome = supervisor.finish(CloseReason::Cancelled).await.unwrap();
    // The fake upstream asserts the original FD's contents after replacement.
    assert!(outcome.verified_rpc_drain());
}

#[tokio::test]
async fn inherited_secret_can_be_read_for_multiple_sequential_requests() {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let root = Root::new();
    let hmac_path = root.0.join("secret");
    fs::write(&hmac_path, b"DUMMY-TRANSPORT-CANARY").unwrap();
    fs::set_permissions(&hmac_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(root.0.join("release"), b"go").unwrap();
    let mut config = root.config();
    config.secret_file = Some(hmac_path);
    let supervisor = Supervisor::start(config).unwrap();
    let stream = tokio::net::UnixStream::connect(root.0.join("s"))
        .await
        .unwrap();
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    for id in 1..=2 {
        write
            .write_all(format!("{}\n", call(id)).as_bytes())
            .await
            .unwrap();
        let mut line = String::new();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line))
                .await
                .unwrap()
                .unwrap()
                > 0
        );
        assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["id"], id);
    }
    let outcome = supervisor.finish(CloseReason::AgentFinished).await.unwrap();
    assert!(outcome.verified_rpc_drain());
    assert_eq!(outcome.relay.completed_calls, 2);
}

#[tokio::test]
async fn a_competing_secret_reader_causing_exec_failure_cannot_produce_a_receipt() {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let root = Root::new();
    let hmac_path = root.0.join("secret");
    fs::write(&hmac_path, b"DUMMY-TRANSPORT-CANARY").unwrap();
    fs::set_permissions(&hmac_path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut config = root.config();
    config.secret_file = Some(hmac_path);
    config.args=vec!["-u".into(),"-c".into(),r#"
import os,json,sys
fd=int(os.environ['IZANAGI_SECRET_FILE'].rsplit('/',1)[1])
for line in sys.stdin:
 request=json.loads(line)
 assert os.read(fd,4096)==b'DUMMY-TRANSPORT-CANARY'
 assert os.read(fd,4096)==b''
 print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':{'content':[{'type':'text','text':'exec failed: secret reader conflict'}],'isError':True}}),flush=True)
"#.into()];
    let supervisor = Supervisor::start(config).unwrap();
    let stream = tokio::net::UnixStream::connect(root.0.join("s"))
        .await
        .unwrap();
    let (read, mut write) = stream.into_split();
    write
        .write_all(format!("{}\n", call(1)).as_bytes())
        .await
        .unwrap();
    let mut reader = BufReader::new(read);
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        serde_json::from_str::<Value>(&response).unwrap()["result"]["isError"]
            .as_bool()
            .unwrap()
    );
    let outcome = supervisor.wait().await.unwrap();
    assert!(!outcome.verified_rpc_drain());
    assert!(outcome.relay.uncertain && outcome.relay.drain.is_none());
}
