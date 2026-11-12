use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);
fn directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "tempest-proxy-test-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    path
}
const SERVER: &str = r#"
import json,sys,os
with open(sys.argv[1],'w') as trace:
 trace.write(json.dumps({'clean_environment':'AWS_SESSION_TOKEN' not in os.environ})+'\n');trace.flush()
 for line in sys.stdin:
  request=json.loads(line);trace.write(json.dumps(request)+'\n');trace.flush()
  if 'id' not in request: continue
  result={'tools':[{'name':'sandbox_exec','description':'UNCHANGED TOOL DESCRIPTION'}]} if request['method']=='tools/list' else {'content':[{'type':'text','text':'OK'}],'isError':False}
  print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result}),flush=True)
"#;

#[tokio::test]
async fn quota_close_exits_even_if_peer_keeps_stdin_open() {
    use tokio::io::AsyncWriteExt;
    let root = directory();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_tempest"))
        .arg("mcp-proxy")
        .arg("--log")
        .arg(root.join("mcp.jsonl"))
        .arg("--summary")
        .arg(root.join("summary.json"))
        .arg("--stderr")
        .arg(root.join("stderr"))
        .args(["--max-calls", "0", "--", "/usr/bin/python3", "-c", SERVER])
        .arg(root.join("trace"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"sandbox_exec\",\"arguments\":{\"command\":\"/bin/echo\"}}}\n").await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(3), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    let summary: Value =
        serde_json::from_slice(&fs::read(root.join("summary.json")).unwrap()).unwrap();
    assert_eq!(summary["relay"]["admitted_calls"], 0);
    drop(input);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn real_stdio_process_relays_metadata_and_blocks_the_excess_call() {
    let root = directory();
    let trace = root.join("trace.jsonl");
    let mut child = Command::new(env!("CARGO_BIN_EXE_tempest"))
        .args(["mcp-proxy", "--log"])
        .arg(root.join("mcp.jsonl"))
        .arg("--summary")
        .arg(root.join("proxy.json"))
        .arg("--stderr")
        .arg(root.join("upstream.stderr"))
        .args([
            "--max-calls",
            "1",
            "--timeout-ms",
            "10000",
            "--",
            "/usr/bin/python3",
            "-u",
            "-c",
            SERVER,
        ])
        .arg(&trace)
        .env("AWS_SESSION_TOKEN", "LOCAL-DUMMY-NOT-FOR-UPSTREAM")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let requests = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sandbox_exec","arguments":{"command":"/bin/echo","args":["OK"]}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sandbox_exec","arguments":{"command":"/bin/echo","args":["NEVER-FORWARD"]}}}),
    ];
    let mut stdin = child.stdin.take().unwrap();
    for request in requests {
        writeln!(stdin, "{request}").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let replies: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(replies.len(), 4);
    assert_eq!(
        replies[1]["result"]["tools"][0]["description"],
        "UNCHANGED TOOL DESCRIPTION"
    );
    assert_eq!(replies[3]["error"]["code"], -32001);
    let forwarded: Vec<Value> = fs::read_to_string(&trace)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(forwarded[0]["clean_environment"], true);
    assert_eq!(
        forwarded
            .iter()
            .filter(|r| r["method"] == "tools/call")
            .count(),
        1
    );
    assert!(
        !fs::read_to_string(&trace)
            .unwrap()
            .contains("NEVER-FORWARD")
    );
    let summary: Value =
        serde_json::from_slice(&fs::read(root.join("proxy.json")).unwrap()).unwrap();
    assert_eq!(summary["scope"], "rpc_transport_only");
    assert_eq!(summary["relay"]["admitted_calls"], 1);
    assert_eq!(summary["relay"]["uncertain"], false);
    assert_eq!(summary["relay"]["drain"]["closed_reason"], "max_calls");
    for name in ["mcp.jsonl", "proxy.json", "upstream.stderr"] {
        assert_eq!(
            fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unsafe_or_existing_evidence_paths_never_start_the_upstream() {
    let root = directory();
    let existing = root.join("existing");
    fs::write(&existing, b"PRESERVE").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_tempest"))
        .args(["mcp-proxy", "--log"])
        .arg(&existing)
        .arg("--summary")
        .arg(root.join("summary"))
        .arg("--stderr")
        .arg(root.join("stderr"))
        .args(["--", "/definitely/not/a/real/program"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read(existing).unwrap(), b"PRESERVE");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_tempest"))
        .args(["mcp-proxy", "--log"])
        .arg(root.join("new"))
        .arg("--summary")
        .arg(root.join("summary"))
        .arg("--stderr")
        .arg(root.join("stderr"))
        .args(["--", "/definitely/not/a/real/program"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!root.join("new").exists());
    fs::remove_dir_all(root).unwrap();
}
