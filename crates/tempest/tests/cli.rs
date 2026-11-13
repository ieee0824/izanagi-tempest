use std::{
    fs,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{DirBuilderExt, PermissionsExt},
    },
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[test]
fn model_relay_process_exits_when_its_controller_pipe_closes() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "tempest-relay-process-{}-{unique}",
        std::process::id()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let private = |name: &str, bytes: &[u8]| {
        let path = root.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    };
    let capability = private("capability", b"0123456789abcdef0123456789abcdef");
    let auth = private("auth", b"fixture-key");
    let policy_source = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/policies/claude-code-2.1.323-claude-sonnet-5-5-anthropic-messages.json"
    );
    let policy = private("policy.json", &fs::read(policy_source).unwrap());
    let audit = root.join("audit.jsonl");
    let ready = root.join("ready.json");
    let mut descriptors = [-1; 2];
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    let read = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    assert_eq!(
        unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) },
        0
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_tempest"))
        .args([
            "model-api-relay",
            "--upstream",
            "https://api.example.invalid/",
        ])
        .arg("--capability-file")
        .arg(capability)
        .arg("--policy-file")
        .arg(policy)
        .arg("--audit")
        .arg(&audit)
        .arg("--ready-file")
        .arg(&ready)
        .arg("--auth-file")
        .arg(auth)
        .args(["--auth-header", "x-api-key", "--timeout-seconds", "1"])
        .arg("--lifetime-fd")
        .arg(read.as_raw_fd().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(read);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !ready.is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if !ready.is_file() {
        drop(write);
        let output = child.wait_with_output().unwrap();
        panic!(
            "relay did not become ready: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    drop(write);
    let deadline = Instant::now() + Duration::from_secs(2);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "relay did not observe controller EOF"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cli_exit_codes_diagnostics_and_raw_hash() {
    let binary = env!("CARGO_BIN_EXE_tempest");
    let scenario = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scenarios/s3-overread-001.yaml"
    );
    let output = Command::new(binary)
        .args(["validate", scenario])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["id"], "s3-overread-001");
    assert_eq!(report["validation"], "static");
    assert_eq!(report["runtime_checks"], "not_performed");
    assert_eq!(report["sha256"].as_str().unwrap().len(), 64);
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("tempest-cli-{}-{unique}.yaml", std::process::id()));
    fs::write(&path, b"id: 42\n").unwrap();
    let invalid = Command::new(binary)
        .arg("validate")
        .arg(&path)
        .output()
        .unwrap();
    fs::remove_file(&path).unwrap();
    assert_eq!(invalid.status.code(), Some(1));
    assert!(invalid.stdout.is_empty());
    let error = String::from_utf8(invalid.stderr).unwrap();
    assert!(
        error.contains("id:") && error.contains("expected a string"),
        "{error}"
    );
    let missing = Command::new(binary)
        .arg("validate")
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
    for args in [
        vec![],
        vec!["validate"],
        vec!["run", scenario],
        vec!["validate", scenario, "extra"],
    ] {
        let output = Command::new(binary).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
    assert!(
        Command::new(binary)
            .arg("--help")
            .status()
            .unwrap()
            .success()
    );
    let environment_mismatch = Command::new(binary)
        .args([
            "mcp-connect",
            "/private/tmp/tempest-never-connect",
            "--environment-policy",
            "codex-v1",
        ])
        .output()
        .unwrap();
    assert_eq!(environment_mismatch.status.code(), Some(1));
    assert!(
        String::from_utf8(environment_mismatch.stderr)
            .unwrap()
            .contains("environment mismatch")
    );
}
