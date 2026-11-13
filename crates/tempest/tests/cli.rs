use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

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
            "--environment-sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
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
