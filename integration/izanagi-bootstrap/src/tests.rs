use super::*;
use izanagi::sandbox::{ExecOutput, SandboxStatus};

struct Fake {
    fail_up: bool,
    fail_exec: Option<&'static str>,
    stdout: Vec<u8>,
    down_called: bool,
}

#[async_trait::async_trait]
impl Sandbox for Fake {
    async fn up(&mut self, _: &SandboxConfig) -> anyhow::Result<()> {
        anyhow::ensure!(!self.fail_up, "injected boot failure");
        Ok(())
    }
    async fn exec(
        &self,
        cmd: &[String],
        env: &HashMap<String, String>,
    ) -> anyhow::Result<ExecOutput> {
        assert_eq!(cmd, ["/usr/bin/id", "-u"]);
        assert!(env.is_empty());
        if let Some(error) = self.fail_exec {
            anyhow::bail!(error);
        }
        Ok(ExecOutput {
            exit_code: 0,
            stdout: self.stdout.clone(),
            stderr: vec![],
        })
    }
    async fn shell(&self) -> anyhow::Result<()> {
        unreachable!()
    }
    async fn down(&mut self) -> anyhow::Result<()> {
        self.down_called = true;
        Ok(())
    }
    fn status(&self) -> SandboxStatus {
        SandboxStatus::Stopped
    }
}

fn config() -> SandboxConfig {
    SandboxConfig::Qemu {
        restrict_network: true,
        cpus: 1,
        memory_mb: 512,
        image: IMAGE.into(),
        share: ShareConfig {
            host_paths: vec![SHARE.into()],
            mount_point: "/workspace".into(),
            read_only: true,
        },
        dns_proxy: None,
    }
}

#[tokio::test]
async fn boot_failure_still_calls_down() {
    let mut fake = Fake {
        fail_up: true,
        fail_exec: None,
        stdout: vec![],
        down_called: false,
    };
    let report = probe(&mut fake, &config()).await;
    assert!(!report.ready && !report.guest_uid && report.down && fake.down_called);
    assert_eq!(report.exec_status, "not_attempted");
}

#[tokio::test]
async fn exit_zero_with_root_uid_is_rejected_and_stopped() {
    let mut fake = Fake {
        fail_up: false,
        fail_exec: None,
        stdout: b"0\n".to_vec(),
        down_called: false,
    };
    let report = probe(&mut fake, &config()).await;
    assert!(report.ready && !report.guest_uid && report.down && fake.down_called);
    assert_eq!(report.exec_status, "unexpected_uid");
}

#[tokio::test]
async fn expected_uid_is_accepted_and_stopped() {
    let mut fake = Fake {
        fail_up: false,
        fail_exec: None,
        stdout: EXPECTED_GUEST_UID.to_vec(),
        down_called: false,
    };
    let report = probe(&mut fake, &config()).await;
    assert!(report.ready && report.guest_uid && report.down && fake.down_called);
    assert_eq!(report.exec_status, "matched");
    assert_eq!(report.exec_exit_code, Some(0));
    assert_eq!(report.exec_stdout_matches, Some(true));
    assert_eq!(report.exec_stderr_present, Some(false));
}

#[tokio::test]
async fn exec_call_failure_is_unclassified_and_still_stopped() {
    for error in [
        "private-canary transport failure",
        "private-canary command rejected",
    ] {
        let mut fake = Fake {
            fail_up: false,
            fail_exec: Some(error),
            stdout: vec![],
            down_called: false,
        };
        let report = probe(&mut fake, &config()).await;
        assert!(report.ready && !report.guest_uid && report.down && fake.down_called);
        assert_eq!(report.exec_status, "exec_call_error");
        assert_eq!(report.exec_exit_code, None);
        assert_eq!(report.exec_stdout_matches, None);
        assert_eq!(report.exec_stderr_present, None);
    }
}

#[test]
fn nonzero_output_is_not_classified_from_error_text() {
    for stderr in [
        "command execution failed: no allowlist configured",
        "command execution failed: not allowed",
        "command execution failed: not found",
    ] {
        let output = ExecOutput {
            exit_code: -1,
            stdout: vec![],
            stderr: stderr.as_bytes().to_vec(),
        };
        assert_eq!(classify_exec(&output), "nonzero_exit");
    }
}

#[test]
fn ordinary_nonzero_is_not_misclassified_as_agent_denial() {
    let output = ExecOutput {
        exit_code: 1,
        stdout: vec![],
        stderr: b"command execution failed: not allowed".to_vec(),
    };
    assert_eq!(classify_exec(&output), "nonzero_exit");
}

#[test]
fn arbitrary_guest_output_is_only_classified() {
    let output = ExecOutput {
        exit_code: 0,
        stdout: EXPECTED_GUEST_UID.to_vec(),
        stderr: b"private-canary".to_vec(),
    };
    assert_eq!(classify_exec(&output), "unexpected_stderr");
}
