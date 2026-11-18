
use super::*;
use izanagi::sandbox::{ExecOutput, SandboxStatus};

struct Fake {
    fail_up: bool,
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
        stdout: vec![],
        down_called: false,
    };
    let report = probe(&mut fake, &config()).await;
    assert!(!report.ready && !report.guest_uid && report.down && fake.down_called);
}

#[tokio::test]
async fn exit_zero_with_root_uid_is_rejected_and_stopped() {
    let mut fake = Fake {
        fail_up: false,
        stdout: b"0\n".to_vec(),
        down_called: false,
    };
    let report = probe(&mut fake, &config()).await;
    assert!(report.ready && !report.guest_uid && report.down && fake.down_called);
}

#[tokio::test]
async fn expected_uid_is_accepted_and_stopped() {
    let mut fake = Fake {
        fail_up: false,
        stdout: EXPECTED_GUEST_UID.to_vec(),
        down_called: false,
    };
    let report = probe(&mut fake, &config()).await;
    assert!(report.ready && report.guest_uid && report.down && fake.down_called);
}
