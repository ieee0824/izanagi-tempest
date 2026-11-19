use izanagi::sandbox::{ExecOutput, Sandbox, SandboxConfig, ShareConfig};
use std::collections::HashMap;

const IMAGE: &str = "/var/lib/tempest-izanagi-bootstrap-002/base.qcow2";
const SHARE: &str = "/run/tempest-izanagi-bootstrap-002/share";
const SECRET: &str = "/run/tempest-izanagi-bootstrap-002/dummy.secret";
const EXPECTED_GUEST_UID: &[u8] = b"1000\n";

#[derive(Default)]
struct Report {
    ready: bool,
    guest_uid: bool,
    down: bool,
    exec_status: &'static str,
    exec_exit_code: Option<i32>,
    exec_stdout_matches: Option<bool>,
    exec_stderr_present: Option<bool>,
}

fn classify_exec(output: &ExecOutput) -> &'static str {
    if output.exit_code != 0 {
        "nonzero_exit"
    } else if !output.stderr.is_empty() {
        "unexpected_stderr"
    } else if output.stdout != EXPECTED_GUEST_UID {
        "unexpected_uid"
    } else {
        "matched"
    }
}

async fn probe(sandbox: &mut impl Sandbox, config: &SandboxConfig) -> Report {
    let mut report = Report {
        ready: sandbox.up(config).await.is_ok(),
        exec_status: "not_attempted",
        ..Report::default()
    };
    if report.ready {
        let command = vec!["/usr/bin/id".into(), "-u".into()];
        match sandbox.exec(&command, &HashMap::new()).await {
            Ok(output) => {
                report.exec_exit_code = Some(output.exit_code);
                report.exec_stdout_matches = Some(output.stdout == EXPECTED_GUEST_UID);
                report.exec_stderr_present = Some(!output.stderr.is_empty());
                report.exec_status = classify_exec(&output);
                report.guest_uid = report.exec_status == "matched";
            }
            Err(_) => report.exec_status = "exec_call_error",
        }
    }
    // Call down even when up fails. The outer systemd cgroup remains necessary
    // for cancellation, process death, and incomplete upstream cleanup.
    report.down = sandbox.down().await.is_ok();
    report
}

#[tokio::main]
async fn main() {
    // This is a fixed host-specific bootstrap artifact, not a general launcher.
    let identity_ok = unsafe {
        libc::getuid() == 999
            && libc::geteuid() == 999
            && libc::getgid() == 988
            && libc::getegid() == 988
    };
    let secret_ok = std::env::var("IZANAGI_SECRET_FILE").as_deref() == Ok(SECRET)
        && matches!(
            izanagi::protocol::load_shared_secret_from_env(),
            Ok(Some(_))
        );
    if std::env::args_os().len() != 1 || !identity_ok || !secret_ok {
        println!("{{\"preflight\":false}}");
        std::process::exit(1);
    }
    let config = SandboxConfig::Qemu {
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
    };
    let mut sandbox =
        izanagi::qemu_sandbox::QemuSandbox::new().with_qemu_binary("/usr/bin/qemu-system-x86_64");
    let report = probe(&mut sandbox, &config).await;
    println!(
        "{}",
        serde_json::json!({
            "ready": report.ready,
            "guest_uid_matched": report.guest_uid,
            "down_returned_ok": report.down,
            "exec_status": report.exec_status,
            "exec_exit_code": report.exec_exit_code,
            "exec_stdout_matches": report.exec_stdout_matches,
            "exec_stderr_present": report.exec_stderr_present,
        })
    );
    std::process::exit(if report.ready && report.guest_uid && report.down {
        0
    } else {
        1
    });
}

#[cfg(test)]
mod tests;
