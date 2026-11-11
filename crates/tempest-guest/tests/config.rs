use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tempest_guest::config::Config;

fn config() -> Config {
    Config {
        state_dir: "/run/tempest-control".into(),
        data_dir: "/var/lib/lws".into(),
        evidence_dir: "/var/lib/tempest".into(),
        listen: "127.0.0.1:4566".parse().unwrap(),
        upstream: "127.0.0.1:4567".parse().unwrap(),
        lws: "/bin/true".into(),
        aws: "/bin/true".into(),
        tcpdump: "/bin/true".into(),
        capture_interface: "lo".into(),
        service_uid: 1001,
        service_gid: 1001,
        development: true,
        timeout_seconds: 5,
    }
}
#[test]
fn configuration_cannot_select_external_endpoints_or_capture_interfaces() {
    let base = config();
    let mut invalid = base.clone();
    invalid.listen = "0.0.0.0:4566".parse().unwrap();
    assert!(
        invalid
            .validate()
            .unwrap_err()
            .to_string()
            .contains("loopback endpoints")
    );
    let mut invalid = base.clone();
    invalid.upstream = "192.0.2.1:4567".parse().unwrap();
    assert!(
        invalid
            .validate()
            .unwrap_err()
            .to_string()
            .contains("loopback endpoints")
    );
    let mut invalid = base.clone();
    invalid.upstream = invalid.listen;
    assert!(
        invalid
            .validate()
            .unwrap_err()
            .to_string()
            .contains("distinct nonzero")
    );
    let mut invalid = base.clone();
    invalid.capture_interface = "en0".into();
    assert!(
        invalid
            .validate()
            .unwrap_err()
            .to_string()
            .contains("loopback interface")
    );
    let mut invalid = base.clone();
    invalid.timeout_seconds = 0;
    assert!(
        invalid
            .validate()
            .unwrap_err()
            .to_string()
            .contains("1..300")
    );
    let mut invalid = base;
    invalid.data_dir = "relative".into();
    assert!(
        invalid
            .validate()
            .unwrap_err()
            .to_string()
            .contains("absolute")
    );
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn configuration_read_refuses_symlinks_and_oversized_files() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = Directory(
        std::env::temp_dir().join(format!("tempest-config-{}-{nonce}", std::process::id())),
    );
    fs::create_dir(&directory.0).unwrap();
    let path = directory.0.join("config.json");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(&serde_json::to_vec(&config()).unwrap())
        .unwrap();
    drop(file);
    let result = Config::read(&path);
    if unsafe { libc::geteuid() } == 0 {
        assert!(result.unwrap_err().to_string().contains("development mode"));
    } else {
        assert!(result.is_ok());
    }
    let link = directory.0.join("link.json");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(Config::read(&link).is_err());
    fs::write(&path, vec![b' '; 16 * 1024 + 1]).unwrap();
    assert!(
        Config::read(&path)
            .unwrap_err()
            .to_string()
            .contains("16 KiB")
    );
}
