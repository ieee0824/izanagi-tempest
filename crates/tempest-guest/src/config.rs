use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub state_dir: PathBuf,
    pub data_dir: PathBuf,
    pub evidence_dir: PathBuf,
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
    pub lws: PathBuf,
    pub aws: PathBuf,
    pub tcpdump: PathBuf,
    pub capture_interface: String,
    pub service_uid: u32,
    pub service_gid: u32,
    #[serde(default)]
    pub development: bool,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}
fn default_timeout() -> u64 {
    30
}
impl Config {
    pub fn read(path: &Path) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .context("open guest configuration")?;
        let metadata = file
            .metadata()
            .context("read guest configuration metadata")?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "configuration must be a regular file"
        );
        if unsafe { libc::geteuid() } == 0 {
            ensure!(
                metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
                "root requires root-owned configuration without group/other writes"
            );
        }
        let mut bytes = Vec::new();
        file.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 16 * 1024,
            "guest configuration exceeds 16 KiB"
        );
        let mut config: Self =
            serde_json::from_slice(&bytes).context("invalid guest configuration")?;
        if !config.development {
            for binary in [&mut config.lws, &mut config.aws, &mut config.tcpdump] {
                *binary = binary
                    .canonicalize()
                    .context("resolve production executable")?;
                trusted_path(binary)?;
            }
            trusted_path(&std::env::current_exe()?.canonicalize()?)?;
            for directory in [
                &mut config.state_dir,
                &mut config.data_dir,
                &mut config.evidence_dir,
            ] {
                let name = directory
                    .file_name()
                    .context("private directory must not be filesystem root")?
                    .to_owned();
                let parent = directory
                    .parent()
                    .context("private directory parent")?
                    .canonicalize()?;
                trusted_path(&parent)?;
                *directory = parent.join(name);
            }
        }
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.listen.ip().is_loopback() && self.upstream.ip().is_loopback(),
            "only loopback endpoints are allowed"
        );
        ensure!(
            self.listen.port() != 0 && self.upstream.port() != 0 && self.listen != self.upstream,
            "distinct nonzero loopback ports required"
        );
        ensure!(
            self.timeout_seconds > 0 && self.timeout_seconds <= 300,
            "timeout_seconds must be 1..300"
        );
        ensure!(
            matches!(self.capture_interface.as_str(), "lo" | "lo0"),
            "capture_interface must be a loopback interface (lo/lo0)"
        );
        for p in [
            &self.state_dir,
            &self.data_dir,
            &self.evidence_dir,
            &self.lws,
            &self.aws,
            &self.tcpdump,
        ] {
            ensure!(p.is_absolute(), "configuration paths must be absolute");
        }
        ensure!(
            self.state_dir != self.data_dir
                && self.state_dir != self.evidence_dir
                && self.data_dir != self.evidence_dir,
            "private directories must be distinct"
        );
        ensure!(
            !self.development || unsafe { libc::geteuid() } != 0,
            "development mode is forbidden for root"
        );
        if !self.development {
            ensure!(
                unsafe { libc::geteuid() } == 0,
                "production supervisor requires root"
            );
            ensure!(
                self.service_uid != 0 && self.service_gid != 0,
                "LWS and proxy must run as non-root service uid/gid"
            );
            for path in [
                &self.lws,
                &self.aws,
                &self.tcpdump,
                &std::env::current_exe()?,
            ] {
                let metadata =
                    std::fs::metadata(path).context("read production executable metadata")?;
                ensure!(
                    metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o6022 == 0,
                    "production executables must be root-owned and not group/other writable"
                );
            }
        }
        Ok(())
    }
    pub fn socket(&self) -> PathBuf {
        self.state_dir.join("control.sock")
    }
    pub fn endpoint(&self) -> String {
        format!("http://{}", self.upstream)
    }
}

fn trusted_path(path: &Path) -> Result<()> {
    for component in path.ancestors() {
        let metadata = std::fs::metadata(component).context("read trusted production path")?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "production path and ancestors must be root-owned without group/other writes"
        );
    }
    Ok(())
}
