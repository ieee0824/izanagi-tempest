use super::{open_private_login_directory, pin_login_path, read_login_child};
use std::{io, path::Path, process::ExitCode};

const MANAGEMENT_PARENT: &str = "/var/lib/izanagi-tempest";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CommittedCheckpoint {
    sequence: u64,
    digest: String,
}

struct HostInputs {
    _key: [u8; 32],
    _checkpoint: CommittedCheckpoint,
}

fn read_inputs() -> io::Result<HostInputs> {
    let parent = pin_login_path(Path::new(MANAGEMENT_PARENT), libc::O_DIRECTORY)?;
    let metadata = parent.metadata()?;
    use std::os::unix::fs::MetadataExt;
    if (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777) != (0, 0, 0o700) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let authority = open_private_login_directory(&parent, "host-login-authority")?;
    let recovery = open_private_login_directory(&parent, "host-login-recovery")?;
    let key = read_login_child(&authority, "verification-key", 32)?
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidData)?;
    let checkpoint: CommittedCheckpoint =
        serde_json::from_slice(&read_login_child(&recovery, "checkpoint.json", 1024)?)
            .map_err(io::Error::other)?;
    if checkpoint.sequence == 0
        || checkpoint.digest.len() != 64
        || !checkpoint
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(HostInputs {
        _key: key,
        _checkpoint: checkpoint,
    })
}

pub(crate) fn run_host_login_diagnostic() -> ExitCode {
    if std::env::args_os().len() != 1 || unsafe { libc::geteuid() } != 0 {
        eprintln!("host login diagnostic refused: dedicated administrator entry required");
    } else if read_inputs().is_err() {
        eprintln!("host login diagnostic refused: management inputs unavailable or invalid");
    } else {
        eprintln!(
            "host login diagnostic: management inputs read; receipt verification unavailable"
        );
    }
    ExitCode::FAILURE
}
