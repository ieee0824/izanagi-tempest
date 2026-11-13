use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) fn directory(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)
}
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = crate::proxy_cli::private_new(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
pub(crate) fn json_new(path: &Path, value: &impl serde::Serialize) -> io::Result<()> {
    write_new(path, &serde_json::to_vec_pretty(value)?)
}
pub(crate) fn json_replace(path: &Path, value: &impl serde::Serialize) -> io::Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", random_hex()?));
    write_new(&temporary, &serde_json::to_vec_pretty(value)?)?;
    fs::rename(temporary, path)?;
    File::open(path.parent().unwrap())?.sync_all()
}
pub(crate) fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension(format!("{}.tmp", random_hex()?));
    write_new(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    File::open(path.parent().unwrap())?.sync_all()
}
pub(crate) fn digest(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut buffer = [0; 65536];
    let mut hash = Sha256::new();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
pub(crate) fn json_append(path: &Path, value: &impl serde::Serialize) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    serde_json::to_writer(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

pub(crate) fn random_hex() -> io::Result<String> {
    let mut bytes = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
pub(crate) fn now_ns() -> io::Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| io::Error::other("invalid host clock"))?
            .as_nanos(),
    )
    .map_err(|_| io::Error::other("host clock overflow"))
}
pub(crate) fn utc_offset_seconds() -> io::Result<i64> {
    let seconds = (now_ns()? / 1_000_000_000) as libc::time_t;
    let mut local: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&seconds, &mut local) }.is_null() {
        return Err(io::Error::other("host timezone unavailable"));
    }
    Ok(local.tm_gmtoff as i64)
}
pub(crate) fn command(executable: &Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(executable);
    command.env_clear();
    command.stdin(std::process::Stdio::null());
    for name in ["HOME", "PATH", "TZ"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("TERM", "dumb");
    command
}
pub(crate) fn private_copy(source: &Path, target: &Path) -> io::Result<()> {
    let metadata = source.symlink_metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("source must be a regular file"));
    }
    let mut input = File::open(source)?;
    let mut output = crate::proxy_cli::private_new(target)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o600))
}
