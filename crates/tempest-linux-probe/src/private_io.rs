//! Small local probe I/O; never imports the production Tempest launcher.
#[cfg(test)]
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};
use std::{
    fs::File,
    io::{self, Read},
};

pub(crate) fn random_hex() -> io::Result<String> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
pub(crate) fn directory(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(test)]
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(test)]
pub(crate) fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension(random_hex()?);
    write_new(&temporary, bytes)?;
    fs::rename(temporary, path)
}
