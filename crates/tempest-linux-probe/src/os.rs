//! Descriptor-bound immutable code and kernel resource primitives.
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Fault {
    ExitedAfterListing,
    Identity,
    LeaseUnavailable,
    WatchdogRecovery,
    GuardianUnconfirmed,
    GuardianStartupStopped,
    GuardianDied,
    Ownership,
    Path,
    Seal,
    Kernel(i32),
    Child(i32),
    ChildSignal(i32, bool),
    OutputLimit(super::contract::Role, u8),
    LifecycleDetected(super::contract::Scenario),
    Bootstrap(u8, i32),
    ForeignReady,
    RunCleanup,
    UntrackedChildCleanup(i32),
    ReportTimeout,
    ReportEof,
    CgroupKillFailureRecovered,
    LibraryRejected(super::contract::Scenario),
}

impl Fault {
    pub(super) fn reason(&self) -> &'static str {
        match self {
            Self::ExitedAfterListing => "exited_after_listing",
            Self::Identity => "identity",
            Self::LeaseUnavailable => "watchdog_lease_unavailable",
            Self::WatchdogRecovery => "watchdog_recovery_failed",
            Self::GuardianUnconfirmed => "watchdog_guardian_unconfirmed",
            Self::GuardianStartupStopped => "watchdog_startup_failed",
            Self::GuardianDied => "watchdog_guardian_died",
            Self::Ownership => "ownership",
            Self::Path => "path",
            Self::Seal => "seal",
            Self::Kernel(_) => "kernel",
            Self::Child(_) => "child_exit",
            Self::ChildSignal(_, _) => "child_signal",
            Self::OutputLimit(_, _) => "output_limit",
            Self::LifecycleDetected(_) => "lifecycle_detected",
            Self::Bootstrap(_, _) => "bootstrap",
            Self::ForeignReady => "foreign_ready",
            Self::RunCleanup => "run_cleanup",
            Self::UntrackedChildCleanup(_) => "untracked_child_cleanup",
            Self::ReportTimeout => "report_timeout",
            Self::ReportEof => "report_eof",
            Self::CgroupKillFailureRecovered => "cgroup_kill_failure_recovered",
            Self::LibraryRejected(_) => "library_rejected",
        }
    }
}

impl From<io::Error> for Fault {
    fn from(value: io::Error) -> Self {
        Self::Kernel(value.raw_os_error().unwrap_or(0))
    }
}

pub(super) fn syscall(result: libc::c_int) -> Result<(), Fault> {
    if result == -1 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

pub(super) fn duplicate_fd(fd: RawFd) -> Result<OwnedFd, Fault> {
    let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if raw < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// These bytes, rather than a subsequently resolved pathname, are what is
/// executed or mounted into the capsule. Neither input nor output is model data.
pub(super) struct Snapshot {
    fd: OwnedFd,
    pub(super) sha256: String,
}

impl Snapshot {
    fn copy(source: &mut impl Read) -> Result<Self, Fault> {
        let name = c"tempest-fixed-probe";
        // SAFETY: a constant NUL-terminated name and supported flag mask.
        let raw = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: memfd_create returned a new descriptor, now owned by File.
        let mut target = unsafe { File::from_raw_fd(raw) };
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 65536];
        loop {
            super::lease::pulse()?;
            let count = source.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
            target.write_all(&buffer[..count])?;
        }
        syscall(unsafe { libc::fchmod(target.as_raw_fd(), 0o555) })?;
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        syscall(unsafe { libc::fcntl(target.as_raw_fd(), libc::F_ADD_SEALS, seals) })?;
        if unsafe { libc::fcntl(target.as_raw_fd(), libc::F_GET_SEALS) } != seals {
            return Err(Fault::Seal);
        }
        target.seek(SeekFrom::Start(0))?;
        Ok(Self {
            fd: target.into(),
            sha256: format!("{:x}", hash.finalize()),
        })
    }

    pub(super) fn trusted(path: &Path) -> Result<Self, Fault> {
        // The caller chooses only fixed binary/library paths. Check every
        // ancestor before resolution, and bind the opened inode to metadata.
        // No symlink, writable ancestor, caller cwd or loader search is trusted.
        if !path.is_absolute() {
            return Err(Fault::Path);
        }
        for ancestor in path.ancestors() {
            let metadata = ancestor.symlink_metadata()?;
            if metadata.file_type().is_symlink() {
                return Err(Fault::Path);
            }
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(Fault::Ownership);
            }
        }
        let mut source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let opened = source.metadata()?;
        let named = path.symlink_metadata()?;
        if !opened.is_file()
            || opened.uid() != 0
            || opened.mode() & 0o022 != 0
            || opened.nlink() != 1
            || opened.dev() != named.dev()
            || opened.ino() != named.ino()
        {
            return Err(Fault::Identity);
        }
        Self::copy(&mut source)
    }

    pub(super) fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub(super) fn identity(&self) -> Result<(u64, u64), Fault> {
        let metadata = fs::metadata(format!("/proc/self/fd/{}", self.fd()))?;
        Ok((metadata.dev(), metadata.ino()))
    }

    pub(super) fn materialize(&self, target: &mut File) -> Result<(), Fault> {
        let mut offset = 0;
        let mut buffer = [0_u8; 65536];
        loop {
            super::lease::pulse()?;
            let count =
                unsafe { libc::pread(self.fd(), buffer.as_mut_ptr().cast(), buffer.len(), offset) };
            if count < 0 {
                return Err(io::Error::last_os_error().into());
            }
            if count == 0 {
                break;
            }
            target.write_all(&buffer[..count as usize])?;
            offset += count as i64;
        }
        self.verify_file(target)?;
        syscall(unsafe { libc::fchmod(target.as_raw_fd(), 0o555) })?;
        Ok(())
    }
    pub(super) fn verify_file(&self, target: &File) -> Result<(), Fault> {
        let mut hash = Sha256::new();
        let mut offset = 0;
        let mut buffer = [0_u8; 65536];
        loop {
            super::lease::pulse()?;
            let count = unsafe {
                libc::pread(
                    target.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    offset,
                )
            };
            if count < 0 {
                return Err(io::Error::last_os_error().into());
            }
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count as usize]);
            offset += count as i64;
        }
        if format!("{:x}", hash.finalize()) != self.sha256 {
            return Err(Fault::Identity);
        }
        Ok(())
    }
}

/// Fork-style clone with independent mount, PID and network namespaces.
pub(super) fn clone_isolated() -> Result<libc::pid_t, Fault> {
    clone_pid_and_mount(true)
}

pub(super) fn clone_pid_and_mount(new_network: bool) -> Result<libc::pid_t, Fault> {
    if !cfg!(target_arch = "x86_64") || fs::read_dir("/proc/self/task")?.count() != 1 {
        return Err(Fault::Identity);
    }
    let mut flags = libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::SIGCHLD;
    if new_network {
        flags |= libc::CLONE_NEWNET;
    }
    let pid = unsafe { libc::syscall(libc::SYS_clone, flags, 0, 0, 0, 0) };
    if pid < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(pid as libc::pid_t)
}

pub(super) fn pipe() -> Result<(OwnedFd, OwnedFd), Fault> {
    let mut fds = [-1; 2];
    syscall(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) })?;
    // SAFETY: pipe2 returned two new descriptors with exactly these owners.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

pub(super) fn mount(
    source: Option<&Path>,
    target: &Path,
    kind: Option<&str>,
    flags: libc::c_ulong,
    options: Option<&str>,
) -> Result<(), Fault> {
    use std::os::unix::ffi::OsStrExt;
    let source = source
        .map(|p| CString::new(p.as_os_str().as_bytes()).map_err(|_| Fault::Path))
        .transpose()?;
    let target = CString::new(target.as_os_str().as_bytes()).map_err(|_| Fault::Path)?;
    let kind = kind
        .map(|s| CString::new(s).map_err(|_| Fault::Path))
        .transpose()?;
    let options = options
        .map(|s| CString::new(s).map_err(|_| Fault::Path))
        .transpose()?;
    syscall(unsafe {
        libc::mount(
            source.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            target.as_ptr(),
            kind.as_ref().map_or(std::ptr::null(), |s| s.as_ptr()),
            flags,
            options
                .as_ref()
                .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
        )
    })
}

pub(super) fn close_except(keep: &[RawFd]) -> Result<(), Fault> {
    let mut keep = keep.to_vec();
    keep.sort_unstable();
    keep.dedup();
    if keep.iter().any(|fd| *fd < 0) {
        return Err(Fault::Identity);
    }
    let mut first = 0_u32;
    for fd in keep {
        let fd = fd as u32;
        if first < fd {
            let result = unsafe { libc::syscall(libc::SYS_close_range, first, fd - 1, 0) };
            if result != 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        first = fd + 1;
    }
    if unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 0) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

pub(super) fn private_directory(path: &Path) -> Result<(), Fault> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

/// Remove only the empty directory acquired by this run. A path replacement
/// or unexpected content is evidence to retain, never recursively adopt.
pub(super) fn remove_owned_empty_directory(path: &Path, pinned: &File) -> Result<(), Fault> {
    let owned = pinned.metadata()?;
    let current = path.symlink_metadata()?;
    if !owned.is_dir()
        || !current.is_dir()
        || owned.dev() != current.dev()
        || owned.ino() != current.ino()
        || current.uid() != unsafe { libc::geteuid() }
        || current.mode() & 0o7777 != 0o700
    {
        return Err(Fault::Identity);
    }
    fs::remove_dir(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_changes_do_not_change_the_sealed_execution_object() {
        let root = std::env::temp_dir().join(format!(
            "tempest-snapshot-{}",
            crate::private_io::random_hex().unwrap()
        ));
        private_directory(&root).unwrap();
        let path = root.join("code");
        crate::private_io::write_new(&path, b"fixed executable bytes").unwrap();
        let snapshot = Snapshot::copy(&mut File::open(&path).unwrap()).unwrap();
        crate::private_io::replace(&path, b"replaced pathname").unwrap();
        let mut observed = Vec::new();
        File::open(format!("/proc/self/fd/{}", snapshot.fd()))
            .unwrap()
            .read_to_end(&mut observed)
            .unwrap();
        assert_eq!(observed, b"fixed executable bytes");
        assert_eq!(snapshot.sha256, format!("{:x}", Sha256::digest(&observed)));
        assert_eq!(
            unsafe { libc::write(snapshot.fd(), b"bad".as_ptr().cast(), 3) },
            -1
        );
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn output_verification_detects_late_write_and_does_not_trust_file_offset() {
        let root = std::env::temp_dir().join(format!(
            "tempest-library-{}",
            crate::private_io::random_hex().unwrap()
        ));
        private_directory(&root).unwrap();
        let path = root.join("library");
        let snapshot = Snapshot::copy(&mut &b"fixed dummy library"[..]).unwrap();
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        snapshot.materialize(&mut writer).unwrap();
        writer.seek(SeekFrom::End(0)).unwrap();
        snapshot.verify_file(&writer).unwrap();
        // Intentionally retain a writable alias as a negative fixture. A
        // content hash from before this write must never authorize the file.
        writer.seek(SeekFrom::Start(0)).unwrap();
        writer.write_all(b"altered").unwrap();
        assert_eq!(snapshot.verify_file(&writer), Err(Fault::Identity));
        drop(writer);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_run_cleanup_does_not_remove_a_replacement_or_unexpected_contents() {
        let base = std::env::temp_dir().join(format!(
            "tempest-lock-{}",
            crate::private_io::random_hex().unwrap()
        ));
        private_directory(&base).unwrap();
        let path = base.join("run");
        private_directory(&path).unwrap();
        let pinned = File::open(&path).unwrap();
        let moved = base.join("old");
        fs::rename(&path, &moved).unwrap();
        private_directory(&path).unwrap();
        assert_eq!(
            remove_owned_empty_directory(&path, &pinned),
            Err(Fault::Identity)
        );
        assert!(path.exists() && moved.exists());
        fs::remove_dir(&path).unwrap();
        fs::rename(&moved, &path).unwrap();
        File::create(path.join("unexpected")).unwrap();
        assert!(remove_owned_empty_directory(&path, &pinned).is_err());
        assert!(path.join("unexpected").exists());
        fs::remove_file(path.join("unexpected")).unwrap();
        remove_owned_empty_directory(&path, &pinned).unwrap();
        fs::remove_dir(base).unwrap();
    }

    #[test]
    fn writable_ancestor_and_symlink_cannot_select_privileged_code() {
        let root = std::env::temp_dir().join(format!(
            "tempest-trusted-path-{}",
            crate::private_io::random_hex().unwrap()
        ));
        private_directory(&root).unwrap();
        crate::private_io::write_new(&root.join("code"), b"dummy").unwrap();
        std::os::unix::fs::symlink(root.join("code"), root.join("link")).unwrap();
        assert!(Snapshot::trusted(&root.join("code")).is_err());
        assert!(Snapshot::trusted(&root.join("link")).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
