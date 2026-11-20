use super::{GID, OfflineRecovery, UID, WorkArea, fd_identity, own, unlink_at};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
};

const SETTINGS: &str = "settings.json";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Disposition {
    Remove,
    Retain,
    Quarantine,
}

pub(super) fn disposition(
    recovery: Option<OfflineRecovery>,
    successful: bool,
    explicit_retain: bool,
) -> Disposition {
    match recovery {
        Some(OfflineRecovery::RemovedAfterTermination) if successful && explicit_retain => {
            Disposition::Retain
        }
        Some(OfflineRecovery::RemovedAfterTermination | OfflineRecovery::RemovedBeforeGrant) => {
            Disposition::Remove
        }
        Some(OfflineRecovery::RetainedAfterGrant) | None => Disposition::Quarantine,
    }
}

pub(super) struct Generation {
    pub path: PathBuf,
    name: CString,
    pinned: File,
}

impl Generation {
    pub fn create(parent: &File, parent_path: &Path, work: &WorkArea) -> io::Result<Self> {
        // mkdirat with the current work name refuses a stale generation.
        let name = work.name.clone();
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let path = parent_path.join(std::ffi::OsStr::from_bytes(name.as_bytes()));
        let pinned = WorkArea::open_at(parent, &name)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join(SETTINGS))?;
        own(&path.join(SETTINGS), 0o600).map_err(|fault| io::Error::other(fault.reason()))?;
        own(&path, 0o700).map_err(|fault| io::Error::other(fault.reason()))?;
        Ok(Self { path, name, pinned })
    }

    pub fn bind(&self, root: &Path) -> Result<(), super::Fault> {
        use super::super::os;
        let target = root.join("home/fixture/config");
        os::mount(Some(&self.path), &target, None, libc::MS_BIND, None)?;
        os::mount(
            None,
            &target,
            None,
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            None,
        )?;
        if fd_identity(&File::open(target)?)? != fd_identity(&self.pinned)? {
            return Err(super::Fault::Identity);
        }
        Ok(())
    }

    pub fn audit(&self, parent: &File, require_probe: bool) -> io::Result<bool> {
        let current = WorkArea::open_at(parent, &self.name)?;
        let directory = self.pinned.metadata()?;
        if fd_identity(&current)? != fd_identity(&self.pinned)?
            || (directory.uid(), directory.gid(), directory.mode() & 0o7777) != (UID, GID, 0o700)
        {
            return Err(io::Error::other("private configuration identity changed"));
        }
        let mut settings = false;
        let mut probe = false;
        for item in fs::read_dir(format!("/proc/self/fd/{}", self.pinned.as_raw_fd()))? {
            let item = item?;
            let metadata = item.path().symlink_metadata()?;
            if !metadata.is_file()
                || (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777) != (UID, GID, 0o600)
                || metadata.len() != 0
                || metadata.nlink() != 1
            {
                return Err(io::Error::other(
                    "unexpected private configuration metadata",
                ));
            }
            match item.file_name().as_bytes() {
                b"settings.json" => settings = true,
                b"write-probe" => probe = true,
                _ => return Err(io::Error::other("unexpected private configuration entry")),
            }
        }
        if !settings || require_probe && !probe {
            return Err(io::Error::other(
                "private configuration observation missing",
            ));
        }
        Ok(probe)
    }

    pub fn finish(
        &self,
        parent: &File,
        action: Disposition,
        require_probe: bool,
    ) -> io::Result<()> {
        if action == Disposition::Quarantine {
            return Err(io::Error::other("private configuration quarantined"));
        }
        let probe = self.audit(parent, require_probe)?;
        if action == Disposition::Remove {
            if probe {
                unlink_at(self.pinned.as_raw_fd(), c"write-probe", 0)?;
            }
            unlink_at(self.pinned.as_raw_fd(), c"settings.json", 0)?;
            unlink_at(parent.as_raw_fd(), &self.name, libc::AT_REMOVEDIR)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires root and private network and mount namespaces"]
    fn unknown_exit_refuses_reuse_and_preserves_generation() {
        use super::super::{directory, request_cli_start, supervised_observed};
        let fixture = Path::new("/var/lib").join(format!(
            "tempest-writable-test-{}",
            crate::private_io::random_hex().unwrap()
        ));
        fs::create_dir(&fixture).unwrap();
        fs::set_permissions(
            &fixture,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let work_root = fixture.join("work");
        let config_root = fixture.join("config");
        fs::create_dir(&work_root).unwrap();
        fs::create_dir(&config_root).unwrap();
        let work_parent = directory(&work_root).unwrap();
        let config_parent = directory(&config_root).unwrap();
        let work = WorkArea::create(&work_parent, &work_root).unwrap();
        let config = Generation::create(&config_parent, &config_root, &work).unwrap();
        let mut observed = None;
        let result = supervised_observed(
            &work_parent,
            &work,
            |_, _, control, _| {
                request_cli_start(control)?;
                // Exit after grant before attesting to PID reaping and mount detach.
                unsafe { libc::_exit(7) }
            },
            &mut observed,
        );
        assert!(result.is_err());
        let observed = observed.unwrap();
        assert!(matches!(
            observed.recovery,
            OfflineRecovery::RetainedAfterGrant
        ));
        assert!(
            config
                .finish(
                    &config_parent,
                    disposition(Some(observed.recovery), false, false),
                    false
                )
                .is_err()
        );
        config.audit(&config_parent, false).unwrap();
        assert!(work.path.is_dir());
        assert_eq!(
            Generation::create(&config_parent, &config_root, &work)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::AlreadyExists
        );

        let next = WorkArea::create(&work_parent, &work_root).unwrap();
        let next_config = Generation::create(&config_parent, &config_root, &next).unwrap();
        assert_ne!(
            fd_identity(&config.pinned).unwrap(),
            fd_identity(&next_config.pinned).unwrap()
        );
        let unexpected = next_config.path.join("unexpected");
        fs::write(&unexpected, b"").unwrap();
        own(&unexpected, 0o600).unwrap();
        assert!(
            next_config
                .finish(&config_parent, Disposition::Remove, false)
                .is_err()
        );
        assert!(unexpected.exists());
        fs::remove_file(unexpected).unwrap();
        next_config
            .finish(&config_parent, Disposition::Remove, false)
            .unwrap();
        next.remove(&work_parent).unwrap();
        config.audit(&config_parent, false).unwrap();

        // The injected fault launched no command, and the supervisor has been reaped.
        config
            .finish(&config_parent, Disposition::Remove, false)
            .unwrap();
        work.remove(&work_parent).unwrap();
        fs::remove_dir(work_root).unwrap();
        fs::remove_dir(config_root).unwrap();
        fs::remove_dir(fixture).unwrap();
    }

    #[test]
    fn disposition_requires_confirmed_termination_for_retention() {
        use Disposition::*;
        use OfflineRecovery::*;
        assert_eq!(
            disposition(Some(RemovedAfterTermination), true, true),
            Retain
        );
        assert_eq!(
            disposition(Some(RemovedAfterTermination), true, false),
            Remove
        );
        assert_eq!(
            disposition(Some(RemovedAfterTermination), false, true),
            Remove
        );
        assert_eq!(disposition(Some(RemovedBeforeGrant), false, true), Remove);
        assert_eq!(
            disposition(Some(RetainedAfterGrant), true, true),
            Quarantine
        );
        assert_eq!(disposition(None, false, false), Quarantine);
    }
}
