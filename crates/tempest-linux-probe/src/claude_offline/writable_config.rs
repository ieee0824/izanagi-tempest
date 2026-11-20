use super::{GID, OfflineRecovery, UID, WorkArea, fd_identity, unlink_at};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
};

const SETTINGS: &str = "settings.json";
const INITIAL_SETTINGS: &[u8] = b"{}\n";

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

#[derive(Clone, Copy, PartialEq, Eq)]
enum SetupStage {
    OpenDirectory,
    CreateSettings,
    ConfigurePermissions,
}

fn configure(file: &File, mode: u32) -> io::Result<()> {
    if unsafe { libc::fchown(file.as_raw_fd(), UID, GID) } < 0 {
        return Err(io::Error::last_os_error());
    }
    file.set_permissions(fs::Permissions::from_mode(mode))
}

impl Generation {
    pub fn create(parent: &File, parent_path: &Path, work: &WorkArea) -> io::Result<Self> {
        Self::create_with(parent, parent_path, work, |_, _| Ok(()))
    }

    fn create_with(
        parent: &File,
        parent_path: &Path,
        work: &WorkArea,
        mut before: impl FnMut(SetupStage, &Path) -> io::Result<()>,
    ) -> io::Result<Self> {
        // An existing generation prevents mkdirat from succeeding and is never recovered here.
        let name = work.name.clone();
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let path = parent_path.join(std::ffi::OsStr::from_bytes(name.as_bytes()));
        let mut identity = None;
        let mut settings = None;
        let result = (|| {
            let metadata = fs::symlink_metadata(
                PathBuf::from(format!("/proc/self/fd/{}", parent.as_raw_fd()))
                    .join(std::ffi::OsStr::from_bytes(name.as_bytes())),
            )?;
            if !metadata.is_dir() || metadata.uid() != 0 {
                return Err(io::Error::other(
                    "new configuration directory identity unavailable",
                ));
            }
            identity = Some((metadata.dev(), metadata.ino()));
            before(SetupStage::OpenDirectory, &path)?;
            let pinned = WorkArea::open_at(parent, &name)?;
            if Some(fd_identity(&pinned)?) != identity {
                return Err(io::Error::other(
                    "new configuration directory identity changed",
                ));
            }
            before(SetupStage::CreateSettings, &path)?;
            let directory = PathBuf::from(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.join(SETTINGS))?;
            settings = Some(file);
            let mut file = settings.as_ref().unwrap();
            file.write_all(INITIAL_SETTINGS)?;
            before(SetupStage::ConfigurePermissions, &path)?;
            configure(file, 0o600)?;
            configure(&pinned, 0o700)?;
            Ok(pinned)
        })();

        match result {
            Ok(pinned) => Ok(Self { path, name, pinned }),
            Err(setup) => match Self::rollback_setup(parent, &name, identity, settings.as_ref()) {
                Ok(()) => Err(io::Error::other(format!(
                    "private configuration setup failed; new generation removed: {setup}"
                ))),
                Err(cleanup) => Err(io::Error::other(format!(
                    "private configuration setup failed; generation retained or removal unconfirmed: {setup}; cleanup: {cleanup}"
                ))),
            },
        }
    }

    fn rollback_setup(
        parent: &File,
        name: &std::ffi::CStr,
        identity: Option<(u64, u64)>,
        settings: Option<&File>,
    ) -> io::Result<()> {
        let pinned = WorkArea::open_at(parent, name)?;
        if Some(fd_identity(&pinned)?) != identity {
            return Err(io::Error::other(
                "private configuration rollback identity mismatch",
            ));
        }
        let directory = PathBuf::from(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
        for item in fs::read_dir(directory)? {
            let item = item?;
            let metadata = item.path().symlink_metadata()?;
            if item.file_name() != SETTINGS
                || !metadata.is_file()
                || metadata.nlink() != 1
                || Some((metadata.dev(), metadata.ino()))
                    != settings.map(fd_identity).transpose()?
            {
                return Err(io::Error::other(
                    "unexpected entry during private configuration rollback",
                ));
            }
        }
        if settings.is_some() {
            unlink_at(pinned.as_raw_fd(), c"settings.json", 0)?;
        }
        unlink_at(parent.as_raw_fd(), name, libc::AT_REMOVEDIR)
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
        let mounted = File::open(target)?;
        if fd_identity(&mounted)? != fd_identity(&self.pinned)? || self.audit_entries(false)? {
            return Err(super::Fault::Identity);
        }
        Ok(())
    }

    pub fn audit(&self, parent: &File, require_probe: bool) -> io::Result<bool> {
        let current = WorkArea::open_at(parent, &self.name)?;
        if fd_identity(&current)? != fd_identity(&self.pinned)? {
            return Err(io::Error::other("private configuration identity changed"));
        }
        self.audit_entries(require_probe)
    }

    fn audit_entries(&self, require_probe: bool) -> io::Result<bool> {
        let directory = self.pinned.metadata()?;
        if (directory.uid(), directory.gid(), directory.mode() & 0o7777) != (UID, GID, 0o700) {
            return Err(io::Error::other(
                "private configuration permissions changed",
            ));
        }
        let mut settings = false;
        let mut probe = false;
        for item in fs::read_dir(format!("/proc/self/fd/{}", self.pinned.as_raw_fd()))? {
            let item = item?;
            let metadata = item.path().symlink_metadata()?;
            if !metadata.is_file()
                || (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777) != (UID, GID, 0o600)
                || metadata.nlink() != 1
            {
                return Err(io::Error::other(
                    "unexpected private configuration metadata",
                ));
            }
            match item.file_name().as_bytes() {
                b"settings.json" if metadata.len() == INITIAL_SETTINGS.len() as u64 => {
                    let mut settings_file = OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                        .open(item.path())?;
                    let mut contents = [0; INITIAL_SETTINGS.len()];
                    use std::io::Read;
                    if fd_identity(&settings_file)? != (metadata.dev(), metadata.ino()) {
                        return Err(io::Error::other("private settings identity changed"));
                    }
                    settings_file.read_exact(&mut contents)?;
                    if contents != INITIAL_SETTINGS || settings_file.read(&mut [0])? != 0 {
                        return Err(io::Error::other("private settings contents changed"));
                    }
                    settings = true;
                }
                b"write-probe" if metadata.len() == 0 => probe = true,
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
    use super::super::own;
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    #[test]
    #[ignore = "requires root to create fixed UID/GID configuration fixtures"]
    fn partial_setup_recovers_only_the_new_generation() {
        use super::super::directory;
        let fixture = Path::new("/var/lib").join(format!(
            "tempest-writable-rollback-{}",
            crate::private_io::random_hex().unwrap()
        ));
        fs::DirBuilder::new().mode(0o700).create(&fixture).unwrap();
        let work_root = fixture.join("work");
        let config_root = fixture.join("config");
        fs::create_dir(&work_root).unwrap();
        fs::create_dir(&config_root).unwrap();
        let work_parent = directory(&work_root).unwrap();
        let config_parent = directory(&config_root).unwrap();
        let prior_work = WorkArea::create(&work_parent, &work_root).unwrap();
        let prior = Generation::create(&config_parent, &config_root, &prior_work).unwrap();
        let prior_identity = fd_identity(&prior.pinned).unwrap();
        let duplicate = Generation::create(&config_parent, &config_root, &prior_work);
        assert_eq!(
            duplicate.err().unwrap().kind(),
            io::ErrorKind::AlreadyExists
        );

        let work = WorkArea::create(&work_parent, &work_root).unwrap();
        for injected in [
            SetupStage::OpenDirectory,
            SetupStage::CreateSettings,
            SetupStage::ConfigurePermissions,
        ] {
            let result =
                Generation::create_with(&config_parent, &config_root, &work, |stage, _| {
                    if stage == injected {
                        return Err(io::Error::other("injected setup failure"));
                    }
                    Ok(())
                });
            assert!(
                result
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("new generation removed")
            );
            assert_eq!(fs::read_dir(&config_root).unwrap().count(), 1);
            assert!(!prior.audit(&config_parent, false).unwrap());
            assert_eq!(fd_identity(&prior.pinned).unwrap(), prior_identity);
        }

        let result = Generation::create_with(&config_parent, &config_root, &work, |stage, path| {
            if stage == SetupStage::ConfigurePermissions {
                fs::write(path.join("unexpected"), b"")?;
                return Err(io::Error::other("injected failure with unexpected entry"));
            }
            Ok(())
        });
        assert!(
            result
                .err()
                .unwrap()
                .to_string()
                .contains("generation retained or removal unconfirmed")
        );
        let retained = config_root.join(std::ffi::OsStr::from_bytes(work.name.as_bytes()));
        assert!(retained.join(SETTINGS).is_file());
        assert!(retained.join("unexpected").is_file());
        assert!(!prior.audit(&config_parent, false).unwrap());
        assert_eq!(fd_identity(&prior.pinned).unwrap(), prior_identity);

        fs::remove_file(retained.join("unexpected")).unwrap();
        fs::remove_file(retained.join(SETTINGS)).unwrap();
        fs::remove_dir(retained).unwrap();
        work.remove(&work_parent).unwrap();
        prior
            .finish(&config_parent, Disposition::Remove, false)
            .unwrap();
        prior_work.remove(&work_parent).unwrap();
        fs::remove_dir(work_root).unwrap();
        fs::remove_dir(config_root).unwrap();
        fs::remove_dir(fixture).unwrap();
    }

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
