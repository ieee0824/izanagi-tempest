//! Fixed-name, run-owned kernel resource group. Supervisor never joins it.
use super::{contract::Role, os::Fault};
use std::{
    ffi::CString,
    fs, io,
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
    thread,
    time::{Duration, Instant},
};

pub(super) const ROOT: &str = "/sys/fs/cgroup/tempest-linux-isolation-probe";

pub(super) struct Group {
    armed: bool,
    identity: (u64, u64),
    directory: fs::File,
}

/// No normal Group API and no Drop cleanup. Only an exclusive death proof
/// authorizes use of the already validated identity and duplicated directory FD.
pub(super) struct RecoveryGroup {
    identity: (u64, u64),
    directory: fs::File,
}
impl RecoveryGroup {
    fn verify_pinned(&self) -> Result<(), Fault> {
        use std::os::unix::fs::MetadataExt;
        let pinned = self.directory.metadata()?;
        if !pinned.is_dir() || (pinned.dev(), pinned.ino()) != self.identity {
            return Err(Fault::Identity);
        }
        Ok(())
    }
    fn verify(&self) -> Result<(), Fault> {
        use std::os::unix::fs::MetadataExt;
        let pinned = self.directory.metadata()?;
        let current = fs::symlink_metadata(ROOT)?;
        if !current.is_dir()
            || (current.dev(), current.ino()) != self.identity
            || (pinned.dev(), pinned.ino()) != self.identity
        {
            return Err(Fault::Identity);
        }
        Ok(())
    }
    pub(super) fn recover(
        self,
        proof: &super::watchdog::DeadGuardian<'_>,
        registry: &mut super::registry::Registry,
        counts: &mut super::registry::Counts,
    ) -> Result<(), Fault> {
        self.verify_pinned()?;
        if matches!(fs::symlink_metadata(ROOT), Err(error) if error.kind() == io::ErrorKind::NotFound)
        {
            counts.cgroup_populated = Some(false);
            return registry.stop_and_reap(proof, counts);
        }
        self.verify()?;
        let mut evidence_failure = None;
        // Snapshot is bounded by the fixed parent pids.max=48; populated=0
        // remains independently necessary because fork can race this snapshot.
        for role in Role::ALL {
            use super::registry::SnapshotStage;
            let mut stage = SnapshotStage::ReadMembers;
            let result = (|| {
                let directory = match open_at(
                    &self.directory,
                    role.name(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                ) {
                    Ok(directory) => directory,
                    Err(Fault::Kernel(libc::ENOENT)) => return Ok(()),
                    Err(error) => return Err(error),
                };
                let members = read(&directory, "cgroup.procs")?;
                if members.len() > 1024 {
                    return Err(Fault::Identity);
                }
                for pid in members.split_whitespace().take(49) {
                    stage = SnapshotStage::Bind;
                    let process =
                        super::identity::Process::bind(pid.parse().map_err(|_| Fault::Identity)?)?;
                    stage = SnapshotStage::Membership;
                    if !process.recovery_member(role)? {
                        return Err(Fault::Identity);
                    }
                    stage = SnapshotStage::Track;
                    registry.track(role, &process, false)?;
                }
                Ok::<_, Fault>(())
            })();
            if let Err(error) = result {
                if counts.snapshot_stage.is_none() {
                    counts.snapshot_stage = Some(stage);
                    counts.snapshot_reason = Some(error.reason());
                    counts.snapshot_errno = match error {
                        Fault::Kernel(errno) => Some(errno),
                        _ => None,
                    };
                }
                evidence_failure.get_or_insert(error);
            }
        }
        self.verify()?;
        let stopped = write(&self.directory, "cgroup.kill", "1");
        // Stop unattached direct children even if cgroup.kill failed.
        let reaped = registry.stop_and_reap(proof, counts);
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            self.verify()?;
            let events = read(&self.directory, "cgroup.events")?;
            counts.cgroup_populated = events.lines().find_map(|line| match line {
                "populated 0" => Some(false),
                "populated 1" => Some(true),
                _ => None,
            });
            if counts.cgroup_populated == Some(false) {
                break;
            }
            if Instant::now() >= until {
                return Err(Fault::Kernel(libc::EBUSY));
            }
            thread::sleep(Duration::from_millis(10));
        }
        stopped?;
        reaped?;
        if let Some(error) = evidence_failure {
            return Err(error);
        }
        for role in Role::ALL {
            match rmdir(&self.directory, role.name()) {
                Ok(()) | Err(Fault::Kernel(libc::ENOENT)) => (),
                Err(error) => return Err(error),
            }
        }
        self.verify()?;
        // Top-level identity-check/unlink race with another privileged actor
        // remains a separate gate, as in the normal cleanup path.
        fs::remove_dir(ROOT)?;
        Ok(())
    }
}

fn open_directory() -> Result<fs::File, Fault> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(ROOT)?)
}

fn component(name: &str) -> Result<CString, Fault> {
    if name.is_empty() || matches!(name, "." | "..") || name.contains('/') {
        return Err(Fault::Path);
    }
    CString::new(name).map_err(|_| Fault::Path)
}

fn open_at(directory: &fs::File, name: &str, flags: i32) -> Result<fs::File, Fault> {
    let name = component(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn write(directory: &fs::File, name: &str, value: &str) -> Result<(), Fault> {
    use std::io::Write;
    open_at(directory, name, libc::O_WRONLY)?.write_all(value.as_bytes())?;
    Ok(())
}

fn read(directory: &fs::File, name: &str) -> Result<String, Fault> {
    use std::io::Read;
    let mut value = String::new();
    open_at(directory, name, libc::O_RDONLY)?.read_to_string(&mut value)?;
    Ok(value)
}

fn mkdir(directory: &fs::File, name: &str) -> Result<(), Fault> {
    let name = component(name)?;
    super::os::syscall(unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o755) })
}

fn rmdir(directory: &fs::File, name: &str) -> Result<(), Fault> {
    let name = component(name)?;
    super::os::syscall(unsafe {
        libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
    })
}

impl Group {
    pub(super) fn recovery_handle(&self) -> Result<RecoveryGroup, Fault> {
        self.verify()?;
        Ok(RecoveryGroup {
            identity: self.identity,
            directory: super::os::duplicate_fd(self.directory.as_raw_fd())?.into(),
        })
    }
    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
    pub(super) fn arm(&mut self) {
        self.armed = true;
    }
    pub(super) fn identity(&self) -> (u64, u64) {
        self.identity
    }

    pub(super) fn adopt(identity: (u64, u64)) -> Result<Self, Fault> {
        let group = Self {
            armed: true,
            identity,
            directory: open_directory()?,
        };
        group.verify()?;
        Ok(group)
    }

    fn verify(&self) -> Result<(), Fault> {
        super::lease::pulse()?;
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(ROOT)?;
        let pinned = self.directory.metadata()?;
        if !metadata.is_dir()
            || (metadata.dev(), metadata.ino()) != self.identity
            || (pinned.dev(), pinned.ino()) != self.identity
        {
            return Err(Fault::Identity);
        }
        Ok(())
    }

    pub(super) fn recover(&mut self) -> Result<(), Fault> {
        // Parent may have completed cleanup already; never adopt a replacement.
        match fs::symlink_metadata(ROOT) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.armed = false;
                Ok(())
            }
            _ => self.cleanup(),
        }
    }
    pub(super) fn create() -> Result<Self, Fault> {
        let path = Path::new(ROOT);
        // A leftover group is never adopted or overwritten by a new probe.
        fs::create_dir(path)?;
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(path)?;
        let mut group = Self {
            armed: true,
            identity: (metadata.dev(), metadata.ino()),
            directory: open_directory()?,
        };
        let setup = (|| {
            for (name, value) in [
                ("memory.max", "536870912"),
                ("memory.swap.max", "0"),
                ("pids.max", "48"),
                ("cpu.max", "50000 100000"),
                ("cgroup.subtree_control", "+cpu +memory +pids"),
            ] {
                write(&group.directory, name, value)?;
            }
            for role in Role::ALL {
                mkdir(&group.directory, role.name())?;
                let child = open_at(
                    &group.directory,
                    role.name(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )?;
                for (name, value) in [
                    ("memory.max", "134217728"),
                    ("memory.swap.max", "0"),
                    ("pids.max", "12"),
                    ("cpu.max", "20000 100000"),
                ] {
                    write(&child, name, value)?;
                    // Kernel-normalized whitespace is not policy variance.
                    if read(&child, name)?.trim() != value {
                        return Err(Fault::Identity);
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = setup {
            // Do not turn a cleanup failure into successful initialization.
            if group.cleanup().is_err() {
                return Err(Fault::Kernel(libc::EBUSY));
            }
            return Err(error);
        }
        Ok(group)
    }

    pub(super) fn attach(&self, role: Role, pid: u32) -> Result<(), Fault> {
        self.verify()?;
        let child = open_at(
            &self.directory,
            role.name(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        write(&child, "cgroup.procs", &pid.to_string())
    }

    pub(super) fn bound(&self, role: Role, pid: u32) -> Result<bool, Fault> {
        self.verify()?;
        let value = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        Ok(value
            .lines()
            .any(|line| line == format!("0::/tempest-linux-isolation-probe/{}", role.name())))
    }

    pub(super) fn pids_events(&self) -> Result<u64, Fault> {
        self.verify()?;
        let child = open_at(
            &self.directory,
            Role::A.name(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        read(&child, "pids.events")?
            .lines()
            .find_map(|line| line.strip_prefix("max "))
            .ok_or(Fault::Identity)?
            .parse()
            .map_err(|_| Fault::Identity)
    }

    pub(super) fn pids_members(&self) -> Result<Vec<u32>, Fault> {
        self.verify()?;
        let child = open_at(
            &self.directory,
            Role::A.name(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        if read(&child, "pids.current")?.trim() != "12" || read(&child, "pids.max")?.trim() != "12"
        {
            return Err(Fault::Identity);
        }
        self.members(Role::A)
    }

    pub(super) fn members(&self, role: Role) -> Result<Vec<u32>, Fault> {
        self.verify()?;
        let child = open_at(
            &self.directory,
            role.name(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        read(&child, "cgroup.procs")?
            .split_whitespace()
            .map(|pid| pid.parse().map_err(|_| Fault::Identity))
            .collect()
    }

    pub(super) fn memory_events(&self, role: Option<Role>) -> Result<[u64; 3], Fault> {
        self.verify()?;
        let directory = if let Some(role) = role {
            open_at(
                &self.directory,
                role.name(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?
        } else {
            self.directory.try_clone()?
        };
        let limit = if role.is_some() {
            "134217728"
        } else {
            "536870912"
        };
        if read(&directory, "memory.max")?.trim() != limit
            || read(&directory, "memory.swap.max")?.trim() != "0"
        {
            return Err(Fault::Identity);
        }
        let events = read(&directory, "memory.events.local")?;
        let counter = |key: &str| -> Result<u64, Fault> {
            events
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .ok_or(Fault::Identity)?
                .parse()
                .map_err(|_| Fault::Identity)
        };
        Ok([counter("max ")?, counter("oom ")?, counter("oom_kill ")?])
    }

    pub(super) fn kill(&self) -> Result<(), Fault> {
        self.verify()?;
        write(&self.directory, "cgroup.kill", "1")
    }

    pub(super) fn empty(&self) -> Result<bool, Fault> {
        self.verify()?;
        let events = read(&self.directory, "cgroup.events")?;
        events
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
            .map(|value| value == "0")
            .ok_or(Fault::Identity)
    }

    pub(super) fn cleanup(&mut self) -> Result<(), Fault> {
        if !self.armed {
            return Ok(());
        }
        let path = Path::new(ROOT);
        self.kill()?;
        let until = Instant::now() + Duration::from_secs(3);
        while !self.empty()? {
            if Instant::now() >= until {
                return Err(Fault::Kernel(libc::EBUSY));
            }
            thread::sleep(Duration::from_millis(10));
        }
        for role in Role::ALL {
            match rmdir(&self.directory, role.name()) {
                Ok(()) => (),
                Err(Fault::Kernel(libc::ENOENT)) => (),
                Err(e) => return Err(e),
            }
        }
        fs::remove_dir(path)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        // Last-resort shutdown on early returns; normal completion must check
        // cleanup() explicitly and retain a failed run lock on any error.
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_write_remains_bound_to_directory_after_path_replacement() {
        let base = std::env::temp_dir().join(format!(
            "tempest-cgroup-fd-{}",
            crate::private_io::random_hex().unwrap()
        ));
        super::super::os::private_directory(&base).unwrap();
        let path = base.join("group");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("cgroup.kill"), b"0").unwrap();
        let pinned = fs::File::open(&path).unwrap();
        fs::rename(&path, base.join("original")).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("cgroup.kill"), b"0").unwrap();
        // Simulate replacement AFTER the caller's identity check. openat must
        // still target the held directory, never the newly named group.
        write(&pinned, "cgroup.kill", "1").unwrap();
        assert_eq!(fs::read(base.join("original/cgroup.kill")).unwrap(), b"1");
        assert_eq!(fs::read(path.join("cgroup.kill")).unwrap(), b"0");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn control_symlinks_and_parent_components_are_not_followed() {
        let base = std::env::temp_dir().join(format!(
            "tempest-cgroup-link-{}",
            crate::private_io::random_hex().unwrap()
        ));
        super::super::os::private_directory(&base).unwrap();
        fs::write(base.join("foreign"), b"0").unwrap();
        std::os::unix::fs::symlink(base.join("foreign"), base.join("cgroup.kill")).unwrap();
        let directory = fs::File::open(&base).unwrap();
        assert!(write(&directory, "cgroup.kill", "1").is_err());
        assert_eq!(fs::read(base.join("foreign")).unwrap(), b"0");
        for name in ["", ".", "..", "../foreign", "a/b"] {
            assert_eq!(component(name), Err(Fault::Path));
        }
        fs::remove_dir_all(base).unwrap();
    }
}
