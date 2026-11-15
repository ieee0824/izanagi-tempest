//! Fixed-name, run-owned kernel resource group. Supervisor never joins it.
use super::{contract::Role, os::Fault};
use std::{
    fs, io,
    path::Path,
    thread,
    time::{Duration, Instant},
};

pub(super) const ROOT: &str = "/sys/fs/cgroup/tempest-linux-isolation-probe";

pub(super) struct Group {
    armed: bool,
}

fn write(path: &Path, name: &str, value: &str) -> Result<(), Fault> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut file = fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path.join(name))?;
    file.write_all(value.as_bytes())?;
    Ok(())
}

impl Group {
    pub(super) fn recover_owned() -> Result<(), Fault> {
        if !Path::new(ROOT).exists() {
            return Ok(());
        }
        let mut group = Self { armed: true };
        group.cleanup()
    }
    pub(super) fn create() -> Result<Self, Fault> {
        let path = Path::new(ROOT);
        // A leftover group is never adopted or overwritten by a new probe.
        fs::create_dir(path)?;
        let mut group = Self { armed: true };
        let setup = (|| {
            for (name, value) in [
                ("memory.max", "536870912"),
                ("memory.swap.max", "0"),
                ("pids.max", "48"),
                ("cpu.max", "50000 100000"),
                ("cgroup.subtree_control", "+cpu +memory +pids"),
            ] {
                write(path, name, value)?;
            }
            for role in Role::ALL {
                let child = path.join(role.name());
                fs::create_dir(&child)?;
                for (name, value) in [
                    ("memory.max", "134217728"),
                    ("memory.swap.max", "0"),
                    ("pids.max", "12"),
                    ("cpu.max", "20000 100000"),
                ] {
                    write(&child, name, value)?;
                    // Kernel-normalized whitespace is not policy variance.
                    if fs::read_to_string(child.join(name))?.trim() != value {
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
        write(
            &Path::new(ROOT).join(role.name()),
            "cgroup.procs",
            &pid.to_string(),
        )
    }

    pub(super) fn bound(&self, role: Role, pid: u32) -> Result<bool, Fault> {
        let value = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        Ok(value
            .lines()
            .any(|line| line == format!("0::/tempest-linux-isolation-probe/{}", role.name())))
    }

    pub(super) fn kill(&self) -> Result<(), Fault> {
        write(Path::new(ROOT), "cgroup.kill", "1")
    }

    pub(super) fn empty(&self) -> Result<bool, Fault> {
        let events = fs::read_to_string(Path::new(ROOT).join("cgroup.events"))?;
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
            match fs::remove_dir(path.join(role.name())) {
                Ok(()) => (),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
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
