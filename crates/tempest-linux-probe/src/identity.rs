//! Kernel observations are independent of a payload's ready message.
use super::{
    cgroup::Group,
    contract::{Identity, Role, State},
    os::Fault,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Descriptor {
    dev: u64,
    ino: u64,
    mode: u32,
    access: i32,
}

impl Descriptor {
    pub(super) fn bind(fd: i32) -> Result<Self, Fault> {
        let metadata = fs::metadata(format!("/proc/self/fd/{fd}"))?;
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if flags & libc::O_PATH != 0 {
            return Err(Fault::Identity);
        }
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            access: flags & libc::O_ACCMODE,
        })
    }

    fn matches(&self, pid: u32, fd: i32) -> Result<bool, Fault> {
        let metadata = fs::metadata(format!("/proc/{pid}/fd/{fd}"))?;
        let info = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}"))?;
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .ok_or(Fault::Identity)?;
        let flags = i32::from_str_radix(flags.trim(), 8).map_err(|_| Fault::Identity)?;
        Ok(flags & libc::O_PATH == 0
            && self.dev == metadata.dev()
            && self.ino == metadata.ino()
            && self.mode == metadata.mode()
            && flags & libc::O_PATH == 0
            && self.access == flags & libc::O_ACCMODE)
    }
}

pub(super) struct Process {
    pub(super) pid: u32,
    pub(super) birth: u64,
    fd: OwnedFd,
}

fn ticks(value: &str, expected_pid: u32) -> Result<u64, Fault> {
    let (pid, _) = value.split_once(' ').ok_or(Fault::Identity)?;
    if pid.parse::<u32>().map_err(|_| Fault::Identity)? != expected_pid {
        return Err(Fault::Identity);
    }
    value
        .rsplit_once(')')
        .ok_or(Fault::Identity)?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or(Fault::Identity)?
        .parse()
        .map_err(|_| Fault::Identity)
}

impl Process {
    pub(super) fn snapshot_read_error(fd: i32, error: Fault) -> Fault {
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 0) } > 0 && poll.revents & libc::POLLIN != 0 {
            Fault::ExitedAfterListing
        } else {
            error
        }
    }
    pub(super) fn recovery_member(&self, role: Role) -> Result<bool, Fault> {
        let membership = fs::read_to_string(format!("/proc/{}/cgroup", self.pid))
            .map_err(|error| Self::snapshot_read_error(self.fd(), error.into()))?;
        let current = ticks(
            &fs::read_to_string(format!("/proc/{}/stat", self.pid))
                .map_err(|error| Self::snapshot_read_error(self.fd(), error.into()))?,
            self.pid,
        )?;
        if current != self.birth
            || !membership
                .lines()
                .any(|line| line == format!("0::/tempest-linux-isolation-probe/{}", role.name()))
        {
            return Ok(false);
        }
        if !self.alive()? {
            return Err(Fault::ExitedAfterListing);
        }
        Ok(true)
    }
    pub(super) fn duplicate(&self) -> Result<Self, Fault> {
        Ok(Self {
            pid: self.pid,
            birth: self.birth,
            fd: super::os::duplicate_fd(self.fd.as_raw_fd())?,
        })
    }
    pub(super) fn fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
    pub(super) fn bind(pid: u32) -> Result<Self, Fault> {
        Self::bind_with_dead_fault(pid, Fault::Identity)
    }
    pub(super) fn bind_snapshot(pid: u32) -> Result<Self, Fault> {
        Self::bind_with_dead_fault(pid, Fault::ExitedAfterListing)
    }
    fn bind_with_dead_fault(pid: u32, dead_fault: Fault) -> Result<Self, Fault> {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let value = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|error| {
            if dead_fault == Fault::ExitedAfterListing {
                Self::snapshot_read_error(fd.as_raw_fd(), error.into())
            } else {
                error.into()
            }
        })?;
        let birth = ticks(&value, pid)?;
        let process = Self { pid, birth, fd };
        if !process.alive()? {
            return Err(dead_fault);
        }
        Ok(process)
    }

    pub(super) fn alive(&self) -> Result<bool, Fault> {
        let mut poll = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(result == 0 && poll.revents == 0)
    }

    pub(super) fn exited(&self) -> Fault {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                self.fd.as_raw_fd() as u32,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 && unsafe { info.si_pid() } != 0 {
            let status = unsafe { info.si_status() };
            match info.si_code {
                libc::CLD_EXITED => Fault::Child(status),
                libc::CLD_KILLED => Fault::ChildSignal(status, false),
                libc::CLD_DUMPED => Fault::ChildSignal(status, true),
                _ => Fault::Identity,
            }
        } else {
            Fault::Identity
        }
    }

    pub(super) fn kill(&self) -> Result<(), Fault> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd.as_raw_fd(),
                libc::SIGKILL,
                0,
                0,
            )
        };
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    pub(super) fn identity(&self) -> Result<Identity, Fault> {
        let root = format!("/proc/{}", self.pid);
        let current = ticks(&fs::read_to_string(format!("{root}/stat"))?, self.pid)?;
        if current != self.birth || !self.alive()? {
            return Err(Fault::Identity);
        }
        let namespaces = namespace_ids(self.pid)?;
        let code = fs::metadata(format!("{root}/exe"))?;
        Ok(Identity {
            pid: self.pid,
            start_ticks: current,
            namespaces,
            code: (code.dev(), code.ino()),
        })
    }

    pub(super) fn lineage(&self) -> Result<[u32; 3], Fault> {
        let value = fs::read_to_string(format!("/proc/{}/stat", self.pid))?;
        if ticks(&value, self.pid)? != self.birth || !self.alive()? {
            return Err(Fault::Identity);
        }
        let fields = value.rsplit_once(')').ok_or(Fault::Identity)?.1;
        let mut fields = fields.split_whitespace().skip(1);
        let mut number = || {
            fields
                .next()
                .ok_or(Fault::Identity)?
                .parse()
                .map_err(|_| Fault::Identity)
        };
        Ok([number()?, number()?, number()?])
    }

    pub(super) fn observe(
        &self,
        group: &Group,
        role: Role,
        descriptors: &BTreeMap<i32, Descriptor>,
    ) -> Result<State, Fault> {
        let identity = self.identity()?;
        let value = fs::read_to_string(format!("/proc/{}/status", self.pid))?;
        let mut state = status(&value, identity)?;
        let expected: BTreeSet<i32> = descriptors.keys().copied().collect();
        let actual = fs::read_dir(format!("/proc/{}/fd", self.pid))?
            .map(|entry| {
                entry?
                    .file_name()
                    .to_str()
                    .ok_or(Fault::Identity)?
                    .parse::<i32>()
                    .map_err(|_| Fault::Identity)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        state.descriptors_bound = actual == expected;
        if state.descriptors_bound {
            for (fd, descriptor) in descriptors {
                state.descriptors_bound &= descriptor.matches(self.pid, *fd)?;
            }
        }
        state.cgroup_bound = group.bound(role, self.pid)?;
        state.alive = self.alive()?;
        if self.identity()? != state.identity {
            return Err(Fault::Identity);
        }
        Ok(state)
    }
}

pub(super) fn namespace_ids(pid: u32) -> Result<[u64; 3], Fault> {
    ["mnt", "pid", "net"]
        .map(|kind| {
            fs::metadata(format!("/proc/{pid}/ns/{kind}"))
                .map(|m| m.ino())
                .map_err(Fault::from)
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| Fault::Identity)
}

fn status(value: &str, identity: Identity) -> Result<State, Fault> {
    let row = |key: &str| {
        value
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .ok_or(Fault::Identity)
    };
    let four = |key| {
        row(key)?
            .split_whitespace()
            .map(|v| v.parse::<u32>().map_err(|_| Fault::Identity))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Fault::Identity)
    };
    let mut capabilities = [0; 5];
    for (index, key) in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
        .iter()
        .enumerate()
    {
        capabilities[index] =
            u64::from_str_radix(row(key)?.trim(), 16).map_err(|_| Fault::Identity)?;
    }
    Ok(State {
        identity,
        uid: four("Uid:")?,
        gid: four("Gid:")?,
        capabilities,
        groups: row("Groups:")?
            .split_whitespace()
            .map(|v| v.parse().map_err(|_| Fault::Identity))
            .collect::<Result<Vec<_>, _>>()?,
        no_new_privs: row("NoNewPrivs:")?.trim() == "1",
        seccomp: row("Seccomp:")?
            .trim()
            .parse()
            .map_err(|_| Fault::Identity)?,
        descriptors_bound: false,
        cgroup_bound: false,
        alive: false,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn normal_exit_nine_is_distinct_from_sigkill_without_reaping() {
        struct Child(i32);
        impl Drop for Child {
            fn drop(&mut self) {
                // This is our own unreaped child, so its PID cannot be reused.
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                    libc::waitpid(self.0, std::ptr::null_mut(), 0);
                }
            }
        }
        for killed in [false, true] {
            let (read, write) = super::super::os::pipe().unwrap();
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                use std::os::fd::AsRawFd;
                let mut byte = 0_u8;
                unsafe {
                    libc::read(read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1);
                    libc::_exit(9);
                }
            }
            let _child = Child(pid);
            let process = super::Process::bind(pid as u32).unwrap();
            if killed {
                process.kill().unwrap();
            } else {
                use std::os::fd::AsRawFd;
                assert_eq!(
                    unsafe { libc::write(write.as_raw_fd(), b"G".as_ptr().cast(), 1) },
                    1
                );
            }
            let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while process.alive().unwrap() {
                assert!(std::time::Instant::now() < until);
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            assert_eq!(
                process.exited(),
                if killed {
                    super::Fault::ChildSignal(libc::SIGKILL, false)
                } else {
                    super::Fault::Child(9)
                }
            );
        }
    }

    #[test]
    fn process_lineage_matches_independent_kernel_calls() {
        let process = super::Process::bind(std::process::id()).unwrap();
        assert_eq!(process.lineage().unwrap(), unsafe {
            [
                libc::getppid() as u32,
                libc::getpgrp() as u32,
                libc::getsid(0) as u32,
            ]
        });
    }

    use super::*;

    #[test]
    fn descriptor_binding_checks_object_and_access_not_only_fd_count() {
        use std::os::unix::fs::OpenOptionsExt;

        let root = std::env::temp_dir().join(format!(
            "tempest-fd-binding-{}",
            crate::private_io::random_hex().unwrap()
        ));
        crate::private_io::directory(&root).unwrap();
        for name in ["one", "two"] {
            crate::private_io::write_new(&root.join(name), b"dummy").unwrap();
        }
        let read = fs::File::open(root.join("one")).unwrap();
        let write = fs::OpenOptions::new()
            .write(true)
            .open(root.join("one"))
            .unwrap();
        let other = fs::File::open(root.join("two")).unwrap();
        let path_only = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(root.join("one"))
            .unwrap();
        let bound = Descriptor::bind(read.as_raw_fd()).unwrap();
        assert!(matches!(
            Descriptor::bind(path_only.as_raw_fd()),
            Err(Fault::Identity)
        ));
        assert!(
            !bound
                .matches(std::process::id(), path_only.as_raw_fd())
                .unwrap()
        );
        assert!(bound.matches(std::process::id(), read.as_raw_fd()).unwrap());
        assert!(
            !bound
                .matches(std::process::id(), write.as_raw_fd())
                .unwrap()
        );
        assert!(
            !bound
                .matches(std::process::id(), other.as_raw_fd())
                .unwrap()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn descriptor_binding_rejects_path_only_pipe_alias() {
        use std::os::unix::fs::OpenOptionsExt;

        let (read, _write) = crate::os::pipe().unwrap();
        let alias = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(format!("/proc/self/fd/{}", read.as_raw_fd()))
            .unwrap();
        let bound = Descriptor::bind(read.as_raw_fd()).unwrap();
        assert!(matches!(
            Descriptor::bind(alias.as_raw_fd()),
            Err(Fault::Identity)
        ));
        assert!(
            !bound
                .matches(std::process::id(), alias.as_raw_fd())
                .unwrap()
        );
    }

    #[test]
    fn process_birth_binding_does_not_depend_on_comm_contents() {
        let raw = fs::read_to_string("/proc/self/stat").unwrap();
        let pid = std::process::id();
        let before = ticks(&raw, pid).unwrap();
        let start = raw.find('(').unwrap();
        let end = raw.rfind(')').unwrap();
        let altered = format!("{}(dummy ) marker)){}", &raw[..start], &raw[end + 1..]);
        assert_eq!(ticks(&altered, pid).unwrap(), before);
        assert!(ticks(&raw, pid + 1).is_err());
        assert!(ticks("1 (truncated)", 1).is_err());
    }

    #[test]
    fn omitted_kernel_privilege_fields_are_not_assumed_safe() {
        let process = Process::bind(std::process::id()).unwrap();
        let identity = process.identity().unwrap();
        let raw = fs::read_to_string("/proc/self/status").unwrap();
        assert!(status(&raw, identity.clone()).is_ok());
        let missing = raw
            .lines()
            .filter(|l| !l.starts_with("CapBnd:"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(status(&missing, identity).is_err());
    }
}
