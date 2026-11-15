//! Kernel observations are independent of a payload's ready message.
use super::{
    cgroup::Group,
    contract::{Identity, Role, State},
    os::Fault,
};
use std::{
    collections::BTreeSet,
    fs, io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
};

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
    pub(super) fn fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
    pub(super) fn bind(pid: u32) -> Result<Self, Fault> {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let birth = ticks(&fs::read_to_string(format!("/proc/{pid}/stat"))?, pid)?;
        let process = Self { pid, birth, fd };
        if !process.alive()? {
            return Err(Fault::Identity);
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
            Fault::Child(unsafe { info.si_status() })
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

    pub(super) fn observe(&self, group: &Group, role: Role) -> Result<State, Fault> {
        let identity = self.identity()?;
        let value = fs::read_to_string(format!("/proc/{}/status", self.pid))?;
        let mut state = status(&value, identity)?;
        let expected: BTreeSet<i32> = if role == Role::Guard {
            [0, 1, 2, 3, 4, 5, 8, 9, 10].into_iter().collect()
        } else {
            [0, 1, 2, 3, 4, 5, 8].into_iter().collect()
        };
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
    use super::*;

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
