use crate::runtime::ChildReport;
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

#[derive(Debug)]
pub struct Outcome {
    pub deadline_exceeded: bool,
    pub child_terminal_reaped: bool,
    pub explicit_cleanup_complete: bool,
    pub primary_errno: Option<i32>,
    pub cleanup_errno: Option<i32>,
}

fn terminal(pid: i32, until: Instant) -> io::Result<i32> {
    loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            return Ok(status);
        }
        if waited < 0 {
            return Err(io::Error::last_os_error());
        }
        if Instant::now() >= until {
            return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn supervise(child: fn() -> ChildReport, budget: Duration) -> io::Result<Outcome> {
    supervise_inner(child, budget, false)
}
fn supervise_inner(
    child: fn() -> ChildReport,
    budget: Duration,
    missing_gate_reader: bool,
) -> io::Result<Outcome> {
    // Fixed standalone probe policy; EPIPE must become a diagnostic, not death.
    if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) } == libc::SIG_ERR {
        return Err(io::Error::last_os_error());
    }
    let mut gate = [-1; 2];
    if unsafe { libc::pipe2(gate.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let read = unsafe { OwnedFd::from_raw_fd(gate[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(gate[1]) };
    let mut reports = [-1; 2];
    if unsafe { libc::pipe2(reports.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let report_read = unsafe { OwnedFd::from_raw_fd(reports[0]) };
    let report_write = unsafe { OwnedFd::from_raw_fd(reports[1]) };
    let parent = unsafe { libc::getpid() };
    let until = Instant::now() + budget;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        drop(write);
        drop(report_read);
        // Private fault fixture: acknowledge reader closure, then wait for
        // parent PIDFD recovery. Production always passes false.
        if missing_gate_reader {
            drop(read);
            unsafe {
                libc::write(report_write.as_raw_fd(), c"E".as_ptr().cast(), 1);
                loop {
                    libc::pause();
                }
            }
        }
        let mut byte = 0_u8;
        let armed = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == 0
            && unsafe { libc::getppid() } == parent;
        let admitted = armed
            && unsafe { libc::read(read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) } == 1
            && byte == b'G';
        drop(read);
        if !admitted {
            unsafe {
                libc::_exit(125);
            }
        }
        let result = child();
        let mut record = [0_u8; 12];
        record[..4].copy_from_slice(b"KVM1");
        record[4..8].copy_from_slice(&result.primary_errno.unwrap_or(0).to_le_bytes());
        record[8..12].copy_from_slice(&result.cleanup_errno.unwrap_or(0).to_le_bytes());
        let sent =
            unsafe { libc::write(report_write.as_raw_fd(), record.as_ptr().cast(), 12) } == 12;
        unsafe {
            libc::_exit(if sent && result.passed() { 0 } else { 1 });
        }
    }
    drop(report_write);
    drop(read);
    // Unreaped direct child + blocked gate prevents PID reuse before PIDFD bind.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        drop(write); // EOF: child never enters KVM code.
        terminal(pid, Instant::now() + Duration::from_secs(2))?;
        return Err(io::Error::from_raw_os_error(libc::ENOSYS));
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    if missing_gate_reader {
        let mut poll = libc::pollfd {
            fd: report_read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let mut byte = 0_u8;
        if unsafe { libc::poll(&mut poll, 1, 1000) } != 1
            || unsafe { libc::read(report_read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) } != 1
            || byte != b'E'
        {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    0,
                    0,
                );
            }
            terminal(pid, Instant::now() + Duration::from_secs(2))?;
            return Err(io::Error::from_raw_os_error(libc::EPROTO));
        }
    }
    let sent = unsafe { libc::write(write.as_raw_fd(), c"G".as_ptr().cast(), 1) } == 1;
    drop(write);
    let result = if sent {
        terminal(pid, until)
    } else {
        Err(io::Error::from_raw_os_error(libc::EPIPE))
    };
    match result {
        Ok(status) => {
            let mut record = [0_u8; 13];
            let count = unsafe {
                libc::read(
                    report_read.as_raw_fd(),
                    record.as_mut_ptr().cast(),
                    record.len(),
                )
            };
            if count != 12 || &record[..4] != b"KVM1" {
                return Err(io::Error::from_raw_os_error(libc::EPROTO));
            }
            let primary = i32::from_le_bytes(record[4..8].try_into().unwrap());
            let cleanup = i32::from_le_bytes(record[8..12].try_into().unwrap());
            if primary < 0 || cleanup < 0 {
                return Err(io::Error::from_raw_os_error(libc::EPROTO));
            }
            Ok(Outcome {
                deadline_exceeded: false,
                child_terminal_reaped: true,
                explicit_cleanup_complete: primary == 0
                    && cleanup == 0
                    && libc::WIFEXITED(status)
                    && libc::WEXITSTATUS(status) == 0,
                primary_errno: (primary != 0).then_some(primary),
                cleanup_errno: (cleanup != 0).then_some(cleanup),
            })
        }
        Err(error) if error.raw_os_error() != Some(libc::ECHILD) => {
            let killed = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if killed < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                return Err(io::Error::last_os_error());
            }
            terminal(pid, Instant::now() + Duration::from_secs(2))?;
            Ok(Outcome {
                deadline_exceeded: error.raw_os_error() == Some(libc::ETIMEDOUT),
                child_terminal_reaped: true,
                explicit_cleanup_complete: false,
                primary_errno: Some(error.raw_os_error().unwrap_or(libc::EIO)),
                cleanup_errno: None,
            })
        }
        Err(error) => Err(error),
    }
}

pub fn run() -> io::Result<Outcome> {
    if !crate::identity::current().is_some_and(|user| user.valid()) {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    supervise(
        || {
            crate::runtime::child().unwrap_or_else(|error| ChildReport {
                primary_errno: Some(error.raw_os_error().unwrap_or(libc::EIO)),
                cleanup_errno: Some(libc::ENODATA),
            })
        },
        Duration::from_secs(5),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_gate_reader_becomes_epipe_and_owned_child_is_reaped() {
        let result = supervise_inner(
            || panic!("payload must not start"),
            Duration::from_secs(2),
            true,
        )
        .unwrap();
        assert_eq!(result.primary_errno, Some(libc::EPIPE));
        assert!(result.child_terminal_reaped);
        assert!(!result.explicit_cleanup_complete);
        assert!(!result.deadline_exceeded);
    }
    #[test]
    fn normal_failure_and_deadline_are_distinct_without_kvm() {
        let normal = supervise(
            || ChildReport {
                primary_errno: None,
                cleanup_errno: None,
            },
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(normal.explicit_cleanup_complete && normal.child_terminal_reaped);
        let failed = supervise(
            || ChildReport {
                primary_errno: Some(libc::EPERM),
                cleanup_errno: Some(libc::EIO),
            },
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(failed.primary_errno, Some(libc::EPERM));
        assert_eq!(failed.cleanup_errno, Some(libc::EIO));
        assert!(!failed.explicit_cleanup_complete && !failed.deadline_exceeded);
        let timeout = supervise(
            || {
                loop {
                    unsafe {
                        libc::pause();
                    }
                }
            },
            Duration::from_millis(10),
        )
        .unwrap();
        assert!(timeout.deadline_exceeded && timeout.child_terminal_reaped);
        assert!(!timeout.explicit_cleanup_complete);
    }
}
