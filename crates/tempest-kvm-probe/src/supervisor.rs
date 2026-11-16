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

fn supervise(child: fn() -> i32, budget: Duration) -> io::Result<Outcome> {
    let mut gate = [-1; 2];
    if unsafe { libc::pipe2(gate.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let read = unsafe { OwnedFd::from_raw_fd(gate[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(gate[1]) };
    let parent = unsafe { libc::getpid() };
    let until = Instant::now() + budget;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        drop(write);
        let mut byte = 0_u8;
        let armed = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == 0
            && unsafe { libc::getppid() } == parent;
        let admitted = armed
            && unsafe { libc::read(read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) } == 1
            && byte == b'G';
        drop(read);
        unsafe {
            libc::_exit(if admitted { child() } else { 125 });
        }
    }
    drop(read);
    // Unreaped direct child + blocked gate prevents PID reuse before PIDFD bind.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        drop(write); // EOF: child never enters KVM code.
        terminal(pid, Instant::now() + Duration::from_secs(2))?;
        return Err(io::Error::from_raw_os_error(libc::ENOSYS));
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    let sent = unsafe { libc::write(write.as_raw_fd(), c"G".as_ptr().cast(), 1) } == 1;
    drop(write);
    let result = if sent {
        terminal(pid, until)
    } else {
        Err(io::Error::from_raw_os_error(libc::EPIPE))
    };
    match result {
        Ok(status) => Ok(Outcome {
            deadline_exceeded: false,
            child_terminal_reaped: true,
            explicit_cleanup_complete: libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        }),
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
            if crate::runtime::child().is_ok_and(|report| report.passed()) {
                0
            } else {
                1
            }
        },
        Duration::from_secs(5),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normal_failure_and_deadline_are_distinct_without_kvm() {
        let normal = supervise(|| 0, Duration::from_secs(1)).unwrap();
        assert!(normal.explicit_cleanup_complete && normal.child_terminal_reaped);
        let failed = supervise(|| 1, Duration::from_secs(1)).unwrap();
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
