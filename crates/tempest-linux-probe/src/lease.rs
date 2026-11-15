//! Root-thread lease only. Workload forks clear this state before bootstrap.
use super::os::Fault;
use std::{
    cell::Cell,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
enum State {
    Off,
    Active {
        control: i32,
        guardian: i32,
        last: Instant,
    },
    Forbidden,
}
thread_local! { static STATE: Cell<State> = const { Cell::new(State::Off) }; }

pub(super) fn clear() {
    STATE.with(|state| state.set(State::Off));
}
pub(super) fn forbid() {
    STATE.with(|state| state.set(State::Forbidden));
}
pub(super) fn activate(control: i32, guardian: i32) {
    STATE.with(|state| {
        state.set(State::Active {
            control,
            guardian,
            last: Instant::now() - Duration::from_secs(1),
        })
    });
}
pub(super) fn guardian_fd() -> i32 {
    STATE.with(|state| match state.get() {
        State::Active { guardian, .. } => guardian,
        _ => -1,
    })
}
pub(super) fn pulse() -> Result<(), Fault> {
    STATE.with(|state| match state.get() {
        State::Off => Ok(()),
        State::Forbidden => Err(Fault::LeaseUnavailable),
        State::Active {
            control,
            guardian,
            last,
        } => {
            // Check death even between heartbeat writes. Pipe HUP/EPIPE alone
            // never grants recovery authority; terminal reap is still required.
            let mut poll = libc::pollfd {
                fd: guardian,
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, 0) } < 0
                || poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0
            {
                state.set(State::Forbidden);
                return Err(Fault::LeaseUnavailable);
            }
            if poll.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                state.set(State::Forbidden);
                return Err(Fault::GuardianDied);
            }
            if last.elapsed() < Duration::from_millis(250) {
                return Ok(());
            }
            if unsafe { libc::write(control, b"H".as_ptr().cast(), 1) } != 1 {
                state.set(State::Forbidden);
                return Err(Fault::LeaseUnavailable);
            }
            state.set(State::Active {
                control,
                guardian,
                last: Instant::now(),
            });
            Ok(())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::fd::{FromRawFd, OwnedFd};
    #[test]
    fn handoff_forbids_later_operations_and_heartbeats_are_rate_limited() {
        let (read, write) = crate::os::pipe().unwrap();
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
        assert!(raw >= 0);
        let guardian = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        activate(write.as_raw_fd(), guardian.as_raw_fd());
        pulse().unwrap();
        pulse().unwrap();
        let mut bytes = [0_u8; 4];
        assert_eq!(
            unsafe { libc::read(read.as_raw_fd(), bytes.as_mut_ptr().cast(), 4) },
            1
        );
        assert_eq!(bytes[0], b'H');
        forbid();
        assert_eq!(pulse(), Err(Fault::LeaseUnavailable));
        clear();
    }

    #[test]
    fn guardian_death_forbids_operations_even_with_live_control_pipe() {
        let (_read, write) = crate::os::pipe().unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::_exit(0);
            }
        }
        // Our own child remains unreaped, so the PID cannot be reused.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(raw >= 0);
        let guardian = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let mut poll = libc::pollfd {
            fd: guardian.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 2000) }, 1);
        activate(write.as_raw_fd(), guardian.as_raw_fd());
        assert_eq!(pulse(), Err(Fault::GuardianDied));
        assert_eq!(pulse(), Err(Fault::LeaseUnavailable));
        assert_eq!(guardian_fd(), -1);
        assert_eq!(unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) }, pid);
        clear();
    }
}
