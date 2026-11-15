//! Root-thread lease only. Workload forks clear this state before bootstrap.
use super::os::Fault;
use std::{
    cell::Cell,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
enum State {
    Off,
    Active(i32, Instant),
    Forbidden,
}
thread_local! { static STATE: Cell<State> = const { Cell::new(State::Off) }; }

pub(super) fn clear() {
    STATE.with(|state| state.set(State::Off));
}
pub(super) fn forbid() {
    STATE.with(|state| state.set(State::Forbidden));
}
pub(super) fn activate(fd: i32) {
    STATE.with(|state| state.set(State::Active(fd, Instant::now() - Duration::from_secs(1))));
}
pub(super) fn pulse() -> Result<(), Fault> {
    STATE.with(|state| match state.get() {
        State::Off => Ok(()),
        State::Forbidden => Err(Fault::LeaseUnavailable),
        State::Active(fd, last) => {
            if last.elapsed() < Duration::from_millis(250) {
                return Ok(());
            }
            if unsafe { libc::write(fd, b"H".as_ptr().cast(), 1) } != 1 {
                return Err(Fault::LeaseUnavailable);
            }
            state.set(State::Active(fd, Instant::now()));
            Ok(())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    #[test]
    fn handoff_forbids_later_operations_and_heartbeats_are_rate_limited() {
        let (read, write) = crate::os::pipe().unwrap();
        activate(write.as_raw_fd());
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
}
