//! Bounded discard-only capture. Payload bytes never enter the public audit.
use super::{
    contract::Role,
    os::{self, Fault},
};
use std::{
    cell::Cell,
    io,
    os::fd::{AsRawFd, OwnedFd},
};

pub(super) const LIMIT: u64 = 65536;
pub(super) const CHUNK: usize = 4096;

pub(super) struct Capture {
    role: Role,
    streams: [OwnedFd; 2],
    counts: Cell<[u64; 2]>,
    closed: Cell<[bool; 2]>,
}

impl Capture {
    pub(super) fn new(role: Role, stdout: OwnedFd, stderr: OwnedFd) -> Result<Self, Fault> {
        for fd in [&stdout, &stderr] {
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error().into());
            }
            os::syscall(unsafe {
                libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
            })?;
        }
        Ok(Self {
            role,
            streams: [stdout, stderr],
            counts: Cell::new([0; 2]),
            closed: Cell::new([false; 2]),
        })
    }

    pub(super) fn fd(&self, index: usize) -> i32 {
        self.streams[index].as_raw_fd()
    }
    pub(super) fn poll_fd(&self, index: usize) -> i32 {
        if self.closed.get()[index] {
            -1
        } else {
            self.fd(index)
        }
    }
    pub(super) fn counts(&self) -> [u64; 2] {
        self.counts.get()
    }

    pub(super) fn drain(&self, index: usize) -> Result<(), Fault> {
        let mut buffer = [0_u8; CHUNK];
        let count = unsafe { libc::read(self.fd(index), buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::EAGAIN) {
                Ok(())
            } else {
                Err(error.into())
            };
        }
        if count == 0 {
            let mut closed = self.closed.get();
            closed[index] = true;
            self.closed.set(closed);
            return Ok(());
        }
        let mut counts = self.counts.get();
        counts[index] = counts[index].saturating_add(count as u64);
        self.counts.set(counts);
        if counts[0].saturating_add(counts[1]) > LIMIT {
            return Err(Fault::OutputLimit(self.role, (index + 1) as u8));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_is_combined_across_streams_and_rejects_the_first_excess_byte() {
        let (a, aw) = os::pipe().unwrap();
        let (b, bw) = os::pipe().unwrap();
        let capture = Capture::new(Role::A, a, b).unwrap();
        let writers = [aw, bw];
        for index in 0..32 {
            let stream = index % 2;
            let bytes = [42_u8; 2048];
            assert_eq!(
                unsafe {
                    libc::write(
                        writers[stream].as_raw_fd(),
                        bytes.as_ptr().cast(),
                        bytes.len(),
                    )
                },
                2048
            );
            capture.drain(stream).unwrap();
        }
        assert_eq!(capture.counts(), [32768, 32768]);
        assert_eq!(
            unsafe { libc::write(writers[0].as_raw_fd(), b"X".as_ptr().cast(), 1) },
            1
        );
        assert_eq!(capture.drain(0), Err(Fault::OutputLimit(Role::A, 1)));
        assert_eq!(capture.counts(), [32769, 32768]);
    }

    #[test]
    fn eof_disables_polling_and_empty_nonblocking_reads_do_not_change_counts() {
        let (a, aw) = os::pipe().unwrap();
        let (b, _bw) = os::pipe().unwrap();
        let capture = Capture::new(Role::B, a, b).unwrap();
        drop(aw);
        capture.drain(0).unwrap();
        assert_eq!(capture.poll_fd(0), -1);
        capture.drain(1).unwrap();
        assert!(capture.poll_fd(1) >= 0);
        assert_eq!(capture.counts(), [0, 0]);
    }
}
