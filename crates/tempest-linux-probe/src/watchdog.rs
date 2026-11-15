//! Fixed root recovery role, outside the payload cgroup and process group.
//! It accepts only a completion byte, never a command or path.
use super::{
    cgroup::Group,
    identity::Process,
    os::{self, Fault},
};
use std::{
    fs, io,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::{Duration, Instant},
};

const RUN: &str = "/run/tempest-linux-isolation-probe";

pub(super) struct Watchdog {
    pid: i32,
    control: OwnedFd,
    active: bool,
}

impl Watchdog {
    pub(super) fn start() -> Result<(Self, Group), Fault> {
        let owner = Process::bind(std::process::id())?;
        let root = fs::metadata(RUN)?;
        let identity = (root.dev(), root.ino());
        let (read, write) = os::pipe()?;
        let (ack_read, ack_write) = os::pipe()?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if pid == 0 {
            let mut expired = false;
            let result = (|| {
                os::syscall(unsafe { libc::setsid() })?;
                os::close_except(&[read.as_raw_fd(), owner.fd(), ack_write.as_raw_fd()])?;
                // Only this process creates the group. A preexisting ROOT fails
                // before ownership is acquired and is never recovered.
                let mut group = Group::create()?;
                let (dev, ino) = group.identity();
                let mut ack = [0_u8; 16];
                ack[..8].copy_from_slice(&dev.to_ne_bytes());
                ack[8..].copy_from_slice(&ino.to_ne_bytes());
                if unsafe { libc::write(ack_write.as_raw_fd(), ack.as_ptr().cast(), ack.len()) }
                    != 16
                {
                    return Err(Fault::Identity);
                }
                // Keep ack_write's OwnedFd alive: close_except already closed
                // ack_read/write copies, which must never be reused here.

                let until = Instant::now() + Duration::from_secs(90);
                loop {
                    let mut poll = libc::pollfd {
                        fd: read.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    if unsafe { libc::poll(&mut poll, 1, 50) } < 0 {
                        break;
                    }
                    if poll.revents & libc::POLLIN != 0 {
                        let mut value = 0_u8;
                        if unsafe { libc::read(poll.fd, (&mut value as *mut u8).cast(), 1) } == 1
                            && value == b'D'
                        {
                            if Path::new(super::cgroup::ROOT).exists() {
                                return Err(Fault::Identity);
                            }
                            let current = fs::metadata(RUN)?;
                            if (current.dev(), current.ino()) != identity {
                                return Err(Fault::Identity);
                            }
                            return Ok(());
                        }
                        break;
                    }
                    if Instant::now() >= until {
                        expired = true;
                        break;
                    }
                    if poll.revents & libc::POLLHUP != 0 || !owner.alive()? {
                        break;
                    }
                }
                let current = fs::metadata(RUN)?;
                if (current.dev(), current.ino()) != identity {
                    return Err(Fault::Identity);
                }
                group.recover()?;
                fs::remove_dir_all(RUN)?;
                Ok(())
            })();
            unsafe {
                libc::_exit(if result.is_ok() {
                    if expired { 124 } else { 0 }
                } else {
                    1
                });
            }
        }
        drop(read);
        drop(ack_write);
        let mut watchdog = Self {
            pid,
            control: write,
            active: true,
        };
        let mut poll = libc::pollfd {
            fd: ack_read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 5000) } <= 0 {
            return Err(Fault::Identity);
        }
        let mut ack = [0_u8; 16];
        if unsafe { libc::read(ack_read.as_raw_fd(), ack.as_mut_ptr().cast(), ack.len()) } != 16 {
            let _ = watchdog.wait();
            return Err(Fault::Identity);
        }
        let identity = (
            u64::from_ne_bytes(ack[..8].try_into().map_err(|_| Fault::Identity)?),
            u64::from_ne_bytes(ack[8..].try_into().map_err(|_| Fault::Identity)?),
        );
        let group = Group::adopt(identity)?;
        Ok((watchdog, group))
    }

    fn wait(&mut self) -> Result<(), Fault> {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if result == self.pid {
                self.active = false;
                return if libc::WIFEXITED(status) {
                    if libc::WEXITSTATUS(status) == 0 {
                        Ok(())
                    } else {
                        Err(Fault::Child(libc::WEXITSTATUS(status)))
                    }
                } else if libc::WIFSIGNALED(status) {
                    Err(Fault::ChildSignal(
                        libc::WTERMSIG(status),
                        libc::WCOREDUMP(status),
                    ))
                } else {
                    Err(Fault::Identity)
                };
            }
            if result < 0 {
                return Err(io::Error::last_os_error().into());
            }
            if Instant::now() >= until {
                return Err(Fault::Kernel(libc::EBUSY));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub(super) fn finish(&mut self) -> Result<(), Fault> {
        let wrote = unsafe { libc::write(self.control.as_raw_fd(), b"D".as_ptr().cast(), 1) } == 1;
        // Reap even on EPIPE so an already completed recovery/deadline is
        // distinguishable from an unexplained missing control reader.
        let finished = self.wait();
        if wrote {
            finished
        } else {
            finished.and(Err(Fault::Identity))
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                libc::write(self.control.as_raw_fd(), b"A".as_ptr().cast(), 1);
            }
            let _ = self.wait();
        }
    }
}
