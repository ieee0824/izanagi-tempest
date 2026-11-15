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
    pub(super) fn start() -> Result<Self, Fault> {
        let owner = Process::bind(std::process::id())?;
        let root = fs::metadata(RUN)?;
        let identity = (root.dev(), root.ino());
        let (read, write) = os::pipe()?;
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if pid == 0 {
            let result = (|| {
                os::syscall(unsafe { libc::setsid() })?;
                os::close_except(&[read.as_raw_fd(), owner.fd()])?;
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
                    if poll.revents & libc::POLLHUP != 0
                        || !owner.alive()?
                        || Instant::now() >= until
                    {
                        break;
                    }
                }
                let current = fs::metadata(RUN)?;
                if (current.dev(), current.ino()) != identity {
                    return Err(Fault::Identity);
                }
                Group::recover_owned()?;
                fs::remove_dir_all(RUN)?;
                Ok(())
            })();
            unsafe {
                libc::_exit(if result.is_ok() { 0 } else { 1 });
            }
        }
        drop(read);
        Ok(Self {
            pid,
            control: write,
            active: true,
        })
    }

    fn wait(&mut self) -> Result<(), Fault> {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if result == self.pid {
                self.active = false;
                return if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                    Ok(())
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
        if unsafe { libc::write(self.control.as_raw_fd(), b"D".as_ptr().cast(), 1) } != 1 {
            return Err(Fault::Identity);
        }
        self.wait()
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
