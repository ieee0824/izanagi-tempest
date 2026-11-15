//! Kernel-lifetime run serialization; no filesystem artifact or network peer.
use super::os::Fault;
use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};

pub(super) struct Guard(OwnedFd);
impl Guard {
    pub(super) fn acquire() -> Result<Self, Fault> {
        Self::bind(b"tempest-linux-isolation-probe-lock")
    }
    fn bind(name: &[u8]) -> Result<Self, Fault> {
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let socket = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        if name.len() + 1 > address.sun_path.len() {
            return Err(Fault::Identity);
        }
        for (target, byte) in address.sun_path[1..].iter_mut().zip(name) {
            *target = *byte as libc::c_char;
        }
        let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + name.len();
        if unsafe {
            libc::bind(
                fd,
                (&address as *const libc::sockaddr_un).cast(),
                length as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(socket)
    }
    pub(super) fn fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn serialization_survives_owner_fd_drop_until_all_copies_close() {
        let name = format!(
            "tempest-guard-test-{}",
            crate::private_io::random_hex().unwrap()
        );
        let guard = Guard::bind(name.as_bytes()).unwrap();
        let duplicate = guard.0.try_clone().unwrap();
        assert!(Guard::bind(name.as_bytes()).is_err());
        drop(guard);
        assert!(Guard::bind(name.as_bytes()).is_err());
        drop(duplicate);
        Guard::bind(name.as_bytes()).unwrap();
    }
}
