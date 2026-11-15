//! Consume ancillary descriptors before any IPC bytes cross to a payload.
#[cfg(test)]
use std::os::fd::AsRawFd;
use std::{
    io,
    mem::{size_of, zeroed},
    os::fd::{FromRawFd, OwnedFd, RawFd},
};

const MAX_FRAME: usize = 4096;
// Aligned storage exceeds Linux's limit of 253 SCM_RIGHTS descriptors.
const CONTROL_WORDS: usize = 256;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Rejection {
    Io(i32),
    EndOfStream,
    Ancillary,
    Truncated,
    Framing,
}

pub(super) fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: two writable slots; successful descriptors each acquire one owner.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

pub(super) fn receive(fd: RawFd) -> Result<Vec<u8>, Rejection> {
    receive_with_control(fd, CONTROL_WORDS)
}

fn receive_with_control(fd: RawFd, words: usize) -> Result<Vec<u8>, Rejection> {
    let mut data = [0_u8; MAX_FRAME + 4];
    let mut control = [0_u64; CONTROL_WORDS];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    // SAFETY: pointers refer to aligned live writable buffers throughout recvmsg
    // and cmsg parsing. The kernel supplies validated cmsghdr boundaries.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = words.min(CONTROL_WORDS) * size_of::<u64>();
    let count = unsafe { libc::recvmsg(fd, &mut message, libc::MSG_CMSG_CLOEXEC) };
    if count < 0 {
        return Err(Rejection::Io(
            io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ));
    }
    let mut received = Vec::new();
    let mut has_control = false;
    // Own ALL delivered descriptors before checking flags/framing. Every exit
    // then closes them, including the MSG_CTRUNC and malformed-frame paths.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            has_control = true;
            let base = libc::CMSG_LEN(0) as usize;
            if (*header).cmsg_level == libc::SOL_SOCKET
                && (*header).cmsg_type == libc::SCM_RIGHTS
                && (*header).cmsg_len >= base
            {
                let bytes = (*header).cmsg_len - base;
                for index in 0..bytes / size_of::<RawFd>() {
                    let fd = libc::CMSG_DATA(header).cast::<RawFd>().add(index).read();
                    if fd >= 0 {
                        received.push(OwnedFd::from_raw_fd(fd));
                    }
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    drop(received);
    if message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
        return Err(Rejection::Truncated);
    }
    if has_control {
        return Err(Rejection::Ancillary);
    }
    if count == 0 {
        return Err(Rejection::EndOfStream);
    }
    let count = count as usize;
    if count < 4 {
        return Err(Rejection::Framing);
    }
    let length = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
    if length > MAX_FRAME || length != count - 4 {
        return Err(Rejection::Framing);
    }
    Ok(data[4..count].to_vec())
}

#[cfg(test)]
fn send(fd: RawFd, data: &[u8], rights: &[RawFd]) {
    let mut control = [0_u64; CONTROL_WORDS];
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    // SAFETY: the message references live buffers and caller-owned descriptors.
    unsafe {
        let mut message: libc::msghdr = zeroed();
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        if !rights.is_empty() {
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen = libc::CMSG_SPACE(size_of_val(rights) as u32) as usize;
            assert!(message.msg_controllen <= size_of_val(&control));
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of_val(rights) as u32) as usize;
            std::ptr::copy_nonoverlapping(
                rights.as_ptr(),
                libc::CMSG_DATA(header).cast::<RawFd>(),
                rights.len(),
            );
        }
        assert_eq!(
            libc::sendmsg(fd, &message, libc::MSG_NOSIGNAL),
            data.len() as isize
        );
    }
}

pub(super) fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut value = (bytes.len() as u32).to_be_bytes().to_vec();
    value.extend_from_slice(bytes);
    value
}

// Count references to one unique canary inode. A global fd count would race
// with unrelated Cargo tests executing on other threads.
#[cfg(test)]
fn references(fd: RawFd) -> usize {
    let mut expected: libc::stat = unsafe { zeroed() };
    assert_eq!(unsafe { libc::fstat(fd, &mut expected) }, 0);
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            let Ok(number) = entry.file_name().to_string_lossy().parse::<RawFd>() else {
                return false;
            };
            let mut actual: libc::stat = unsafe { zeroed() };
            (unsafe { libc::fstat(number, &mut actual) == 0 })
                && actual.st_dev == expected.st_dev
                && actual.st_ino == expected.st_ino
        })
        .count()
}

#[test]
fn accepted_frame_and_eof_are_distinct() {
    let (sender, receiver) = pair().unwrap();
    send(sender.as_raw_fd(), &frame(b"ping"), &[]);
    assert_eq!(receive(receiver.as_raw_fd()).unwrap(), b"ping");
    drop(sender);
    assert_eq!(receive(receiver.as_raw_fd()), Err(Rejection::EndOfStream));
}

#[test]
fn live_descriptor_injection_is_closed_without_forwarding() {
    let root = std::env::temp_dir().join(format!(
        "tempest-ancillary-{}",
        crate::private_io::random_hex().unwrap()
    ));
    crate::private_io::directory(&root).unwrap();
    crate::private_io::write_new(&root.join("canary"), b"dummy").unwrap();
    let (sender, receiver) = pair().unwrap();
    let (socket, _) = pair().unwrap();
    let directory = std::fs::File::open(&root).unwrap();
    let file = std::fs::File::open(root.join("canary")).unwrap();
    for target in [socket.as_raw_fd(), directory.as_raw_fd(), file.as_raw_fd()] {
        let before = references(target);
        send(sender.as_raw_fd(), &frame(b"canary"), &[target, target]);
        assert_eq!(receive(receiver.as_raw_fd()), Err(Rejection::Ancillary));
        assert_eq!(references(target), before);
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn truncated_control_closes_every_delivered_descriptor() {
    let (sender, receiver) = pair().unwrap();
    let (canary, _) = pair().unwrap();
    let before = references(canary.as_raw_fd());
    send(
        sender.as_raw_fd(),
        &frame(b"reject"),
        &[canary.as_raw_fd(); 32],
    );
    assert_eq!(
        receive_with_control(receiver.as_raw_fd(), 4),
        Err(Rejection::Truncated)
    );
    assert_eq!(references(canary.as_raw_fd()), before);
}

#[test]
fn oversized_and_malformed_frames_cannot_cross_the_boundary() {
    let (sender, receiver) = pair().unwrap();
    send(sender.as_raw_fd(), &[0; 3], &[]);
    assert_eq!(receive(receiver.as_raw_fd()), Err(Rejection::Framing));
    send(sender.as_raw_fd(), &[0, 0, 0, 2, 42], &[]);
    assert_eq!(receive(receiver.as_raw_fd()), Err(Rejection::Framing));
    send(sender.as_raw_fd(), &frame(&[0; MAX_FRAME + 1]), &[]);
    assert_eq!(receive(receiver.as_raw_fd()), Err(Rejection::Truncated));
}

#[test]
fn unexpected_credentials_ancillary_is_rejected() {
    let (sender, receiver) = pair().unwrap();
    let enabled: libc::c_int = 1;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                receiver.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&enabled as *const libc::c_int).cast(),
                size_of_val(&enabled) as libc::socklen_t,
            )
        },
        0
    );
    send(sender.as_raw_fd(), &frame(b"ping"), &[]);
    assert_eq!(receive(receiver.as_raw_fd()), Err(Rejection::Ancillary));
}
