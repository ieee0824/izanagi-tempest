//! Socket-domain boundary for the actual fixed manual-login child.
//! Keep TCP/Unix sockets available; only the trusted gateway may use vsock.
use std::io;

fn statement(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
fn equal(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    }
}

pub(super) fn install() -> io::Result<()> {
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
    }
    let load = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let ret = (libc::BPF_RET | libc::BPF_K) as u16;
    let deny = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    // Fixed stack storage: installation runs in Command::pre_exec.
    let mut filters = [
        statement(load, 4),
        equal(0xc000003e, 1, 0), // native x86_64 only, reject compat socketcall
        statement(ret, libc::SECCOMP_RET_KILL_PROCESS),
        statement(load, 0),
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: 0x40000000,
        }, // x32 syscall bit
        statement(ret, deny),
        equal(libc::SYS_io_uring_setup as u32, 0, 1),
        statement(ret, deny),
        equal(libc::SYS_io_uring_enter as u32, 0, 1),
        statement(ret, deny),
        equal(libc::SYS_io_uring_register as u32, 0, 1),
        statement(ret, deny),
        equal(libc::SYS_socket as u32, 1, 0),
        equal(libc::SYS_socketpair as u32, 0, 3),
        statement(load, 16), // low 32 bits of socket domain (kernel int)
        equal(libc::AF_VSOCK as u32, 0, 1),
        statement(ret, deny),
        statement(ret, libc::SECCOMP_RET_ALLOW),
    ];
    let program = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_mut_ptr(),
    };
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn child_denies_vsock_and_async_socket_bypass_but_keeps_tcp() {
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let valid = (|| -> std::io::Result<bool> {
                super::install()?;
                for call in [
                    libc::SYS_io_uring_setup,
                    libc::SYS_io_uring_enter,
                    libc::SYS_io_uring_register,
                ] {
                    if unsafe { libc::syscall(call, 0, 0, 0, 0, 0, 0) } != -1
                        || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
                    {
                        return Ok(false);
                    }
                }
                let denied = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
                if denied != -1
                    || std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
                {
                    return Ok(false);
                }
                let tcp = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
                let _client = std::net::TcpStream::connect(tcp.local_addr()?)?;
                let _accepted = tcp.accept()?;
                Ok(true)
            })()
            .unwrap_or(false);
            unsafe {
                libc::_exit(i32::from(!valid));
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert_eq!(status, 0);
    }
}
