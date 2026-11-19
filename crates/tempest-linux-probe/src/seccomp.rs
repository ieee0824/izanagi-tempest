//! Fixed dummy syscall policy. This is not a Claude-compatible policy.
use super::{
    contract::Role,
    os::{Fault, syscall},
};

fn statement(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(value: u32, yes: u8, no: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt: yes,
        jf: no,
        k: value,
    }
}

pub(super) fn install(role: Role, bootstrap_exec: bool) -> Result<(), Fault> {
    install_filter(Some(role), bootstrap_exec)
}

pub(super) fn install_mcp_stdio() -> Result<(), Fault> {
    install_filter(None, true)
}

fn install_filter(role: Option<Role>, bootstrap_exec: bool) -> Result<(), Fault> {
    if !cfg!(target_arch = "x86_64") {
        return Err(Fault::Kernel(libc::ENOTSUP));
    }
    let load = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let ret = (libc::BPF_RET | libc::BPF_K) as u16;
    let deny = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    let mut program = vec![
        statement(load, 4),     // seccomp_data.arch
        jump(0xc000003e, 1, 0), // AUDIT_ARCH_X86_64, never an alternate ABI
        statement(ret, libc::SECCOMP_RET_KILL_PROCESS),
        statement(load, 0), // seccomp_data.nr
    ];
    for number in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_pread64,
        libc::SYS_openat,
        libc::SYS_readlink,
        libc::SYS_readlinkat,
        libc::SYS_access,
        libc::SYS_faccessat,
        libc::SYS_getdents64,
        libc::SYS_fcntl,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_arch_prctl,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_futex,
        libc::SYS_getrandom,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getresuid,
        libc::SYS_getresgid,
        libc::SYS_getgroups,
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_setsid,
        libc::SYS_uname,
        libc::SYS_prlimit64,
        libc::SYS_getrlimit,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ] {
        program.push(jump(number as u32, 0, 1));
        program.push(statement(ret, libc::SECCOMP_RET_ALLOW));
    }
    // Only the guard receives ancillary data. A/B cannot receive a late fd
    // behind its back. No role may create a new socket, connect, mount or trace.
    if role.is_some() {
        for number in [libc::SYS_fork, libc::SYS_vfork] {
            program.push(jump(number as u32, 0, 1));
            program.push(statement(ret, libc::SECCOMP_RET_ALLOW));
        }
    } else {
        for number in [
            libc::SYS_epoll_create1,
            libc::SYS_epoll_ctl,
            libc::SYS_epoll_wait,
            libc::SYS_epoll_pwait,
            libc::SYS_eventfd2,
            libc::SYS_sched_getaffinity,
            libc::SYS_sched_yield,
            libc::SYS_getcpu,
            libc::SYS_pipe2,
        ] {
            program.push(jump(number as u32, 0, 1));
            program.push(statement(ret, libc::SECCOMP_RET_ALLOW));
        }
        // Let glibc fall back to the inspectable clone flags.
        program.extend([
            jump(libc::SYS_clone3 as u32, 0, 1),
            statement(ret, libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
        ]);
    }
    if role == Some(Role::Guard) {
        program.push(jump(libc::SYS_recvmsg as u32, 0, 1));
        program.push(statement(ret, libc::SECCOMP_RET_ALLOW));
    }
    // A zero-signal positive control to the namespace's own PID 1. It grants
    // neither a signal to another process nor a nonzero self signal.
    program.extend([
        jump(libc::SYS_kill as u32, 0, 6),
        statement(load, 16),
        jump(1, 0, 3),
        statement(load, 24),
        jump(0, 0, 1),
        statement(ret, libc::SECCOMP_RET_ALLOW),
        statement(ret, deny),
        statement(load, 0),
    ]);
    if role.is_none() {
        const THREAD_FLAGS: u32 = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID) as u32;
        program.extend([
            jump(libc::SYS_clone as u32, 0, 6),
            statement(load, 20),
            jump(0, 0, 3),
            statement(load, 16),
            jump(THREAD_FLAGS, 0, 1),
            statement(ret, libc::SECCOMP_RET_ALLOW),
            statement(ret, deny),
        ]);
    }
    program.extend([
        jump(libc::SYS_clone as u32, 0, 4),
        statement(load, 16), // args[0]: clone flags
        statement(
            (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16,
            (libc::CLONE_NEWNS
                | libc::CLONE_NEWCGROUP
                | libc::CLONE_NEWUTS
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWUSER
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWNET
                | libc::CLONE_PTRACE
                | libc::CLONE_PARENT) as u32,
        ),
        jump(0, 0, 1),
        statement(ret, libc::SECCOMP_RET_ALLOW),
        statement(load, 0),
        jump(libc::SYS_prctl as u32, 0, 7),
        statement(load, 16),
        jump(libc::PR_GET_NO_NEW_PRIVS as u32, 4, 0),
        jump(libc::PR_GET_SECCOMP as u32, 3, 0),
        jump(libc::PR_SET_SECCOMP as u32, 2, 0),
        jump(libc::PR_GET_DUMPABLE as u32, 1, 0),
        statement(ret, deny),
        statement(ret, libc::SECCOMP_RET_ALLOW),
        statement(load, 0),
    ]);
    if bootstrap_exec {
        // The bootstrap filter checks dirfd 6, not the pathname bytes or a
        // one-shot counter. The trusted bootstrap supplies the empty pathname
        // and AT_EMPTY_PATH for the sealed fd. Absolute paths cannot be excluded
        // by this fd check alone. Before Ready, the worker stacks a second
        // filter denying every exec, and the supervisor verifies image identity.
        program.extend([
            jump(libc::SYS_execveat as u32, 0, 4),
            statement(load, 16),
            jump(6, 0, 1),
            statement(ret, libc::SECCOMP_RET_ALLOW),
            statement(ret, deny),
            statement(load, 0),
        ]);
    }
    program.push(statement(ret, deny));
    let descriptor = libc::sock_fprog {
        len: program.len().try_into().map_err(|_| Fault::Identity)?,
        filter: program.as_mut_ptr(),
    };
    match unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } {
        0 => syscall(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })?,
        1 => (),
        _ => return Err(Fault::Identity),
    }
    // SAFETY: filter storage is live, immutable to the kernel during the call,
    // and copied by the kernel before this function returns.
    syscall(unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &descriptor) })
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;

    #[test]
    fn mcp_stdio_allows_runtime_threads_and_denies_network() {
        const CHILD: &str = "TEMPEST_MCP_SECCOMP_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "seccomp::tests::mcp_stdio_allows_runtime_threads_and_denies_network",
                    "--test-threads=1",
                ])
                .env_clear()
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success(), "{status}");
            return;
        }
        install_mcp_stdio().unwrap();
        let denied = |result| {
            assert_eq!(result, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
        };
        let thread = std::thread::spawn(move || {
            denied(unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) });
            denied(unsafe { libc::connect(-1, std::ptr::null(), 0) });
        });
        thread.join().unwrap();
        denied(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) });
    }
}
