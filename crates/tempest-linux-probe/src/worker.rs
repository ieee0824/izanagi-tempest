//! Fixed non-root dummy roles. No model, guest, config or external destination.
use super::{
    ancillary,
    contract::{Check, Observation, Role},
    seccomp,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    os::fd::{FromRawFd, RawFd},
    os::unix::fs::OpenOptionsExt,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    pub(super) role: Role,
    pub(super) nonce: [u8; 16],
    pub(super) supervisor: u32,
    pub(super) peers: [u32; 3],
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    BootstrapFault,
    Ready,
    Done,
    GuardRejected,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Event {
    #[serde(default)]
    pub(super) bootstrap: Option<(u8, i32)>,
    pub(super) role: Role,
    pub(super) nonce: [u8; 16],
    pub(super) phase: Phase,
    pub(super) checks: Vec<Observation>,
    // An internal address of a dummy marker for the supervisor's memory-read
    // positive control. Never serialize this internal Event into public audit.
    pub(super) canary_address: u64,
}

static MEMORY: &[u8] = b"synthetic-memory-only";

fn bytes(fd: RawFd, value: &[u8]) -> bool {
    let mut offset = 0;
    while offset < value.len() {
        let count =
            unsafe { libc::write(fd, value[offset..].as_ptr().cast(), value.len() - offset) };
        if count <= 0 {
            return false;
        }
        offset += count as usize;
    }
    true
}

fn event(manifest: &Manifest, phase: Phase, checks: Vec<Observation>) -> bool {
    let value = Event {
        bootstrap: None,
        role: manifest.role,
        nonce: manifest.nonce,
        phase,
        checks,
        canary_address: MEMORY.as_ptr() as u64,
    };
    let Ok(mut raw) = serde_json::to_vec(&value) else {
        return false;
    };
    raw.push(b'\n');
    bytes(5, &raw)
}

fn wait() -> bool {
    let mut value = 0_u8;
    unsafe { libc::read(4, (&mut value as *mut u8).cast(), 1) == 1 && value == b'G' }
}

fn observe(check: Check, role: Role, passed: bool, denials: u64) -> Observation {
    Observation {
        check,
        role: Some(role),
        passed,
        attempts: 1,
        denials,
    }
}

fn denied(value: libc::c_long) -> bool {
    value == -1
        && matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM | libc::EACCES)
        )
}

fn checks(manifest: &Manifest) -> Vec<Observation> {
    let role = manifest.role;
    let mut values = Vec::new();
    let own = if role == Role::A {
        fs::read("/private/credential.canary").is_ok_and(|b| b == b"synthetic-canary-only")
    } else {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open("/work/own")
            .and_then(|mut f| f.write_all(b"dummy"))
            .is_ok()
    };
    values.push(observe(Check::PositiveCanary, role, own, 0));
    values.push(observe(
        Check::PeerCanaryDenied,
        role,
        role == Role::A || fs::read("/private/credential.canary").is_err(),
        u64::from(role != Role::A),
    ));
    for (check, paths) in [
        (
            Check::HostPathsDenied,
            vec![
                "/home/ubuntu",
                "/run/tempest-linux-isolation-probe",
                "/sys/fs/cgroup",
            ],
        ),
        (
            Check::ShellAbsent,
            vec!["/bin/sh", "/bin/bash", "/usr/bin/sudo", "/usr/bin/env"],
        ),
        (Check::KvmAbsent, vec!["/dev/kvm"]),
    ] {
        let passed = paths.iter().all(|p| fs::symlink_metadata(p).is_err());
        values.push(Observation {
            check,
            role: Some(role),
            passed,
            attempts: paths.len() as u64,
            denials: paths.len() as u64,
        });
    }
    let peer_proc = std::iter::once(manifest.supervisor)
        .chain(manifest.peers)
        .all(|pid| {
            ["root", "cwd", "fd", "environ", "maps", "mem", "ns"]
                .iter()
                .all(|name| fs::metadata(format!("/proc/{pid}/{name}")).is_err())
        });
    values.push(observe(Check::PeerProcDenied, role, peer_proc, 1));
    values.push(observe(
        Check::InheritedFdClosed,
        role,
        unsafe { libc::fcntl(40, libc::F_GETFD) } == -1,
        1,
    ));
    values.push(observe(
        Check::EnvironmentCleared,
        role,
        std::env::vars_os().all(|(key, _)| key == "LANG" || key == "LC_ALL"),
        0,
    ));
    values.push(observe(
        Check::PrivilegeDenied,
        role,
        denied(unsafe { libc::syscall(libc::SYS_setresuid, 0, 0, 0) }),
        1,
    ));
    values.push(observe(
        Check::NamespaceDenied,
        role,
        denied(unsafe {
            libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER | libc::CLONE_NEWNET)
        }),
        1,
    ));
    let target = manifest.supervisor as libc::pid_t;
    let self_signal = unsafe { libc::kill(1, 0) } == 0;
    values.push(observe(
        Check::SignalDenied,
        role,
        self_signal && denied(unsafe { libc::syscall(libc::SYS_kill, target, 0) }),
        1,
    ));
    values.push(observe(
        Check::PtraceDenied,
        role,
        denied(unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_ATTACH, target, 0, 0) }),
        1,
    ));
    let mut byte = 0_u8;
    let local = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let remote = libc::iovec {
        iov_base: MEMORY.as_ptr().cast_mut().cast(),
        iov_len: 1,
    };
    values.push(observe(
        Check::ProcessMemoryDenied,
        role,
        denied(unsafe {
            libc::syscall(libc::SYS_process_vm_readv, target, &local, 1, &remote, 1, 0)
        }),
        1,
    ));
    let mut network = true;
    for domain in [
        libc::AF_INET,
        libc::AF_INET6,
        libc::AF_PACKET,
        libc::AF_NETLINK,
    ] {
        network &= denied(unsafe { libc::syscall(libc::SYS_socket, domain, libc::SOCK_DGRAM, 0) });
    }
    values.push(Observation {
        check: Check::NetworkDenied,
        role: Some(role),
        passed: network,
        attempts: 4,
        denials: 4,
    });
    values
}

pub(super) fn run() -> i32 {
    if unsafe { libc::getpid() } != 1 {
        return 2;
    }
    let mut raw = Vec::new();
    // FD 7 is a one-way, bounded bootstrap manifest from the root supervisor.
    let mut source = unsafe { fs::File::from_raw_fd(7) };
    loop {
        let mut byte = [0];
        if source.read_exact(&mut byte).is_err() || raw.len() >= 4096 {
            return 2;
        }
        if byte[0] == b'\n' {
            break;
        }
        raw.push(byte[0]);
    }
    drop(source);
    let Ok(manifest) = serde_json::from_slice::<Manifest>(&raw) else {
        return 2;
    };
    if unsafe { libc::geteuid() } != manifest.role.uid() {
        return 2;
    }
    if seccomp::install(manifest.role, false).is_err() {
        return 2;
    }
    if !event(&manifest, Phase::Ready, Vec::new()) || !wait() {
        return 3;
    }
    // All raw argv/stderr bytes are deliberately untrusted and must be bounded
    // and discarded by the supervisor instead of copied into audit.
    bytes(2, b"dummy-stderr-marker\n");
    let mut values = checks(&manifest);
    if manifest.role == Role::Guard {
        for (input, output) in [(3, 10), (8, 9)] {
            let Ok(value) = ancillary::receive(input) else {
                event(&manifest, Phase::GuardRejected, values);
                wait();
                return 4;
            };
            let framed = ancillary::frame(&value);
            if !bytes(output, &framed) {
                return 4;
            }
        }
    } else {
        if !bytes(3, &ancillary::frame(b"ping")) {
            return 4;
        }
        let mut echoed = [0_u8; 8];
        let count = unsafe { libc::read(8, echoed.as_mut_ptr().cast(), echoed.len()) };
        values.push(observe(
            Check::PositiveIpc,
            manifest.role,
            count == 8 && echoed == [0, 0, 0, 4, b'p', b'i', b'n', b'g'],
            0,
        ));
    }
    let ok = values.iter().all(|v| v.passed);
    if !event(&manifest, Phase::Done, values) {
        return 4;
    }
    wait();
    if ok { 0 } else { 1 }
}
