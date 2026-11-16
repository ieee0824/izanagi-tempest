//! Fixed non-root dummy roles. No model, guest, config or external destination.
use super::{
    ancillary,
    contract::{Check, Observation, Role, Scenario},
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
    pub(super) scenario: Scenario,
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
    Entered,
    Done,
    GuardRejected,
    MemoryArmed,
    StateWritten,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Event {
    #[serde(default)]
    pub(super) bootstrap: Option<(u8, i32)>,
    #[serde(default)]
    pub(super) library_fault: Option<Scenario>,
    #[serde(default)]
    pub(super) rejection: Option<ancillary::Rejection>,
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
    let mut nonce = manifest.nonce;
    if manifest.scenario == Scenario::ForeignReady
        && manifest.role == Role::A
        && phase == Phase::Ready
    {
        nonce[0] ^= 1;
    }
    let value = Event {
        bootstrap: None,
        library_fault: None,
        rejection: None,
        role: manifest.role,
        nonce,
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
        scenario: None,
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

fn positive_canary(role: Role) -> bool {
    if role == Role::A {
        fs::read("/private/credential.canary").is_ok_and(|b| b == b"synthetic-canary-only")
    } else {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open("/work/own")
            .and_then(|mut f| f.write_all(b"dummy"))
            .is_ok()
    }
}

fn resource_checks(manifest: &Manifest) -> Vec<Observation> {
    let role = manifest.role;
    let mut values = vec![observe(
        Check::PositiveCanary,
        role,
        positive_canary(role),
        0,
    )];
    if role != Role::A {
        return values;
    }
    let resource = match manifest.scenario {
        Scenario::PidsLimit => {
            let mut children = 0;
            let mut denied = false;
            let mut attempts = 0;
            // Absolute cap even if the kernel contract is broken. Children do
            // no work and remain in this role cgroup until supervisor cleanup.
            for _ in 0..16 {
                attempts += 1;
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    let delay = libc::timespec {
                        tv_sec: 30,
                        tv_nsec: 0,
                    };
                    loop {
                        unsafe {
                            libc::nanosleep(&delay, std::ptr::null_mut());
                        }
                    }
                }
                if pid < 0 {
                    denied = std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN);
                    break;
                }
                children += 1;
            }
            Observation {
                scenario: None,
                check: Check::PidsBounded,
                role: Some(role),
                passed: children == 11 && denied,
                attempts,
                denials: u64::from(denied),
            }
        }
        Scenario::DetachedGrandchild | Scenario::CgroupKillNoop => {
            let child = unsafe { libc::fork() };
            if child == 0 {
                if unsafe { libc::setsid() } < 0 {
                    unsafe {
                        libc::_exit(101);
                    }
                }
                let grandchild = unsafe { libc::fork() };
                if grandchild < 0 {
                    unsafe {
                        libc::_exit(102);
                    }
                }
                if grandchild > 0 {
                    unsafe {
                        libc::_exit(0);
                    }
                }
                // No exec and no work: retain a detached, reparented process
                // until the supervisor proves cgroup/pidfd cleanup.
                let delay = libc::timespec {
                    tv_sec: 30,
                    tv_nsec: 0,
                };
                loop {
                    unsafe {
                        libc::nanosleep(&delay, std::ptr::null_mut());
                    }
                }
            }
            let mut status = 0;
            let waited = child > 0 && unsafe { libc::waitpid(child, &mut status, 0) } == child;
            Observation {
                scenario: None,
                check: Check::DetachedDescendant,
                role: Some(role),
                passed: waited && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                attempts: 2,
                denials: 0,
            }
        }
        Scenario::TmpfsFull => {
            let block = [0_u8; 524288];
            let mut exhausted = false;
            let mut attempts = 0;
            for index in 0..32 {
                attempts += 1;
                let result = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(format!("/work/fixed-fill-{index}"))
                    .and_then(|mut file| file.write_all(&block));
                if let Err(error) = result {
                    exhausted = error.raw_os_error() == Some(libc::ENOSPC);
                    break;
                }
            }
            Observation {
                scenario: None,
                check: Check::TmpfsBounded,
                role: Some(role),
                passed: exhausted && attempts > 1,
                attempts,
                denials: u64::from(exhausted),
            }
        }
        _ => return values,
    };
    values.push(resource);
    values
}

fn checks(manifest: &Manifest) -> Vec<Observation> {
    let role = manifest.role;
    let mut values = Vec::new();
    let own = positive_canary(role);
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
            scenario: None,
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
    let mut library_denials = 0;
    let mut library_reads = true;
    for (_, relative) in super::capsule::LIBRARIES {
        let path = format!("/{relative}");
        library_reads &= fs::File::open(&path).is_ok();
        let result = fs::OpenOptions::new().write(true).open(&path);
        if result.is_err_and(|error| {
            matches!(
                error.raw_os_error(),
                Some(libc::EROFS | libc::EACCES | libc::EPERM)
            )
        }) {
            library_denials += 1;
        }
    }
    if denied(unsafe {
        libc::syscall(
            libc::SYS_mount,
            std::ptr::null::<libc::c_char>(),
            c"/lib/x86_64-linux-gnu/libc.so.6".as_ptr(),
            std::ptr::null::<libc::c_char>(),
            libc::MS_REMOUNT | libc::MS_BIND,
            std::ptr::null::<libc::c_char>(),
        )
    }) {
        library_denials += 1;
    }
    values.push(Observation {
        scenario: None,
        check: Check::LibraryReadonly,
        role: Some(role),
        passed: library_reads && library_denials == 5,
        attempts: 5,
        denials: library_denials,
    });
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
        scenario: None,
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
    if !event(&manifest, Phase::Entered, Vec::new()) {
        return 3;
    }
    if manifest.scenario == Scenario::MemoryOom && manifest.role == Role::A {
        const LENGTH: usize = 160 * 1024 * 1024;
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                LENGTH,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return 92;
        }
        if !event(
            &manifest,
            Phase::MemoryArmed,
            vec![observe(Check::MemoryMapped, manifest.role, true, 0)],
        ) || !wait()
        {
            return 3;
        }
        // Fixed upper bound; touch every base page only after the supervisor
        // verifies limits/counter baselines. The memcg must kill this role.
        for offset in (0..LENGTH).step_by(4096) {
            unsafe {
                std::ptr::write_volatile(mapping.cast::<u8>().add(offset), 1);
            }
        }
        unsafe {
            libc::munmap(mapping, LENGTH);
        }
        return 93; // Surviving the entire allocation is a failure, never OOM.
    }
    if manifest.scenario.output_flood() && manifest.role == manifest.scenario.output_target().0 {
        if !wait() {
            return 3;
        }
        let stream = i32::from(manifest.scenario.output_target().1);
        let mut block = [42_u8; 4096];
        let marker = b"dummy-output-marker";
        block[..marker.len()].copy_from_slice(marker);
        if manifest.scenario == Scenario::ContinuousStdout {
            let until = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while std::time::Instant::now() < until {
                if !bytes(stream, &block) {
                    return 4;
                }
            }
        } else {
            for _ in 0..64 {
                if !bytes(stream, &block) {
                    return 4;
                }
            }
        }
        wait();
        return 0;
    }
    if manifest.scenario.lifecycle() && manifest.role == Role::A {
        if manifest.scenario == Scenario::ReportEof {
            unsafe {
                libc::close(5);
            }
        }
        // Stay alive with no stdout/stderr output. The supervisor must detect
        // EOF or its normal overall deadline, not mistake this for a child exit.
        wait();
        return 0;
    }
    if manifest.scenario.resource() || manifest.scenario.lifecycle() {
        // Peer positives run only after A reports exhaustion, so a success
        // cannot come from before pressure was applied in the other role.
        if manifest.role != Role::A && !wait() {
            return 3;
        }
        let values = resource_checks(&manifest);
        let ok = values.iter().all(|value| value.passed);
        if !event(&manifest, Phase::Done, values) {
            return 4;
        }
        wait();
        return if ok { 0 } else { 1 };
    }
    if manifest.scenario.injection() && manifest.role != Role::Guard {
        // The root fixture injects at the raw socket. Recipients remain armed
        // without consuming their output pipes until the guard has rejected it.
        if !wait() {
            return 3;
        }
        let mut poll = libc::pollfd {
            fd: 8,
            events: libc::POLLIN,
            revents: 0,
        };
        let clear = unsafe { libc::poll(&mut poll, 1, 0) } == 0;
        if !event(
            &manifest,
            Phase::Done,
            vec![observe(Check::NoForwardedPayload, manifest.role, clear, 0)],
        ) {
            return 4;
        }
        wait();
        return if clear { 0 } else { 1 };
    }
    // All raw argv/stderr bytes are deliberately untrusted and must be bounded
    // and discarded by the supervisor instead of copied into audit.
    bytes(2, b"dummy-stderr-marker\n");
    let mut values = checks(&manifest);
    if manifest.role == Role::Guard {
        let directions = if manifest.scenario.reverse() {
            [(8, 9), (3, 10)]
        } else {
            [(3, 10), (8, 9)]
        };
        for (input, output) in directions {
            let received = if manifest.scenario == Scenario::ControlTruncation {
                ancillary::receive_truncated_control(input)
            } else {
                ancillary::receive(input)
            };
            let value = match received {
                Ok(value) => value,
                Err(rejection) => {
                    let rejected = Event {
                        bootstrap: None,
                        library_fault: None,
                        rejection: Some(rejection),
                        role: manifest.role,
                        nonce: manifest.nonce,
                        phase: Phase::GuardRejected,
                        checks: values,
                        canary_address: MEMORY.as_ptr() as u64,
                    };
                    if let Ok(mut raw) = serde_json::to_vec(&rejected) {
                        raw.push(b'\n');
                        bytes(5, &raw);
                    }
                    wait();
                    return 4;
                }
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

#[cfg(test)]
mod protocol_tests {
    use super::*;

    #[test]
    fn manifest_rejects_unknown_inputs_and_invalid_nonce() {
        let manifest = Manifest {
            scenario: Scenario::Baseline,
            role: Role::A,
            nonce: [17; 16],
            supervisor: 42,
            peers: [43, 44, 45],
        };
        let mut value = serde_json::to_value(&manifest).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        let decoded: Manifest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(decoded.nonce, manifest.nonce);
        value["command"] = serde_json::json!("dummy");
        assert!(serde_json::from_value::<Manifest>(value.clone()).is_err());
        value.as_object_mut().unwrap().remove("command");
        value["nonce"] = serde_json::json!([17]);
        assert!(serde_json::from_value::<Manifest>(value).is_err());
    }

    #[test]
    fn event_rejects_unknown_phase_and_observation_fields() {
        let event = Event {
            bootstrap: None,
            library_fault: None,
            rejection: None,
            role: Role::A,
            nonce: [17; 16],
            phase: Phase::Done,
            checks: vec![observe(Check::PositiveCanary, Role::A, true, 0)],
            canary_address: 0,
        };
        let value = serde_json::to_value(event).unwrap();
        assert!(serde_json::from_value::<Event>(value.clone()).is_ok());
        let mut invalid = value.clone();
        invalid["phase"] = serde_json::json!("arbitrary_phase");
        assert!(serde_json::from_value::<Event>(invalid).is_err());
        let mut invalid = value;
        invalid["checks"][0]["path"] = serde_json::json!("dummy");
        assert!(serde_json::from_value::<Event>(invalid).is_err());
    }
}
