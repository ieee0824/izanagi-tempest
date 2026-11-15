//! Single-threaded fixed probe supervisor. No Command/shell execution.
use super::{
    ancillary, capsule,
    cgroup::Group,
    contract::{self, Identity, Observation, Role, Scenario},
    identity::{self, Descriptor, Process},
    os::{self, Fault, Snapshot},
    worker::{Event, Manifest, Phase},
};
use std::{
    fs::{self, File},
    io::{self, Write},
    os::{
        fd::{AsRawFd, OwnedFd, RawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::{Duration, Instant},
};

const RUN: &str = "/run/tempest-linux-isolation-probe";
const OVERALL: Duration = Duration::from_secs(30);

fn capability_contract(value: &str) -> Result<(), Fault> {
    // The reviewed bootstrap drops exactly capabilities 0..=40. A kernel
    // contract change must fail closed, not silently retain additional bits.
    if value.trim().parse::<u32>() == Ok(40) {
        Ok(())
    } else {
        Err(Fault::Identity)
    }
}

struct Channel {
    read: OwnedFd,
    write: OwnedFd,
}

impl Channel {
    fn new() -> Result<Self, Fault> {
        let (read, write) = os::pipe()?;
        Ok(Self { read, write })
    }
    fn send(&self, bytes: &[u8]) -> Result<(), Fault> {
        let count =
            unsafe { libc::write(self.write.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        if count != bytes.len() as isize {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
}

struct Worker {
    descriptors: std::collections::BTreeMap<i32, Descriptor>,
    role: Role,
    process: Process,
    expected: Identity,
    boot: Channel,
    start: Channel,
    report: Channel,
    output: Channel,
    error: Channel,
}

fn code_identity(code: &Snapshot) -> Result<(u64, u64), Fault> {
    let metadata = fs::metadata(format!("/proc/self/fd/{}", code.fd()))?;
    Ok((metadata.dev(), metadata.ino()))
}

fn write_event(channel: &Channel, manifest: &Manifest) -> Result<(), Fault> {
    let bytes = serde_json::to_vec(manifest).map_err(|_| Fault::Identity)?;
    channel.send(&bytes)
}

fn event(worker: &Worker, until: Instant) -> Result<Event, Fault> {
    let mut value = Vec::new();
    loop {
        if Instant::now() >= until {
            return Err(Fault::Kernel(libc::ETIMEDOUT));
        }
        let mut poll = libc::pollfd {
            fd: worker.report.read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, 10) };
        if result < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if poll.revents & libc::POLLIN != 0 {
            let mut byte = 0_u8;
            if unsafe { libc::read(poll.fd, (&mut byte as *mut u8).cast(), 1) } != 1 {
                return Err(Fault::Identity);
            }
            if byte == b'\n' {
                break;
            }
            value.push(byte);
            if value.len() > 8192 {
                return Err(Fault::Identity);
            }
        } else if !worker.process.alive()? {
            return Err(worker.process.exited());
        }
    }
    serde_json::from_slice(&value).map_err(|_| Fault::Identity)
}

fn spawn(
    role: Role,
    code: &Snapshot,
    libraries: &[Snapshot],
    null: &File,
    ipc: &[(RawFd, RawFd)],
    group: &Group,
) -> Result<Worker, Fault> {
    let boot = Channel::new()?;
    let start = Channel::new()?;
    let report = Channel::new()?;
    let output = Channel::new()?;
    let error = Channel::new()?;
    let root = Path::new(RUN).join(role.name());
    os::private_directory(&root)?;
    let mut mappings = vec![
        (null.as_raw_fd(), 0),
        (output.write.as_raw_fd(), 1),
        (error.write.as_raw_fd(), 2),
        (start.read.as_raw_fd(), 4),
        (report.write.as_raw_fd(), 5),
        (code.fd(), 6),
        (boot.read.as_raw_fd(), 7),
    ];
    mappings.extend_from_slice(ipc);
    let descriptors = mappings
        .iter()
        .filter(|(_, target)| !matches!(target, 6 | 7))
        .map(|(source, target)| Ok((*target, Descriptor::bind(*source)?)))
        .collect::<Result<_, Fault>>()?;
    let parent = Process::bind(std::process::id())?;
    // Linux fork-style clone: no shared VM, fd table or filesystem state.
    // This entry point rejects multithreaded supervisors before any clone.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWNET | libc::SIGCHLD,
            0,
            0,
            0,
            0,
        )
    };
    if pid < 0 {
        return Err(io::Error::last_os_error().into());
    }
    if pid == 0 {
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0
            || !parent.alive().unwrap_or(false)
        {
            unsafe {
                libc::_exit(100);
            }
        }
        let mut gate = 0_u8;
        if unsafe { libc::read(start.read.as_raw_fd(), (&mut gate as *mut u8).cast(), 1) } != 1
            || gate != b'I'
        {
            unsafe {
                libc::_exit(100);
            }
        }
        let mut step = 0;
        let result = capsule::enter(role, &root, libraries, &mappings, &mut step);
        if step < 5 {
            // Before descriptor remapping the original report endpoint is
            // still valid. Emit only fixed stage/errno, never an OS message.
            let errno = match result {
                Err(Fault::Kernel(n)) => n,
                _ => 0,
            };
            let value = Event {
                bootstrap: Some((step, errno)),
                rejection: None,
                role,
                nonce: [0; 16],
                phase: Phase::BootstrapFault,
                checks: Vec::new(),
                canary_address: 0,
            };
            if let Ok(mut raw) = serde_json::to_vec(&value) {
                raw.push(b'\n');
                unsafe {
                    libc::write(report.write.as_raw_fd(), raw.as_ptr().cast(), raw.len());
                }
            }
        }
        // Do not format an OS error, inherited environment or pathname.
        unsafe {
            libc::_exit(120 + i32::from(step));
        }
    }
    let bound = (|| {
        let process = Process::bind(pid as u32)?;
        group.attach(role, process.pid)?;
        let mut expected = process.identity()?;
        expected.code = code_identity(code)?;
        Ok((process, expected))
    })();
    let (process, expected) = match bound {
        Ok(bound) => bound,
        Err(error) => {
            // This is our fresh, unreaped clone, so its PID cannot be reused.
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
            }
            let until = Instant::now() + Duration::from_secs(3);
            loop {
                let mut status = 0;
                let result = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
                if result == pid as i32 {
                    break;
                }
                if result < 0 || Instant::now() >= until {
                    return Err(Fault::Kernel(libc::EBUSY));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            return Err(error);
        }
    };
    Ok(Worker {
        descriptors,
        role,
        process,
        expected,
        boot,
        start,
        report,
        output,
        error,
    })
}

fn reap(process: &Process) -> Result<(), Fault> {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let mut status = 0;
        let value = unsafe { libc::waitpid(process.pid as i32, &mut status, libc::WNOHANG) };
        if value == process.pid as i32 {
            return Ok(());
        }
        if value < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if Instant::now() >= until {
            return Err(Fault::Kernel(libc::EBUSY));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn initial_uid_available(role: Role) -> Result<bool, Fault> {
    // No account creation and no reuse of an existing account or live UID.
    if !unsafe { libc::getpwuid(role.uid()) }.is_null() {
        return Ok(false);
    }
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        if let Ok(status) = fs::read_to_string(entry.path().join("status")) {
            if status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .is_some_and(|row| {
                    row.split_whitespace()
                        .any(|id| id.parse::<u32>() == Ok(role.uid()))
                })
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn injection(
    workers: &[Worker],
    group: &Group,
    scenario: Scenario,
    nonce: &[u8; 16],
    until: Instant,
    sender: RawFd,
    guard_socket: RawFd,
    to_a: &Channel,
    to_b: &Channel,
) -> Result<Vec<Observation>, Fault> {
    let file = File::open(Path::new(RUN).join("fd.canary"))?;
    let directory = File::open(RUN)?;
    let (socket, _peer) = ancillary::pair()?;
    if scenario == Scenario::UnexpectedControl {
        let on = 1_i32;
        os::syscall(unsafe {
            libc::setsockopt(
                guard_socket,
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&on as *const i32).cast(),
                std::mem::size_of_val(&on) as libc::socklen_t,
            )
        })?;
    }
    let (packet, rights) = match scenario {
        Scenario::FdFileA | Scenario::FdFileB => {
            (ancillary::frame(b"rejected"), vec![file.as_raw_fd(); 2])
        }
        Scenario::FdDirectoryA | Scenario::FdDirectoryB => (
            ancillary::frame(b"rejected"),
            vec![directory.as_raw_fd(); 2],
        ),
        Scenario::FdSocketA | Scenario::FdSocketB => {
            (ancillary::frame(b"rejected"), vec![socket.as_raw_fd(); 2])
        }
        Scenario::ControlTruncation => (ancillary::frame(b"rejected"), vec![file.as_raw_fd(); 32]),
        Scenario::UnexpectedControl => (ancillary::frame(b"rejected"), Vec::new()),
        Scenario::FrameOversize => (ancillary::frame(&[0; 4097]), Vec::new()),
        Scenario::FrameMalformed => (vec![0, 0, 0, 2, 42], Vec::new()),
        _ => return Err(Fault::Identity),
    };
    ancillary::send_packet(sender, &packet, &rights)?;
    let guard = workers
        .iter()
        .find(|w| w.role == Role::Guard)
        .ok_or(Fault::Identity)?;
    let rejected = event(guard, until)?;
    let expected = match scenario {
        Scenario::ControlTruncation | Scenario::FrameOversize => ancillary::Rejection::Truncated,
        Scenario::FrameMalformed => ancillary::Rejection::Framing,
        _ => ancillary::Rejection::Ancillary,
    };
    if rejected.phase != Phase::GuardRejected
        || rejected.role != Role::Guard
        || rejected.nonce != *nonce
        || rejected.bootstrap.is_some()
        || rejected.rejection != Some(expected)
    {
        return Err(Fault::Identity);
    }
    let state = guard
        .process
        .observe(group, guard.role, &guard.descriptors)?;
    if !contract::ready(guard.role, &guard.expected, &state, nonce, nonce) {
        return Err(Fault::Identity);
    }
    for pipe in [to_a, to_b] {
        let mut count = 0_i32;
        if unsafe { libc::ioctl(pipe.read.as_raw_fd(), libc::FIONREAD, &mut count) } != 0
            || count != 0
        {
            return Err(Fault::Identity);
        }
    }
    let mut observed = vec![Observation {
        scenario: Some(scenario),
        check: contract::Check::AncillaryClosed,
        role: Some(Role::Guard),
        passed: true,
        attempts: 1,
        denials: 1,
    }];
    for recipient in workers.iter().filter(|w| w.role != Role::Guard) {
        recipient.start.send(b"G")?;
        let mut done = event(recipient, until)?;
        if done.phase != Phase::Done
            || done.role != recipient.role
            || done.nonce != *nonce
            || done.bootstrap.is_some()
            || done.rejection.is_some()
            || done.checks.len() != 1
            || done.checks[0].check != contract::Check::NoForwardedPayload
            || !done.checks[0].passed
            || done.checks[0].role != Some(recipient.role)
            || done.checks[0].scenario.is_some()
        {
            return Err(Fault::Identity);
        }
        let state = recipient
            .process
            .observe(group, recipient.role, &recipient.descriptors)?;
        if !contract::ready(recipient.role, &recipient.expected, &state, nonce, nonce) {
            return Err(Fault::Identity);
        }
        done.checks[0].scenario = Some(scenario);
        observed.extend(done.checks);
    }
    Ok(observed)
}

fn baseline(
    code: &Snapshot,
    libraries: &[Snapshot],
    group: &Group,
    phase: &mut &'static str,
    scenario: Scenario,
) -> Result<Vec<Observation>, Fault> {
    let host = identity::namespace_ids(std::process::id())?;
    let nonce: [u8; 16] = crate::private_io::random_hex()?.as_bytes()[..16]
        .try_into()
        .map_err(|_| Fault::Identity)?;
    let null = File::open("/dev/null")?;
    let (a, ga) = ancillary::pair()?;
    let (b, gb) = ancillary::pair()?;
    let to_a = Channel::new()?;
    let to_b = Channel::new()?;
    let mut workers = Vec::new();
    let until = Instant::now() + OVERALL;
    let result = (|| {
        *phase = "clone";
        for role in Role::ALL {
            let ipc = match role {
                Role::A => vec![(a.as_raw_fd(), 3), (to_a.read.as_raw_fd(), 8)],
                Role::B => vec![(b.as_raw_fd(), 3), (to_b.read.as_raw_fd(), 8)],
                Role::Guard => vec![
                    (ga.as_raw_fd(), 3),
                    (gb.as_raw_fd(), 8),
                    (to_a.write.as_raw_fd(), 9),
                    (to_b.write.as_raw_fd(), 10),
                ],
            };
            workers.push(spawn(role, code, libraries, &null, &ipc, group)?);
        }
        let peers: [u32; 3] = workers
            .iter()
            .map(|w| w.process.pid)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Fault::Identity)?;
        for worker in &workers {
            write_event(
                &worker.boot,
                &Manifest {
                    scenario,
                    role: worker.role,
                    nonce,
                    supervisor: std::process::id(),
                    peers,
                },
            )?;
            // Close the only parent-side writer after a finite manifest. The
            // other workers' descriptor copies are closed by their bootstrap.
            worker.start.send(b"I")?;
        }
        // A manifest read must not depend on inherited writer EOF; the worker
        // uses a bounded one-line protocol, terminated by the supervisor.
        for worker in &workers {
            worker.boot.send(b"\n")?;
        }
        let mut states = Vec::new();
        *phase = "ready";
        for worker in &workers {
            let ready = event(worker, until)?;
            if ready.phase == Phase::BootstrapFault {
                let (step, errno) = ready.bootstrap.ok_or(Fault::Identity)?;
                return Err(Fault::Bootstrap(step, errno));
            }
            *phase = "kernel_state";
            let state = worker
                .process
                .observe(group, worker.role, &worker.descriptors)?;
            if ready.role != worker.role
                || ready.phase != Phase::Ready
                || ready.bootstrap.is_some()
                || ready.rejection.is_some()
                || !ready.checks.is_empty()
                || !contract::ready(worker.role, &worker.expected, &state, &nonce, &nonce)
            {
                return Err(Fault::Identity);
            }
            if ready.nonce != nonce {
                return Err(Fault::ForeignReady);
            }
            states.push(state);
        }
        let states: [_; 3] = states.try_into().map_err(|_| Fault::Identity)?;
        if !contract::separate(&states, &host) {
            return Err(Fault::Identity);
        }
        // Recheck kernel state for every role immediately before releasing any
        // payload. A later peer death aborts the run, never a successful result.
        for worker in &workers {
            let state = worker
                .process
                .observe(group, worker.role, &worker.descriptors)?;
            if !contract::ready(worker.role, &worker.expected, &state, &nonce, &nonce) {
                return Err(Fault::Identity);
            }
        }
        *phase = "barrier";
        for worker in &workers {
            worker.start.send(b"G")?;
        }
        *phase = "payload";
        for worker in &workers {
            let entered = event(worker, until)?;
            if entered.role != worker.role
                || entered.nonce != nonce
                || entered.phase != Phase::Entered
                || !entered.checks.is_empty()
                || entered.bootstrap.is_some()
                || entered.rejection.is_some()
            {
                return Err(Fault::Identity);
            }
        }
        if scenario.injection() {
            return injection(
                &workers,
                group,
                scenario,
                &nonce,
                until,
                if scenario.reverse() {
                    b.as_raw_fd()
                } else {
                    a.as_raw_fd()
                },
                if scenario.reverse() {
                    gb.as_raw_fd()
                } else {
                    ga.as_raw_fd()
                },
                &to_a,
                &to_b,
            );
        }
        let mut observations = Vec::new();
        for worker in &workers {
            let mut done = event(worker, until)?;
            if done.role != worker.role
                || done.nonce != nonce
                || done.phase != Phase::Done
                || done.checks.is_empty()
                || done.bootstrap.is_some()
                || done.rejection.is_some()
                || !done
                    .checks
                    .iter()
                    .all(|check| check.passed && check.role == Some(worker.role))
            {
                return Err(Fault::Identity);
            }
            for check in &mut done.checks {
                if check.scenario.is_some() {
                    return Err(Fault::Identity);
                }
                check.scenario = Some(scenario);
            }
            observations.extend(done.checks);
        }
        Ok(observations)
    })();
    let killed = group.kill();
    let leaders = workers.iter().try_for_each(|w| w.process.kill());
    let reaped = workers.iter().try_for_each(|w| reap(&w.process));
    // Raw stdout/stderr is never public audit. These fields keep capture pipes
    // private and live until termination, including an error path.
    for worker in &workers {
        let _ = (&worker.output, &worker.error);
    }
    killed?;
    leaders?;
    reaped?;
    if !group.empty()? {
        return Err(Fault::Kernel(libc::EBUSY));
    }
    if matches!(result, Err(Fault::ForeignReady)) {
        // Payload entry writes a fixed stderr marker only AFTER Go. Do not
        // consume or publish any bytes; inspect the pipe counters independently.
        for worker in &workers {
            for channel in [&worker.output, &worker.error] {
                let mut count = 0_i32;
                if unsafe { libc::ioctl(channel.read.as_raw_fd(), libc::FIONREAD, &mut count) } != 0
                    || count != 0
                {
                    return Err(Fault::Identity);
                }
            }
        }
    }
    result
}

pub(super) fn run(args: &[std::ffi::OsString]) -> std::process::ExitCode {
    if args == [std::ffi::OsString::from("--help")] {
        println!("Usage: tempest linux-isolation-probe (fixed dummy-only root probe; no options)");
        return std::process::ExitCode::SUCCESS;
    }
    if !args.is_empty() || unsafe { libc::geteuid() } != 0 {
        println!("{{\"status\":\"rejected\",\"reason\":\"fixed_root_entry_required\"}}");
        return std::process::ExitCode::from(2);
    }
    let mut locked = false;
    let mut phase = "entry";
    let mut watchdog = None;
    let result = (|| {
        if !cfg!(target_arch = "x86_64") || fs::read_dir("/proc/self/task")?.count() != 1 {
            return Err(Fault::Identity);
        }
        phase = "kernel_contract";
        capability_contract(&fs::read_to_string("/proc/sys/kernel/cap_last_cap")?)?;
        phase = "uid_reservation";
        for role in Role::ALL {
            if !initial_uid_available(role)? {
                return Err(Fault::Identity);
            }
        }
        phase = "code_snapshot";
        let executable = std::env::current_exe()?;
        let code = Snapshot::trusted(&executable)?;
        phase = "library_snapshot";
        let libraries = capsule::LIBRARIES
            .iter()
            .map(|(path, _)| Snapshot::trusted(Path::new(path)))
            .collect::<Result<Vec<_>, _>>()?;
        phase = "run_lock";
        os::private_directory(Path::new(RUN))?;
        locked = true;
        phase = "watchdog";
        let (watch, mut group) = super::watchdog::Watchdog::start()?;
        watchdog = Some(watch);
        phase = "cgroup";
        let mut canary = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(Path::new(RUN).join("fd.canary"))?;
        canary.write_all(b"dummy-fd-canary")?;
        drop(canary);
        let observed = (|| {
            let mut observed = baseline(&code, &libraries, &group, &mut phase, Scenario::Baseline)?;
            for role in Role::ALL {
                fs::remove_dir(Path::new(RUN).join(role.name()))?;
            }
            match baseline(
                &code,
                &libraries,
                &group,
                &mut phase,
                Scenario::ForeignReady,
            ) {
                Err(Fault::ForeignReady) => observed.push(Observation {
                    scenario: Some(Scenario::ForeignReady),
                    check: contract::Check::ForeignReadyRejected,
                    role: Some(Role::A),
                    passed: true,
                    attempts: 1,
                    denials: 1,
                }),
                Err(error) => return Err(error),
                Ok(_) => return Err(Fault::Identity),
            }
            for scenario in Scenario::INJECTIONS {
                for role in Role::ALL {
                    fs::remove_dir(Path::new(RUN).join(role.name()))?;
                }
                observed.extend(baseline(&code, &libraries, &group, &mut phase, scenario)?);
            }
            Ok(observed)
        })();
        group.cleanup()?;
        let observed = observed?;
        Ok((code.sha256, observed))
    })();
    let kernel_removed = !Path::new(super::cgroup::ROOT).exists();
    let watch_finished = if let Some(watch) = &mut watchdog {
        kernel_removed && watch.finish().is_ok()
    } else {
        true
    };
    let removed = if locked && kernel_removed && watch_finished {
        fs::remove_dir_all(RUN).is_ok()
    } else {
        !Path::new(RUN).exists() && kernel_removed
    };
    match result {
        Ok((hash, observations)) if removed => {
            // Further lifecycle/resource/ancillary root cases are not yet
            // implemented. Never advertise the baseline as M1 completion.
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"status":"incomplete",
                "formal_eligible":false,"model_launched":false,"code_sha256":hash,
                "checks":observations,"resources_removed":true})
            );
            std::process::ExitCode::from(1)
        }
        Err(fault) => {
            let child_exit = if let Fault::Child(value) = fault {
                Some(value)
            } else {
                None
            };
            let reason = match fault {
                Fault::Identity => "identity",
                Fault::Ownership => "ownership",
                Fault::Path => "path",
                Fault::Seal => "seal",
                Fault::Kernel(_) => "kernel",
                Fault::Child(_) => "child_exit",
                Fault::Bootstrap(_, _) => "bootstrap",
                Fault::ForeignReady => "foreign_ready",
            };
            let errno = match fault {
                Fault::Kernel(value) => value,
                Fault::Bootstrap(_, value) => value,
                _ => 0,
            };
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"status":"failed",
                "formal_eligible":false,"model_launched":false,"errno":errno,
                "resources_removed":removed,"phase":phase,"reason":reason,"child_exit":child_exit})
            );
            std::process::ExitCode::from(1)
        }
        _ => {
            println!(
                "{{\"status\":\"failed\",\"reason\":\"cleanup_unproven\",\"resources_removed\":false}}"
            );
            std::process::ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_or_unreadable_capability_ceiling_cannot_start_the_probe() {
        assert!(capability_contract("40\n").is_ok());
        for value in ["41", "39", "", "not-a-kernel-value", "40 41"] {
            assert!(capability_contract(value).is_err());
        }
    }
}
