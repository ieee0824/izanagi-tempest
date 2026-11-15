//! Single-threaded fixed probe supervisor. No Command/shell execution.
use super::{
    ancillary, capsule,
    capture::{self, Capture},
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
    report: OwnedFd,
    capture: Capture,
}

fn code_identity(code: &Snapshot) -> Result<(u64, u64), Fault> {
    let metadata = fs::metadata(format!("/proc/self/fd/{}", code.fd()))?;
    Ok((metadata.dev(), metadata.ino()))
}

fn write_event(channel: &Channel, manifest: &Manifest) -> Result<(), Fault> {
    let bytes = serde_json::to_vec(manifest).map_err(|_| Fault::Identity)?;
    channel.send(&bytes)
}

fn event(worker: &Worker, until: Instant, peers: &[Worker]) -> Result<Event, Fault> {
    let mut value = Vec::new();
    loop {
        super::lease::pulse()?;
        if Instant::now() >= until {
            return Err(Fault::ReportTimeout);
        }
        if peers.len() > 3 {
            return Err(Fault::Identity);
        }
        let mut polls = [libc::pollfd {
            fd: -1,
            events: libc::POLLIN,
            revents: 0,
        }; 7];
        polls[0].fd = worker.report.as_raw_fd();
        for (peer_index, peer) in peers.iter().enumerate() {
            for stream in 0..2 {
                polls[1 + peer_index * 2 + stream].fd = peer.capture.poll_fd(stream);
            }
        }
        let result = unsafe {
            libc::poll(
                polls.as_mut_ptr(),
                (1 + peers.len() * 2) as libc::nfds_t,
                10,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error().into());
        }
        for (peer_index, peer) in peers.iter().enumerate() {
            for stream in 0..2 {
                let revents = polls[1 + peer_index * 2 + stream].revents;
                if revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                    return Err(Fault::Identity);
                }
                if revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                    let drained = peer.capture.drain(stream);
                    if Instant::now() >= until {
                        return Err(Fault::ReportTimeout);
                    }
                    drained?;
                }
            }
        }
        super::lease::pulse()?;
        if Instant::now() >= until {
            return Err(Fault::ReportTimeout);
        }
        let report_alive = worker.process.alive()?;
        let poll = &polls[0];
        if poll.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(Fault::Identity);
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
        } else if poll.revents & libc::POLLHUP != 0 && report_alive {
            return Err(Fault::ReportEof);
        } else if !report_alive {
            return Err(worker.process.exited());
        }
    }
    serde_json::from_slice(&value).map_err(|_| Fault::Identity)
}

fn spawn(
    role: Role,
    scenario: Scenario,
    code: &Snapshot,
    libraries: &[Snapshot],
    null: &File,
    ipc: &[(RawFd, RawFd)],
    group: &Group,
) -> Result<Worker, Fault> {
    let boot = Channel::new()?;
    let start = Channel::new()?;
    let report = Channel::new()?;
    let Channel {
        read: output,
        write: output_write,
    } = Channel::new()?;
    let Channel {
        read: error,
        write: error_write,
    } = Channel::new()?;
    let capture = Capture::new(role, output, error)?;
    let root = Path::new(RUN).join(role.name());
    os::private_directory(&root)?;
    let mut mappings = vec![
        (null.as_raw_fd(), 0),
        (output_write.as_raw_fd(), 1),
        (error_write.as_raw_fd(), 2),
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
        super::lease::clear();
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
        let result = capsule::enter(role, scenario, &root, libraries, &mappings, &mut step);
        if step < 5 {
            // Before descriptor remapping the original report endpoint is
            // still valid. Emit only fixed stage/errno, never an OS message.
            let errno = match result {
                Err(Fault::Kernel(n)) => n,
                _ => 0,
            };
            let value = Event {
                bootstrap: Some((step, errno)),
                library_fault: if let Err(Fault::LibraryRejected(scenario)) = result {
                    Some(scenario)
                } else {
                    None
                },
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
    // The supervisor owns read ends only. Retaining any write end here masks
    // a live worker's report closure and prevents real pipe EOF observation.
    drop(report.write);
    drop(output_write);
    drop(error_write);
    Ok(Worker {
        descriptors,
        role,
        process,
        expected,
        boot,
        start,
        report: report.read,
        capture,
    })
}

fn reap(process: &Process) -> Result<(), Fault> {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        super::lease::pulse()?;
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
    let rejected = event(guard, until, workers)?;
    let expected = match scenario {
        Scenario::ControlTruncation | Scenario::FrameOversize => ancillary::Rejection::Truncated,
        Scenario::FrameMalformed => ancillary::Rejection::Framing,
        _ => ancillary::Rejection::Ancillary,
    };
    if rejected.phase != Phase::GuardRejected
        || rejected.role != Role::Guard
        || rejected.nonce != *nonce
        || rejected.bootstrap.is_some()
        || rejected.library_fault.is_some()
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
        let mut done = event(recipient, until, workers)?;
        if done.phase != Phase::Done
            || done.role != recipient.role
            || done.nonce != *nonce
            || done.bootstrap.is_some()
            || done.library_fault.is_some()
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

fn wait_dead(processes: &[&Process]) -> Result<(), Fault> {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        super::lease::pulse()?;
        let alive = processes.iter().try_fold(false, |alive, process| {
            Ok::<_, Fault>(alive | process.alive()?)
        })?;
        if !alive {
            return Ok(());
        }
        if Instant::now() >= until {
            return Err(Fault::Kernel(libc::EBUSY));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
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
    let mut descendants = Vec::new();
    let pids_before = if scenario == Scenario::PidsLimit {
        Some(group.pids_events()?)
    } else {
        None
    };
    let mut result = (|| {
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
            workers.push(spawn(role, scenario, code, libraries, &null, &ipc, group)?);
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
        let mut library_states = Vec::new();
        *phase = "ready";
        for worker in &workers {
            let ready = event(worker, until, &workers)?;
            if ready.phase == Phase::BootstrapFault {
                let (step, errno) = ready.bootstrap.ok_or(Fault::Identity)?;
                if ready.role == Role::A
                    && step == 3
                    && errno == 0
                    && scenario.library_fault()
                    && ready.library_fault == Some(scenario)
                {
                    return Err(Fault::LibraryRejected(scenario));
                }
                return Err(Fault::Bootstrap(step, errno));
            }
            *phase = "kernel_state";
            let state = worker
                .process
                .observe(group, worker.role, &worker.descriptors)?;
            if ready.role != worker.role
                || ready.phase != Phase::Ready
                || ready.bootstrap.is_some()
                || ready.library_fault.is_some()
                || ready.rejection.is_some()
                || !ready.checks.is_empty()
                || !contract::ready(worker.role, &worker.expected, &state, &nonce, &nonce)
            {
                return Err(Fault::Identity);
            }
            if ready.nonce != nonce {
                return Err(Fault::ForeignReady);
            }
            *phase = "library_identity";
            library_states.push(
                libraries
                    .iter()
                    .zip(capsule::LIBRARIES)
                    .map(|(snapshot, (_, relative))| {
                        capsule::verify_library(
                            snapshot,
                            &Path::new(&format!("/proc/{}/root", worker.process.pid))
                                .join(relative),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            );
            states.push(state);
        }
        let states: [_; 3] = states.try_into().map_err(|_| Fault::Identity)?;
        if !contract::separate(&states, &host) {
            return Err(Fault::Identity);
        }
        // Recheck kernel state for every role immediately before releasing any
        // payload. A later peer death aborts the run, never a successful result.
        for (worker, expected_libraries) in workers.iter().zip(&library_states) {
            let state = worker
                .process
                .observe(group, worker.role, &worker.descriptors)?;
            if !contract::ready(worker.role, &worker.expected, &state, &nonce, &nonce) {
                return Err(Fault::Identity);
            }
            *phase = "library_recheck";
            for ((snapshot, (_, relative)), expected) in libraries
                .iter()
                .zip(capsule::LIBRARIES)
                .zip(expected_libraries)
            {
                let target =
                    Path::new(&format!("/proc/{}/root", worker.process.pid)).join(relative);
                if capsule::verify_library(snapshot, &target)? != *expected {
                    return Err(Fault::Identity);
                }
            }
        }
        *phase = "barrier";
        for worker in &workers {
            worker.start.send(b"G")?;
        }
        *phase = "payload";
        for worker in &workers {
            let entered = event(worker, until, &workers)?;
            if entered.role != worker.role
                || entered.nonce != nonce
                || entered.phase != Phase::Entered
                || !entered.checks.is_empty()
                || entered.bootstrap.is_some()
                || entered.library_fault.is_some()
                || entered.rejection.is_some()
            {
                return Err(Fault::Identity);
            }
        }
        if scenario.output_flood() {
            workers
                .iter()
                .find(|peer| peer.role == scenario.output_target().0)
                .ok_or(Fault::Identity)?
                .start
                .send(b"G")?;
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
            if (scenario.resource() || scenario.lifecycle()) && worker.role != Role::A {
                worker.start.send(b"G")?;
            }
            if scenario == Scenario::MemoryOom && worker.role == Role::A {
                let mut armed = event(worker, until, &workers)?;
                if armed.role != Role::A
                    || armed.nonce != nonce
                    || armed.phase != Phase::MemoryArmed
                    || armed.bootstrap.is_some()
                    || armed.library_fault.is_some()
                    || armed.rejection.is_some()
                    || armed.checks.len() != 1
                    || armed.checks[0].check != contract::Check::MemoryMapped
                    || !armed.checks[0].passed
                    || armed.checks[0].role != Some(Role::A)
                    || armed.checks[0].scenario.is_some()
                {
                    return Err(Fault::Identity);
                }
                let state = worker
                    .process
                    .observe(group, Role::A, &worker.descriptors)?;
                if !contract::ready(Role::A, &worker.expected, &state, &nonce, &nonce) {
                    return Err(Fault::Identity);
                }
                let before = group.memory_events(Some(Role::A))?;
                let parent_before = group.memory_events(None)?;
                let b_before = group.memory_events(Some(Role::B))?;
                let guard_before = group.memory_events(Some(Role::Guard))?;
                worker.start.send(b"G")?;
                while worker.process.alive()? {
                    super::lease::pulse()?;
                    if Instant::now() >= until {
                        return Err(Fault::ReportTimeout);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                let exit = worker.process.exited();
                if exit != Fault::ChildSignal(libc::SIGKILL, false) {
                    return Err(exit);
                }
                let after = group.memory_events(Some(Role::A))?;
                if !after
                    .iter()
                    .zip(before)
                    .all(|(after, before)| *after > before)
                    || group.memory_events(None)? != parent_before
                    || group.memory_events(Some(Role::B))? != b_before
                    || group.memory_events(Some(Role::Guard))? != guard_before
                {
                    return Err(Fault::Identity);
                }
                for peer in workers.iter().filter(|peer| peer.role != Role::A) {
                    let state = peer.process.observe(group, peer.role, &peer.descriptors)?;
                    if !contract::ready(peer.role, &peer.expected, &state, &nonce, &nonce) {
                        return Err(Fault::Identity);
                    }
                }
                armed.checks[0].scenario = Some(scenario);
                observations.extend(armed.checks);
                for check in [
                    contract::Check::MemoryBounded,
                    contract::Check::ChildSignalObserved,
                ] {
                    observations.push(Observation {
                        scenario: Some(scenario),
                        check,
                        role: Some(Role::A),
                        passed: true,
                        attempts: 1,
                        denials: 0,
                    });
                }
                continue;
            }
            let received = event(worker, until, &workers);
            if worker.role == Role::A && scenario.lifecycle() {
                let expected_fault = match scenario {
                    Scenario::ReportTimeout => Fault::ReportTimeout,
                    Scenario::ReportEof => Fault::ReportEof,
                    Scenario::StdoutFlood => Fault::OutputLimit(Role::A, 1),
                    Scenario::StderrFlood => Fault::OutputLimit(Role::A, 2),
                    Scenario::PeerStdoutFlood => Fault::OutputLimit(Role::B, 1),
                    Scenario::ContinuousStdout => Fault::OutputLimit(Role::A, 1),
                    _ => return Err(Fault::Identity),
                };
                if received.as_ref().err() != Some(&expected_fault)
                    || (scenario == Scenario::ReportTimeout && Instant::now() < until)
                {
                    return Err(Fault::Identity);
                }
                if scenario.output_flood() {
                    let (role, stream) = scenario.output_target();
                    let source = workers
                        .iter()
                        .find(|peer| peer.role == role)
                        .ok_or(Fault::Identity)?;
                    let counts = source.capture.counts();
                    let stream = usize::from(stream - 1);
                    let total = counts[0].saturating_add(counts[1]);
                    if total <= capture::LIMIT
                        || total > capture::LIMIT + capture::CHUNK as u64
                        || counts[1 - stream] != 0
                    {
                        return Err(Fault::Identity);
                    }
                }
                // Verify every role is still alive and confined at failure.
                // The EOF case intentionally removes exactly report FD 5.
                for peer in &workers {
                    let mut descriptors = peer.descriptors.clone();
                    if scenario == Scenario::ReportEof && peer.role == Role::A {
                        descriptors.remove(&5);
                    }
                    let state = peer.process.observe(group, peer.role, &descriptors)?;
                    if !contract::ready(peer.role, &peer.expected, &state, &nonce, &nonce) {
                        return Err(Fault::Identity);
                    }
                }
                return Err(Fault::LifecycleDetected(scenario));
            }
            let mut done = received?;
            if done.role != worker.role
                || done.nonce != nonce
                || done.phase != Phase::Done
                || done.checks.is_empty()
                || done.bootstrap.is_some()
                || done.library_fault.is_some()
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
        if scenario == Scenario::PidsLimit {
            if group.pids_events()? <= pids_before.ok_or(Fault::Identity)? {
                return Err(Fault::Identity);
            }
            let members = group.pids_members()?;
            let worker = workers
                .iter()
                .find(|worker| worker.role == Role::A)
                .ok_or(Fault::Identity)?;
            if members.len() != 12 || !members.contains(&worker.process.pid) {
                return Err(Fault::Identity);
            }
            for pid in members.into_iter().filter(|pid| *pid != worker.process.pid) {
                let process = Process::bind(pid)?;
                if !process.alive()? || !group.bound(Role::A, pid)? {
                    return Err(Fault::Identity);
                }
                descendants.push(process);
            }
            observations.push(Observation {
                scenario: Some(scenario),
                check: contract::Check::ResourceLimits,
                role: Some(Role::A),
                passed: true,
                attempts: 1,
                denials: 1,
            });
        } else if matches!(
            scenario,
            Scenario::DetachedGrandchild | Scenario::CgroupKillNoop
        ) {
            let worker = workers
                .iter()
                .find(|worker| worker.role == Role::A)
                .ok_or(Fault::Identity)?;
            let members = group.members(Role::A)?;
            if members.len() != 2 || !members.contains(&worker.process.pid) {
                return Err(Fault::Identity);
            }
            let pid = *members
                .iter()
                .find(|pid| **pid != worker.process.pid)
                .ok_or(Fault::Identity)?;
            let descendant = Process::bind(pid)?;
            let [parent, group_id, session] = descendant.lineage()?;
            let [_, parent_group, parent_session] = worker.process.lineage()?;
            if parent != worker.process.pid
                || group_id == 0
                || group_id != session
                || group_id == pid
                || group_id == parent_group
                || session == parent_session
            {
                return Err(Fault::Identity);
            }
            let mut expected = worker.expected.clone();
            expected.pid = pid;
            expected.start_ticks = descendant.birth;
            let state = descendant.observe(group, Role::A, &worker.descriptors)?;
            if !contract::ready(Role::A, &expected, &state, &nonce, &nonce) {
                return Err(Fault::Identity);
            }
            descendants.push(descendant);
            observations.push(Observation {
                scenario: Some(scenario),
                check: contract::Check::KernelIdentity,
                role: Some(Role::A),
                passed: true,
                attempts: 1,
                denials: 0,
            });
        } else if scenario == Scenario::TmpfsFull {
            let worker = workers
                .iter()
                .find(|worker| worker.role == Role::A)
                .ok_or(Fault::Identity)?;
            let root = File::open(format!("/proc/{}/root/work", worker.process.pid))?;
            let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
            os::syscall(unsafe { libc::fstatvfs(root.as_raw_fd(), stats.as_mut_ptr()) })?;
            let stats = unsafe { stats.assume_init() };
            if stats.f_bavail != 0 || stats.f_blocks * stats.f_frsize > 16_777_216 {
                return Err(Fault::Identity);
            }
            observations.push(Observation {
                scenario: Some(scenario),
                check: contract::Check::ResourceLimits,
                role: Some(Role::A),
                passed: true,
                attempts: 1,
                denials: 1,
            });
        }
        Ok(observations)
    })();
    let targets = workers
        .iter()
        .map(|worker| &worker.process)
        .chain(descendants.iter())
        .collect::<Vec<_>>();
    let attest_kill = matches!(
        scenario,
        Scenario::PidsLimit | Scenario::DetachedGrandchild | Scenario::CgroupKillNoop
    );
    let live_before = if attest_kill {
        targets.iter().try_fold(true, |alive, process| {
            Ok::<_, Fault>(alive & process.alive()?)
        })
    } else {
        Ok(true)
    };
    // Fixed negative fixture: omit the kernel operation entirely. Success of
    // the later fallback must never masquerade as cgroup.kill effectiveness.
    let killed = if scenario == Scenario::CgroupKillNoop {
        Ok(())
    } else {
        group.kill()
    };
    // Observe pidfd death BEFORE sending any leader signal or reaping. If the
    // cgroup operation fails, fallback shutdown still runs but cannot pass.
    let group_stopped = if killed.is_ok() {
        wait_dead(&targets)
    } else {
        Err(Fault::Identity)
    };
    let leaders = if group_stopped.is_ok() {
        Ok(())
    } else {
        workers.iter().try_for_each(|worker| worker.process.kill())
    };
    let reaped = workers.iter().try_for_each(|w| reap(&w.process));
    // Raw stdout/stderr is never public audit. These fields keep capture pipes
    // private and live until termination, including an error path.
    for worker in &workers {
        let _ = &worker.capture;
    }
    killed?;
    leaders?;
    reaped?;
    if !group.empty()? {
        return Err(Fault::Kernel(libc::EBUSY));
    }
    if scenario == Scenario::CgroupKillNoop {
        // Do not let successful fallback mask an earlier payload/identity error.
        result.as_ref().map_err(|fault| *fault)?;
        if descendants.len() != 1 || targets.len() != 4 {
            return Err(Fault::Identity);
        }
        if group_stopped != Err(Fault::Kernel(libc::EBUSY)) || !live_before? {
            return Err(Fault::Identity);
        }
        for target in &targets {
            if target.alive()? {
                return Err(Fault::Identity);
            }
        }
        result = Err(Fault::CgroupKillFailureRecovered);
    } else {
        group_stopped?;
    }
    if attest_kill {
        if !live_before? {
            return Err(Fault::Identity);
        }
        if let Ok(observations) = &mut result {
            observations.push(Observation {
                scenario: Some(scenario),
                check: contract::Check::CgroupKillStopped,
                role: None,
                passed: true,
                attempts: targets.len() as u64,
                denials: 0,
            });
            observations.push(Observation {
                scenario: Some(scenario),
                check: contract::Check::CgroupEmpty,
                role: None,
                passed: true,
                attempts: 1,
                denials: 0,
            });
        }
    }
    if scenario == Scenario::MemoryOom {
        if let Ok(observations) = &mut result {
            for (check, attempts) in [
                (contract::Check::RolesReaped, 3),
                (contract::Check::CgroupEmpty, 1),
            ] {
                observations.push(Observation {
                    scenario: Some(scenario),
                    check,
                    role: None,
                    passed: true,
                    attempts,
                    denials: 0,
                });
            }
        }
    }
    if !descendants.is_empty() {
        for descendant in &descendants {
            if descendant.alive()? {
                return Err(Fault::Identity);
            }
        }
        if let Ok(observations) = &mut result {
            observations.push(Observation {
                scenario: Some(scenario),
                check: contract::Check::DescendantsKilled,
                role: Some(Role::A),
                passed: true,
                attempts: descendants.len() as u64,
                denials: 0,
            });
        }
    }
    if matches!(
        result,
        Err(Fault::ForeignReady | Fault::LibraryRejected(_) | Fault::CgroupKillFailureRecovered)
    ) || (scenario.lifecycle()
        && !scenario.output_flood()
        && matches!(result, Err(Fault::LifecycleDetected(_))))
    {
        // Payload entry writes a fixed stderr marker only AFTER Go. Do not
        // publish any bytes. Reject both discarded bytes and unread pipe bytes.
        for worker in &workers {
            if worker.capture.counts() != [0, 0] {
                return Err(Fault::Identity);
            }
            for stream in 0..2 {
                let mut count = 0_i32;
                if unsafe { libc::ioctl(worker.capture.fd(stream), libc::FIONREAD, &mut count) }
                    != 0
                    || count != 0
                {
                    return Err(Fault::Identity);
                }
            }
        }
    }
    result
}

fn handoff_selftest(guard: &super::guard::Guard) -> Result<super::watchdog::Status, Fault> {
    let (mut watch, mut group) = super::watchdog::Watchdog::start(guard)?;
    group.disarm();
    drop(group); // The parent cannot mutate a Group after the handoff command.
    watch.relinquish()?;
    let status = watch.status().ok_or(Fault::Identity)?;
    if status.reason != super::watchdog::Reason::Relinquish
        || status.transition != super::watchdog::Transition::Recovered
        || status.owner_dead
        || super::lease::pulse() != Err(Fault::LeaseUnavailable)
        || Path::new(RUN).exists()
        || Path::new(super::cgroup::ROOT).exists()
    {
        return Err(Fault::Identity);
    }
    Ok(status)
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
    let run_started = Instant::now();
    let mut active_scenario = None;
    let mut run_lock = None;
    let mut phase = "entry";
    let mut watchdog = None;
    let mut run_guard = None;
    let mut handoff_status = None;
    let mut result = (|| {
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
        phase = "run_guard";
        run_guard = Some(super::guard::Guard::acquire()?);
        phase = "run_lock";
        os::private_directory(Path::new(RUN))?;
        run_lock = Some(
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(RUN)?,
        );
        phase = "watchdog";
        handoff_status = Some(handoff_selftest(
            run_guard.as_ref().ok_or(Fault::Identity)?,
        )?);
        // A fresh run identity follows acknowledged recovery. The serialization
        // guard remains held throughout both guardian generations.
        os::private_directory(Path::new(RUN))?;
        run_lock = Some(
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(RUN)?,
        );
        phase = "watchdog";
        let (watch, mut group) =
            super::watchdog::Watchdog::start(run_guard.as_ref().ok_or(Fault::Identity)?)?;
        watchdog = Some(watch);
        watchdog.as_ref().ok_or(Fault::Identity)?.write_metadata()?;
        // Stable regression coverage even when a faster host completes the
        // functional cases before the former fixed 90-second deadline.
        let lease_test_until = Instant::now() + Duration::from_secs(95);
        phase = "cgroup";
        let mut canary = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(Path::new(RUN).join("fd.canary"))?;
        canary.write_all(b"dummy-fd-canary")?;
        drop(canary);
        let mut observed = (|| {
            active_scenario = Some(Scenario::Baseline);
            let mut observed = baseline(&code, &libraries, &group, &mut phase, Scenario::Baseline)?;
            observed.push(Observation {
                scenario: None,
                check: contract::Check::WatchdogHandoff,
                role: None,
                passed: true,
                attempts: 1,
                denials: 0,
            });
            for role in Role::ALL {
                fs::remove_dir(Path::new(RUN).join(role.name()))?;
            }
            active_scenario = Some(Scenario::ForeignReady);
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
            for scenario in Scenario::LIBRARY_FAULTS {
                active_scenario = Some(scenario);
                for role in Role::ALL {
                    fs::remove_dir(Path::new(RUN).join(role.name()))?;
                }
                match baseline(&code, &libraries, &group, &mut phase, scenario) {
                    Err(Fault::LibraryRejected(rejected)) if rejected == scenario => {
                        observed.push(Observation {
                            scenario: Some(scenario),
                            check: contract::Check::LibraryFaultRejected,
                            role: Some(Role::A),
                            passed: true,
                            attempts: 1,
                            denials: 1,
                        })
                    }
                    Err(error) => return Err(error),
                    Ok(_) => return Err(Fault::Identity),
                }
            }
            for scenario in Scenario::RESOURCES {
                active_scenario = Some(scenario);
                for role in Role::ALL {
                    fs::remove_dir(Path::new(RUN).join(role.name()))?;
                }
                observed.extend(baseline(&code, &libraries, &group, &mut phase, scenario)?);
            }
            for role in Role::ALL {
                fs::remove_dir(Path::new(RUN).join(role.name()))?;
            }
            active_scenario = Some(Scenario::CgroupKillNoop);
            match baseline(
                &code,
                &libraries,
                &group,
                &mut phase,
                Scenario::CgroupKillNoop,
            ) {
                Err(Fault::CgroupKillFailureRecovered) => {
                    for (check, attempts) in [
                        (contract::Check::CgroupKillFailureDetected, 1),
                        (contract::Check::RolesReaped, 3),
                        (contract::Check::CgroupEmpty, 1),
                    ] {
                        observed.push(Observation {
                            scenario: Some(Scenario::CgroupKillNoop),
                            check,
                            role: None,
                            passed: true,
                            attempts,
                            denials: 0,
                        });
                    }
                }
                Err(error) => return Err(error),
                Ok(_) => return Err(Fault::Identity),
            }
            for scenario in Scenario::LIFECYCLE {
                active_scenario = Some(scenario);
                for role in Role::ALL {
                    fs::remove_dir(Path::new(RUN).join(role.name()))?;
                }
                let expected = Fault::LifecycleDetected(scenario);
                match baseline(&code, &libraries, &group, &mut phase, scenario) {
                    Err(fault) if fault == expected => {
                        observed.push(Observation {
                            scenario: Some(scenario),
                            check: if scenario == Scenario::ReportTimeout {
                                contract::Check::ReportTimeoutDetected
                            } else if scenario == Scenario::ReportEof {
                                contract::Check::ReportEofDetected
                            } else {
                                contract::Check::OutputLimitDetected
                            },
                            role: Some(if scenario.output_flood() {
                                scenario.output_target().0
                            } else {
                                Role::A
                            }),
                            passed: true,
                            attempts: 1,
                            denials: 1,
                        });
                        if scenario.output_flood() {
                            observed.push(Observation {
                                scenario: Some(scenario),
                                check: contract::Check::OutputCaptureBounded,
                                role: Some(if scenario.output_flood() {
                                    scenario.output_target().0
                                } else {
                                    Role::A
                                }),
                                passed: true,
                                attempts: 1,
                                denials: 0,
                            });
                        }
                        observed.push(Observation {
                            scenario: Some(scenario),
                            check: contract::Check::RolesReaped,
                            role: None,
                            passed: true,
                            attempts: 3,
                            denials: 0,
                        });
                        observed.push(Observation {
                            scenario: Some(scenario),
                            check: contract::Check::CgroupEmpty,
                            role: None,
                            passed: true,
                            attempts: 1,
                            denials: 0,
                        });
                    }
                    Err(error) => return Err(error),
                    Ok(_) => return Err(Fault::Identity),
                }
            }
            for scenario in Scenario::INJECTIONS {
                active_scenario = Some(scenario);
                for role in Role::ALL {
                    fs::remove_dir(Path::new(RUN).join(role.name()))?;
                }
                observed.extend(baseline(&code, &libraries, &group, &mut phase, scenario)?);
            }
            Ok(observed)
        })();
        if let Ok(observations) = &mut observed {
            phase = "watchdog_long_lease";
            while Instant::now() < lease_test_until {
                super::lease::pulse()?;
                std::thread::sleep(Duration::from_millis(25));
            }
            if !group.empty()? {
                return Err(Fault::Identity);
            }
            observations.push(Observation {
                scenario: None,
                check: contract::Check::WatchdogLeaseRenewed,
                role: None,
                passed: true,
                attempts: 1,
                denials: 0,
            });
        }
        group.cleanup()?;
        let observed = observed?;
        Ok((code.sha256, observed))
    })();
    // No payload can exist before Watchdog::start returns ownership. Even if
    // a foreign cgroup exists, release our own empty RUN without touching it.
    let mut early_cleanup_failed = false;
    if watchdog.is_none()
        && phase == "watchdog"
        && !matches!(result, Err(Fault::GuardianUnconfirmed))
    {
        if let Some(lock) = &run_lock {
            match os::remove_owned_empty_directory(Path::new(RUN), lock) {
                Ok(()) => (),
                Err(_) => {
                    early_cleanup_failed = true;
                    result = Err(Fault::RunCleanup);
                }
            }
        }
    }
    let mut kernel_removed = !Path::new(super::cgroup::ROOT).exists();
    let mut watchdog_fault = None;
    let mut watch_finished = watchdog.is_none();
    if let Some(watch) = &mut watchdog {
        // All Group handles have been dropped by the result closure. A
        // relinquish therefore permanently hands off every remaining object.
        let completed = if kernel_removed {
            let cleanup = (|| {
                super::lease::pulse()?;
                if let Some(lock) = &run_lock {
                    let current = fs::symlink_metadata(RUN)?;
                    let pinned = lock.metadata()?;
                    if (current.dev(), current.ino()) != (pinned.dev(), pinned.ino()) {
                        return Err(Fault::Identity);
                    }
                    fs::remove_dir_all(RUN)?;
                }
                Ok::<_, Fault>(())
            })();
            if cleanup.is_ok() {
                watch.finish()
            } else {
                result = Err(Fault::RunCleanup);
                watch.relinquish()
            }
        } else {
            watch.relinquish()
        };
        match completed {
            Ok(()) => watch_finished = true,
            Err(fault) => watchdog_fault = Some(fault),
        }
        kernel_removed = !Path::new(super::cgroup::ROOT).exists();
    }
    if result.is_ok() && watchdog_fault.is_some() {
        phase = "watchdog_finish";
        result = Err(watchdog_fault.unwrap_or(Fault::Identity));
    }
    let watchdog_status = watchdog.as_ref().and_then(|watch| watch.status());
    let terminal_confirmed = if watchdog.is_some() {
        matches!(
            watchdog_status,
            Some(super::watchdog::Status {
                reason: super::watchdog::Reason::ExplicitDone,
                transition: super::watchdog::Transition::Released,
                ..
            }) | Some(super::watchdog::Status {
                reason: super::watchdog::Reason::Relinquish,
                transition: super::watchdog::Transition::Recovered,
                ..
            })
        ) && watch_finished
    } else {
        // Failed startup may release its empty RUN only after the guardian
        // has been reaped. An unconfirmed guardian can create resources later.
        !matches!(result, Err(Fault::GuardianUnconfirmed))
    };
    let removed =
        !early_cleanup_failed && kernel_removed && terminal_confirmed && !Path::new(RUN).exists();
    let watchdog_exit = if let Some(Fault::Child(value)) = watchdog_fault {
        Some(value)
    } else {
        None
    };
    let (watchdog_signal, watchdog_core_dumped) =
        if let Some(Fault::ChildSignal(signal, core)) = watchdog_fault {
            (Some(signal), Some(core))
        } else {
            (None, None)
        };
    match result {
        Ok((hash, observations)) if removed => {
            // Remaining lifecycle/resource/fault gates are not yet complete.
            // Never advertise these observations as M1 completion.
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"status":"incomplete",
                "formal_eligible":false,"model_launched":false,"code_sha256":hash,
                "checks":observations,"resources_removed":true,"watchdog_status":watchdog_status,"handoff_status":handoff_status})
            );
            std::process::ExitCode::from(1)
        }
        Err(fault) => {
            let child_exit = if let Fault::Child(value) = fault {
                Some(value)
            } else {
                None
            };
            let (child_signal, child_core_dumped) = if let Fault::ChildSignal(signal, core) = fault
            {
                (Some(signal), Some(core))
            } else {
                (None, None)
            };
            let (output_role, output_stream) = if let Fault::OutputLimit(role, stream) = fault {
                (Some(role), Some(stream))
            } else {
                (None, None)
            };
            let reason = match fault {
                Fault::Identity => "identity",
                Fault::LeaseUnavailable => "watchdog_lease_unavailable",
                Fault::WatchdogRecovery => "watchdog_recovery_failed",
                Fault::GuardianUnconfirmed => "watchdog_guardian_unconfirmed",
                Fault::GuardianStartupStopped => "watchdog_startup_failed",
                Fault::Ownership => "ownership",
                Fault::Path => "path",
                Fault::Seal => "seal",
                Fault::Kernel(_) => "kernel",
                Fault::Child(_) => "child_exit",
                Fault::ChildSignal(_, _) => "child_signal",
                Fault::OutputLimit(_, _) => "output_limit",
                Fault::LifecycleDetected(_) => "lifecycle_detected",
                Fault::Bootstrap(_, _) => "bootstrap",
                Fault::ForeignReady => "foreign_ready",
                Fault::RunCleanup => "run_cleanup",
                Fault::ReportTimeout => "report_timeout",
                Fault::ReportEof => "report_eof",
                Fault::CgroupKillFailureRecovered => "cgroup_kill_failure_recovered",
                Fault::LibraryRejected(_) => "library_rejected",
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
                "resources_removed":removed,"phase":phase,"reason":reason,"child_exit":child_exit,
                "child_signal":child_signal,"child_core_dumped":child_core_dumped,
                "output_role":output_role,"output_stream":output_stream,
                "watchdog_exit":watchdog_exit,"watchdog_signal":watchdog_signal,"watchdog_core_dumped":watchdog_core_dumped,
                "watchdog_status":watchdog_status,"handoff_status":handoff_status,"active_scenario":active_scenario,"elapsed_ms":run_started.elapsed().as_millis().min(3_600_000) as u64})
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
