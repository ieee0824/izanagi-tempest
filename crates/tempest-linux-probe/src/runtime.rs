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
    io::{self, Read, Write},
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
    record: super::registry::RecordId,
    expected: Identity,
    boot: Channel,
    start: Channel,
    report: OwnedFd,
    capture: Capture,
}

// The guardian owns error cleanup after the normal path ends. Explicitly
// disarm before the inner Group is dropped; a failed Drop is not a handoff.
struct ParentGroup(Group);
impl std::ops::Deref for ParentGroup {
    type Target = Group;
    fn deref(&self) -> &Group {
        &self.0
    }
}
impl std::ops::DerefMut for ParentGroup {
    fn deref_mut(&mut self) -> &mut Group {
        &mut self.0
    }
}
impl Drop for ParentGroup {
    fn drop(&mut self) {
        self.0.disarm();
    }
}

struct SpawnSpec<'a> {
    role: Role,
    scenario: Scenario,
    ipc: &'a [(RawFd, RawFd)],
}

fn code_identity(code: &Snapshot) -> Result<(u64, u64), Fault> {
    let metadata = fs::metadata(format!("/proc/self/fd/{}", code.fd()))?;
    Ok((metadata.dev(), metadata.ino()))
}

fn write_event(channel: &Channel, manifest: &Manifest) -> Result<(), Fault> {
    let bytes = serde_json::to_vec(manifest).map_err(|_| Fault::Identity)?;
    channel.send(&bytes)
}

fn progress(scenario: Scenario, phase: &'static str) -> Result<(), Fault> {
    let value = serde_json::to_vec(&serde_json::json!({"scenario":scenario,"phase":phase}))
        .map_err(|_| Fault::Identity)?;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(Path::new(RUN).join("progress"))?
        .write_all(&value)?;
    Ok(())
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
        }; 8];
        polls[0].fd = worker.report.as_raw_fd();
        polls[1 + peers.len() * 2].fd = super::lease::guardian_fd();
        for (peer_index, peer) in peers.iter().enumerate() {
            for stream in 0..2 {
                polls[1 + peer_index * 2 + stream].fd = peer.capture.poll_fd(stream);
            }
        }
        let result = unsafe {
            libc::poll(
                polls.as_mut_ptr(),
                (2 + peers.len() * 2) as libc::nfds_t,
                10,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error().into());
        }
        super::lease::pulse()?;
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
    spec: SpawnSpec<'_>,
    code: &Snapshot,
    libraries: &[Snapshot],
    null: &File,
    group: &Group,
    registry: &mut super::registry::Registry,
) -> Result<Worker, Fault> {
    let SpawnSpec {
        role,
        scenario,
        ipc,
    } = spec;
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
    let mut record = None;
    let bound = (|| {
        let process = Process::bind(pid as u32)?;
        let id = registry.track(role, &process, true)?;
        record = Some(id);
        group.attach(role, process.pid)?;
        registry.attached(id)?;
        let mut expected = process.identity()?;
        expected.code = code_identity(code)?;
        Ok((process, expected, id))
    })();
    let (process, expected, record) = match bound {
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
                    if !libc::WIFEXITED(status) && !libc::WIFSIGNALED(status) {
                        return Err(Fault::Identity);
                    }
                    if let Some(id) = record {
                        registry.reaped(id)?;
                    }
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
        record,
        expected,
        boot,
        start,
        report: report.read,
        capture,
    })
}

fn reap(
    process: &Process,
    record: super::registry::RecordId,
    registry: &mut super::registry::Registry,
) -> Result<(), Fault> {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        super::lease::pulse()?;
        let mut status = 0;
        let value = unsafe { libc::waitpid(process.pid as i32, &mut status, libc::WNOHANG) };
        if value == process.pid as i32 {
            if !libc::WIFEXITED(status) && !libc::WIFSIGNALED(status) {
                return Err(Fault::Identity);
            }
            registry.reaped(record)?;
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
    registry: &mut super::registry::Registry,
    primary_fault: &mut Option<&'static str>,
) -> Result<Vec<Observation>, Fault> {
    *primary_fault = None;
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
    let mut state_records = None;
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
            workers.push(spawn(
                SpawnSpec {
                    role,
                    scenario,
                    ipc: &ipc,
                },
                code,
                libraries,
                &null,
                group,
                registry,
            )?);
        }
        if matches!(scenario, Scenario::StateRun1 | Scenario::StateRun2) {
            let records = workers
                .iter()
                .map(|worker| worker.record)
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| Fault::Identity)?;
            registry.state_sequence.begin(
                if scenario == Scenario::StateRun1 {
                    1
                } else {
                    2
                },
                nonce,
                records,
            )?;
            state_records = Some(records);
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
        progress(scenario, "barrier")?;
        for worker in &workers {
            worker.start.send(b"G")?;
        }
        *phase = "payload";
        progress(scenario, "payload")?;
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
        progress(scenario, "collector")?;
        let mut observations = Vec::new();
        if matches!(scenario, Scenario::StateRun1 | Scenario::StateRun2) {
            for worker in &workers {
                let written = event(worker, until, &workers)?;
                if written.role != worker.role
                    || written.nonce != nonce
                    || written.phase != Phase::StateWritten
                    || written.bootstrap.is_some()
                    || written.library_fault.is_some()
                    || written.rejection.is_some()
                    || written.checks.len() != 4
                    || !written
                        .checks
                        .iter()
                        .zip([
                            contract::Check::HostHomeDenied,
                            contract::Check::PrivateHomeReadable,
                            contract::Check::PreviousStateAbsent,
                            contract::Check::StateMarkerCreated,
                        ])
                        .all(|(value, check)| {
                            value.check == check
                                && value.passed
                                && value.role == Some(worker.role)
                                && value.scenario.is_none()
                        })
                {
                    return Err(Fault::Identity);
                }
                let state = worker
                    .process
                    .observe(group, worker.role, &worker.descriptors)?;
                if !contract::ready(worker.role, &worker.expected, &state, &nonce, &nonce) {
                    return Err(Fault::Identity);
                }
                // The proc root is intentionally followed only for the already
                // PIDFD-bound live child. All subsequent traversal uses dirfds.
                let root = File::open(format!("/proc/{}/root", worker.process.pid))?;
                let state_fd = unsafe {
                    libc::openat(
                        root.as_raw_fd(),
                        c"state".as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if state_fd < 0 {
                    return Err(io::Error::last_os_error().into());
                }
                let directory =
                    unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(state_fd) };
                let marker_fd = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        c"marker".as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if marker_fd < 0 {
                    return Err(io::Error::last_os_error().into());
                }
                let mut marker =
                    unsafe { <File as std::os::fd::FromRawFd>::from_raw_fd(marker_fd) };
                let metadata = marker.metadata()?;
                let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
                os::syscall(unsafe { libc::fstatfs(marker.as_raw_fd(), filesystem.as_mut_ptr()) })?;
                let filesystem = unsafe { filesystem.assume_init() };
                let mut mount = std::mem::MaybeUninit::<libc::statx>::zeroed();
                os::syscall(unsafe {
                    libc::statx(
                        marker.as_raw_fd(),
                        c"".as_ptr(),
                        libc::AT_EMPTY_PATH,
                        libc::STATX_MNT_ID | libc::STATX_INO,
                        mount.as_mut_ptr(),
                    )
                })?;
                let mount = unsafe { mount.assume_init() };
                let mut content = Vec::new();
                Read::by_ref(&mut marker)
                    .take(17)
                    .read_to_end(&mut content)?;
                let mut after = std::mem::MaybeUninit::<libc::statx>::zeroed();
                os::syscall(unsafe {
                    libc::statx(
                        marker.as_raw_fd(),
                        c"".as_ptr(),
                        libc::AT_EMPTY_PATH,
                        libc::STATX_MNT_ID | libc::STATX_INO,
                        after.as_mut_ptr(),
                    )
                })?;
                let after = unsafe { after.assume_init() };
                let after_metadata = marker.metadata()?;
                if content != nonce
                    || after.stx_mask & (libc::STATX_MNT_ID | libc::STATX_INO)
                        != (libc::STATX_MNT_ID | libc::STATX_INO)
                    || (after.stx_mnt_id, after.stx_ino) != (mount.stx_mnt_id, mount.stx_ino)
                    || (
                        after_metadata.dev(),
                        after_metadata.ino(),
                        after_metadata.len(),
                    ) != (metadata.dev(), metadata.ino(), 16)
                    || filesystem.f_type != libc::TMPFS_MAGIC
                    || mount.stx_mask & (libc::STATX_MNT_ID | libc::STATX_INO)
                        != (libc::STATX_MNT_ID | libc::STATX_INO)
                    || mount.stx_mnt_id == 0
                    || mount.stx_ino != metadata.ino()
                    || !metadata.is_file()
                    || metadata.uid() != worker.role.uid()
                    || metadata.mode() & 0o777 != 0o600
                    || !worker.process.alive()?
                {
                    return Err(Fault::Identity);
                }
                drop(marker);
                drop(directory);
                drop(root);
                for mut value in written.checks {
                    value.scenario = Some(scenario);
                    observations.push(value);
                }
                observations.push(Observation {
                    scenario: Some(scenario),
                    check: contract::Check::StateMarkerObserved,
                    role: Some(worker.role),
                    passed: true,
                    attempts: 1,
                    denials: 0,
                });
                worker.start.send(b"G")?;
            }
        }
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
            // Preserve the observed collector fault before lifecycle checks
            // translate it or a later identity/cleanup operation can fail.
            if primary_fault.is_none() {
                *primary_fault = received.as_ref().err().map(|fault| fault.reason());
            }
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
                registry.track(Role::A, &process, false)?;
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
            registry.track(Role::A, &descendant, false)?;
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
    if primary_fault.is_none() {
        *primary_fault = result.as_ref().err().map(|fault| fault.reason());
    }
    // Leave the live target ledger intact for the exclusive recovery path.
    // Killing namespace leaders here could erase unobserved descendants
    // before RecoveryGroup takes its bounded PIDFD snapshot.
    super::lease::pulse()?;
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
    let reaped = workers
        .iter()
        .try_for_each(|w| reap(&w.process, w.record, registry));
    // Raw stdout/stderr is never public audit. These fields keep capture pipes
    // private and live until termination, including an error path.
    for worker in &workers {
        let _ = &worker.capture;
    }
    killed?;
    leaders?;
    reaped?;
    registry.finish()?;
    if !group.empty()? {
        return Err(Fault::Kernel(libc::EBUSY));
    }
    if let Some(records) = state_records {
        // Channels remain owned by Worker until dropped. Verify all PIDFDs
        // before releasing them, then remove only the fixed empty host roots.
        let dead = workers.iter().try_fold(true, |dead, worker| {
            Ok::<_, Fault>(dead && !worker.process.alive()?)
        })?;
        result.as_ref().map_err(|fault| *fault)?;
        group_stopped?;
        drop(targets);
        drop(workers);
        let socket_fds = [a.as_raw_fd(), b.as_raw_fd(), ga.as_raw_fd(), gb.as_raw_fd()];
        drop(a);
        drop(b);
        drop(ga);
        drop(gb);
        drop(to_a);
        drop(to_b);
        for fd in socket_fds {
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1
                || io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
            {
                return Err(Fault::Identity);
            }
        }
        // Children have no descendants in these fixed scenarios. Their dead,
        // reaped namespace leaders and closed observer FDs release the private
        // mounts. Also reject any accidental mount in the host namespace.
        let mounts = fs::read_to_string("/proc/self/mountinfo")?;
        if mounts.lines().any(|line| {
            line.split_whitespace().nth(4).is_some_and(|path| {
                Role::ALL.iter().any(|role| {
                    let root = format!("{RUN}/{}", role.name());
                    path == root || path.starts_with(&format!("{root}/"))
                })
            })
        }) {
            return Err(Fault::Identity);
        }
        for role in Role::ALL {
            let path = Path::new(RUN).join(role.name());
            fs::remove_dir(&path)?;
            if !fs::symlink_metadata(&path)
                .is_err_and(|error| error.raw_os_error() == Some(libc::ENOENT))
            {
                return Err(Fault::Identity);
            }
        }
        registry
            .state_sequence
            .finish(nonce, records, dead && group.empty()?)?;
        if let Ok(values) = &mut result {
            for check in [
                contract::Check::StateGenerationBound,
                contract::Check::StateCleanupComplete,
            ] {
                values.push(Observation {
                    scenario: Some(scenario),
                    check,
                    role: None,
                    passed: true,
                    attempts: 3,
                    denials: 0,
                });
            }
        }
        return result;
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
    // The caller decides whether an expected negative result is accepted.
    // Preserve an observed fault when validation failed even if cleanup worked.
    if result.is_ok() {
        *primary_fault = None;
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
    let mut registry = super::registry::Registry::default();
    let mut first_fault = None;
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
        let (watch, group) =
            super::watchdog::Watchdog::start(run_guard.as_ref().ok_or(Fault::Identity)?)?;
        let mut group = ParentGroup(group);
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
            let mut state_observed = Vec::new();
            let home_path = Path::new(RUN).join("host-home");
            os::private_directory(&home_path)?;
            let home = File::open(&home_path)?;
            let mut home_identities = Vec::new();
            for category in super::worker::HOME_CATEGORIES {
                let path = home_path.join(category);
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)?;
                file.write_all(b"dummy-host-home")?;
                drop(file);
                let file = File::open(format!("/proc/self/fd/{}/{category}", home.as_raw_fd()))?;
                let metadata = file.metadata()?;
                home_identities.push((metadata.dev(), metadata.ino()));
                let mut content = Vec::new();
                file.take(16).read_to_end(&mut content)?;
                if content != b"dummy-host-home"
                    || !metadata.is_file()
                    || metadata.uid() != 0
                    || metadata.mode() & 0o777 != 0o600
                {
                    return Err(Fault::Identity);
                }
            }
            if unsafe { libc::fcntl(40, libc::F_GETFD) } != -1
                || io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
            {
                return Err(Fault::Identity);
            }
            os::syscall(unsafe { libc::dup3(home.as_raw_fd(), 40, libc::O_CLOEXEC) })?;
            let inherited_home = unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(40) };
            state_observed.push(Observation {
                scenario: None,
                check: contract::Check::HostHomeReadable,
                role: None,
                passed: true,
                attempts: 9,
                denials: 0,
            });
            for scenario in [Scenario::StateRun1, Scenario::StateRun2] {
                active_scenario = Some(scenario);
                let verify_home = || -> Result<(), Fault> {
                    for (category, identity) in
                        super::worker::HOME_CATEGORIES.iter().zip(&home_identities)
                    {
                        let file =
                            File::open(format!("/proc/self/fd/{}/{category}", home.as_raw_fd()))?;
                        let metadata = file.metadata()?;
                        let mut content = Vec::new();
                        file.take(16).read_to_end(&mut content)?;
                        if content != b"dummy-host-home"
                            || !metadata.is_file()
                            || metadata.uid() != 0
                            || metadata.mode() & 0o777 != 0o600
                            || (metadata.dev(), metadata.ino()) != *identity
                        {
                            return Err(Fault::Identity);
                        }
                    }
                    Ok(())
                };
                verify_home()?;
                state_observed.extend(baseline(
                    &code,
                    &libraries,
                    &group,
                    &mut phase,
                    scenario,
                    &mut registry,
                    &mut first_fault,
                )?);
                verify_home()?;
                state_observed.push(Observation {
                    scenario: Some(scenario),
                    check: contract::Check::HostHomeReadable,
                    role: None,
                    passed: true,
                    attempts: 18,
                    denials: 0,
                });
            }
            drop(inherited_home);
            drop(home);
            active_scenario = Some(Scenario::Baseline);
            let mut observed = baseline(
                &code,
                &libraries,
                &group,
                &mut phase,
                Scenario::Baseline,
                &mut registry,
                &mut first_fault,
            )?;
            observed.extend(state_observed);
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
                &mut registry,
                &mut first_fault,
            ) {
                Err(Fault::ForeignReady) => {
                    first_fault = None;
                    observed.push(Observation {
                        scenario: Some(Scenario::ForeignReady),
                        check: contract::Check::ForeignReadyRejected,
                        role: Some(Role::A),
                        passed: true,
                        attempts: 1,
                        denials: 1,
                    });
                }
                Err(error) => return Err(error),
                Ok(_) => return Err(Fault::Identity),
            }
            for scenario in Scenario::LIBRARY_FAULTS {
                active_scenario = Some(scenario);
                for role in Role::ALL {
                    fs::remove_dir(Path::new(RUN).join(role.name()))?;
                }
                match baseline(
                    &code,
                    &libraries,
                    &group,
                    &mut phase,
                    scenario,
                    &mut registry,
                    &mut first_fault,
                ) {
                    Err(Fault::LibraryRejected(rejected)) if rejected == scenario => {
                        first_fault = None;
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
                observed.extend(baseline(
                    &code,
                    &libraries,
                    &group,
                    &mut phase,
                    scenario,
                    &mut registry,
                    &mut first_fault,
                )?);
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
                &mut registry,
                &mut first_fault,
            ) {
                Err(Fault::CgroupKillFailureRecovered) => {
                    first_fault = None;
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
                match baseline(
                    &code,
                    &libraries,
                    &group,
                    &mut phase,
                    scenario,
                    &mut registry,
                    &mut first_fault,
                ) {
                    Err(fault) if fault == expected => {
                        first_fault = None;
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
                observed.extend(baseline(
                    &code,
                    &libraries,
                    &group,
                    &mut phase,
                    scenario,
                    &mut registry,
                    &mut first_fault,
                )?);
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
        if let Err(error) = &observed {
            if first_fault.is_none() {
                first_fault = Some(error.reason());
            }
        }
        group.cleanup()?;
        let observed = observed?;
        Ok((code.sha256, observed))
    })();
    if first_fault.is_none() {
        first_fault = result.as_ref().err().map(|error| error.reason());
    }
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
    let mut parent_recovery_status = None;
    if let Some(watch) = &mut watchdog {
        if let (Some(guard), Some(pinned)) = (&run_guard, &run_lock) {
            parent_recovery_status = watch.parent_recovery(guard, pinned, &mut registry, false);
        }
        if parent_recovery_status.is_none() {
            // ParentGroup is already disarmed/dropped. A sent command leaves
            // ownership with the guardian for its entire remaining lifetime.
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
            if let Err(fault) = completed {
                watchdog_fault = Some(fault);
            }
            if let (Some(guard), Some(pinned)) = (&run_guard, &run_lock) {
                parent_recovery_status =
                    watch.parent_recovery(guard, pinned, &mut registry, completed.is_err());
            }
        }
        if let Some(statuses) = &parent_recovery_status {
            let terminal = statuses.last().map(|status| status.transition);
            watch_finished = matches!(
                terminal,
                Some(
                    super::watchdog::ParentTransition::Recovered
                        | super::watchdog::ParentTransition::Verified
                )
            );
            if terminal != Some(super::watchdog::ParentTransition::Verified) {
                result = Err(Fault::GuardianDied);
            }
        }
        kernel_removed = !Path::new(super::cgroup::ROOT).exists();
    }
    if result.is_ok() && watchdog_fault.is_some() {
        phase = "watchdog_finish";
        result = Err(watchdog_fault.unwrap_or(Fault::Identity));
    }
    let watchdog_status = watchdog.as_ref().and_then(|watch| watch.status());
    let guardian_alive = watchdog.as_ref().and_then(|watch| watch.guardian_alive());
    let terminal_confirmed = if watchdog.is_some() {
        parent_recovery_status.as_ref().is_some_and(|statuses| {
            statuses.last().is_some_and(|status| {
                matches!(
                    status.transition,
                    super::watchdog::ParentTransition::Recovered
                        | super::watchdog::ParentTransition::Verified
                )
            })
        }) && watch_finished
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
                "checks":observations,"resources_removed":true,"watchdog_status":watchdog_status,"handoff_status":handoff_status,"parent_recovery_status":parent_recovery_status,"guardian_alive":guardian_alive})
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
            let reason = fault.reason();
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
                "watchdog_status":watchdog_status,"handoff_status":handoff_status,"parent_recovery_status":parent_recovery_status,"guardian_alive":guardian_alive,"first_fault":first_fault,"active_scenario":active_scenario,"elapsed_ms":run_started.elapsed().as_millis().min(3_600_000) as u64})
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
