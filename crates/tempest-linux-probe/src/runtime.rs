//! Single-threaded fixed probe supervisor. No Command/shell execution.
use super::{
    ancillary, capsule,
    cgroup::Group,
    contract::{self, Identity, Observation, Role},
    identity::{self, Process},
    os::{self, Fault, Snapshot},
    worker::{Event, Manifest, Phase},
};
use std::{
    fs::{self, File},
    io,
    os::{
        fd::{AsRawFd, OwnedFd, RawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
    time::{Duration, Instant},
};

const RUN: &str = "/run/tempest-linux-isolation-probe";
const OVERALL: Duration = Duration::from_secs(30);

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

fn baseline(
    code: &Snapshot,
    libraries: &[Snapshot],
    group: &Group,
    phase: &mut &'static str,
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
            let state = worker.process.observe(group, worker.role)?;
            if ready.role != worker.role
                || ready.phase != Phase::Ready
                || !ready.checks.is_empty()
                || !contract::ready(worker.role, &worker.expected, &state, &nonce, &ready.nonce)
            {
                return Err(Fault::Identity);
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
            let state = worker.process.observe(group, worker.role)?;
            if !contract::ready(worker.role, &worker.expected, &state, &nonce, &nonce) {
                return Err(Fault::Identity);
            }
        }
        *phase = "barrier";
        for worker in &workers {
            worker.start.send(b"G")?;
        }
        *phase = "payload";
        let mut observations = Vec::new();
        for worker in &workers {
            let done = event(worker, until)?;
            if done.role != worker.role
                || done.nonce != nonce
                || done.phase != Phase::Done
                || done.checks.is_empty()
                || !done
                    .checks
                    .iter()
                    .all(|check| check.passed && check.role == Some(worker.role))
            {
                return Err(Fault::Identity);
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
        watchdog = Some(super::watchdog::Watchdog::start()?);
        phase = "cgroup";
        let mut group = Group::create()?;
        let observed = baseline(&code, &libraries, &group, &mut phase);
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
