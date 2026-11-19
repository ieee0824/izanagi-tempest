//! Internal dummy route contract prototype. No launcher authority or OS backend.
use serde_json::Value;
use std::{
    collections::BTreeSet,
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
    time::{Duration, Instant},
};

// The reviewed build must be staged beneath a root-owned, non-writable path
// before Snapshot::trusted can consume it. The build output under /tmp is not
// an executable source for this fixture.
const IZANAGI_MCP_ARTIFACT: &str = "/usr/local/libexec/tempest/izanagi-mcp-fixture";
const IZANAGI_MCP_SHA256: &str = "088a5ca1fcf6f78501fabb329ff41a6318935e4971d86ef23e98626df5c3b0f8";

const MCP_UID: u32 = 62004;

pub(super) struct FixedMcpArtifact {
    executable: super::os::Snapshot,
    libraries: Vec<super::os::Snapshot>,
}

impl FixedMcpArtifact {
    pub(super) fn open() -> Result<Self, super::os::Fault> {
        let snapshot = super::os::Snapshot::trusted(std::path::Path::new(IZANAGI_MCP_ARTIFACT))?;
        if snapshot.sha256 != IZANAGI_MCP_SHA256 {
            return Err(super::os::Fault::Identity);
        }
        Ok(Self {
            executable: snapshot,
            libraries: fixed_mcp_libraries()?,
        })
    }

    /// Return the original child PID while it waits for attachment.
    /// The caller owns reaping and must send the gate byte only after tracking
    /// the original pidfd and verifying placement in the intended cgroup.
    pub(super) fn spawn_waiting(
        &self,
        root: &std::path::Path,
        stdio: [BorrowedFd<'_>; 3],
        gate: [BorrowedFd<'_>; 2],
        caller_gate_writer: BorrowedFd<'_>,
    ) -> Result<libc::pid_t, super::os::Fault> {
        let parent = super::identity::Process::bind(std::process::id())?;
        let pid = super::os::clone_isolated()?;
        if pid != 0 {
            return Ok(pid);
        }
        super::lease::clear();
        // Neither write end belongs to the MCP child. Close both before
        // waiting so failure can reach the corresponding reader as EOF.
        unsafe {
            libc::close(gate[1].as_raw_fd());
            libc::close(caller_gate_writer.as_raw_fd());
        }
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0
            || !parent.alive().unwrap_or(false)
        {
            unsafe { libc::_exit(125) };
        }
        let mut byte = 0_u8;
        if unsafe { libc::read(gate[0].as_raw_fd(), (&mut byte as *mut u8).cast(), 1) } != 1
            || byte != b'I'
        {
            unsafe { libc::_exit(125) };
        }
        let [stdin, stdout, stderr] = stdio;
        // SAFETY: clone_isolated created the required namespaces and only the
        // supervisor can open the gate after registering and attaching us.
        unsafe { self.exec_mcp(&parent, root, stdin, stdout, stderr) }
    }

    /// Track and attach the original child before releasing its bootstrap.
    /// The supervisor still owns direct-child reaping on every error path.
    pub(super) fn attach_and_start(
        group: &super::cgroup::Group,
        registry: &mut super::registry::Registry,
        role: super::contract::Role,
        process: &super::identity::Process,
        gate: OwnedFd,
    ) -> Result<super::registry::RecordId, super::os::Fault> {
        use std::io::Write;

        let record = track_fresh_child(registry, role, process)?;
        group.attach(role, process.pid)?;
        registry.attached(record)?;
        if !process.alive()? || !group.bound(role, process.pid)? {
            return Err(super::os::Fault::Identity);
        }
        std::fs::File::from(gate).write_all(b"I")?;
        Ok(record)
    }

    /// Execute the pinned ELF with the fixed MCP arguments and a minimal
    /// environment. No pathname is resolved for the executable itself.
    ///
    /// # Safety
    /// The caller must be the dedicated, single-threaded fixture child,
    /// created with CLONE_NEWPID, tracked by the supervisor, and attached
    /// to its cgroup.
    /// Its root directory must be freshly created for this trial.
    /// This function consumes the child's inherited descriptor table.
    unsafe fn exec_mcp(
        &self,
        parent: &super::identity::Process,
        root: &std::path::Path,
        stdin: BorrowedFd<'_>,
        stdout: BorrowedFd<'_>,
        stderr: BorrowedFd<'_>,
    ) -> ! {
        use super::capsule;

        const EXEC_FD: libc::c_int = 6;
        if capsule::prepare_mcp_root(root, &self.libraries).is_err() {
            unsafe { libc::_exit(120) };
        }
        if capsule::drop_privileges(MCP_UID).is_err() {
            unsafe { libc::_exit(121) };
        }
        if !parent.alive().unwrap_or(false) {
            unsafe { libc::_exit(125) };
        }
        let mappings = [
            (stdin.as_raw_fd(), libc::STDIN_FILENO),
            (stdout.as_raw_fd(), libc::STDOUT_FILENO),
            (stderr.as_raw_fd(), libc::STDERR_FILENO),
            (self.executable.fd(), EXEC_FD),
        ];
        if capsule::map_descriptors(&mappings, EXEC_FD).is_err() {
            // The FD table may be partly remapped. Exit without unwinding.
            unsafe { libc::_exit(126) };
        }
        if super::seccomp::install_mcp_stdio().is_err() {
            unsafe { libc::_exit(122) };
        }
        let argv = [c"/izanagi".as_ptr(), c"mcp".as_ptr(), std::ptr::null()];
        let env = [
            c"LANG=C".as_ptr(),
            c"LC_ALL=C".as_ptr(),
            c"TOKIO_WORKER_THREADS=1".as_ptr(),
            std::ptr::null(),
        ];
        // SAFETY: The arrays are NUL terminated and EXEC_FD now names the snapshot.
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                EXEC_FD,
                c"".as_ptr(),
                argv.as_ptr(),
                env.as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        };
        unsafe { libc::_exit(127) };
    }

    /// Wait for the fixed image and a runtime thread before requesting
    /// the freeze. The frozen observation remains the release condition.
    pub(super) fn wait_for_runtime(
        &self,
        child: &super::identity::Process,
        deadline: Instant,
    ) -> Result<(), super::os::Fault> {
        use super::os::Fault;

        let executable = self.executable.identity()?;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Fault::Kernel(libc::ETIMEDOUT));
            }
            if !child.alive()? {
                return Err(child.exited());
            }
            let observed = (|| {
                let identity = child.identity()?;
                if identity.code != executable || child.thread_count()? < 2 {
                    return Ok(false);
                }
                if child.identity()? != identity {
                    return Err(Fault::Identity);
                }
                Ok(true)
            })();
            if !child.alive()? {
                return Err(child.exited());
            }
            if observed? && Instant::now() < deadline {
                return Ok(());
            }
            std::thread::sleep(remaining.min(Duration::from_millis(2)));
        }
    }

    /// Check both workers' pipe endpoints and wait for confirmed thaw.
    fn inspect_before_exchange(
        &self,
        group: &mut super::cgroup::Group,
        guard: &super::guard::Guard,
        workers: [(super::contract::Role, &super::identity::Process); 2],
        ends: [(&super::identity::Descriptor, u32); 2],
        deadline: Instant,
    ) -> Result<(), super::os::Fault> {
        use super::{
            contract::Role,
            holder_scan::{Budget, ManagerPipe, task_pipe_fds},
            os::Fault,
        };

        let [(role, caller), (_, mcp)] = workers;
        if role != Role::B {
            return Err(Fault::Identity);
        }
        let [(stdin, request_fd), (stdout, response_fd)] = ends;
        let pipes = [
            stdin.pipe_identity(libc::O_RDONLY)?,
            stdout.pipe_identity(libc::O_WRONLY)?,
        ];
        let manager = pipes.map(|identity| ManagerPipe {
            identity,
            expected: &[],
        });
        group.inspect_while_frozen(
            guard,
            deadline,
            workers,
            &manager,
            |_| {
                let mut budget = Budget {
                    deadline,
                    bytes_left: 262144,
                    entries_left: 8192,
                };
                self.verify_stdio(mcp, stdin, stdout, &mut budget)?;
                for (pipe, fd, writes) in
                    [(pipes[0], request_fd, true), (pipes[1], response_fd, false)]
                {
                    let observed =
                        task_pipe_fds(std::path::Path::new("/proc"), caller.pid, pipe, &mut budget)
                            .map_err(|_| Fault::Identity)?;
                    if observed
                        != [super::holder_scan::TaskPipeFd {
                            tid: caller.pid,
                            start_ticks: caller.birth,
                            fd,
                            writes,
                        }]
                    {
                        return Err(Fault::Identity);
                    }
                }
                Ok(())
            },
            &(),
        )
    }

    pub(super) fn verify_stdio(
        &self,
        child: &super::identity::Process,
        stdin: &super::identity::Descriptor,
        stdout: &super::identity::Descriptor,
        budget: &mut super::holder_scan::Budget,
    ) -> Result<(), super::os::Fault> {
        use super::{holder_scan::required_task_pipe_fds, os::Fault};

        let executable = self.executable.identity()?;
        let state = child.security_state()?;
        let supervisor = super::identity::namespace_ids(std::process::id())?;
        if state.identity.code != executable
            || state
                .identity
                .namespaces
                .iter()
                .zip(supervisor)
                .any(|(observed, manager)| *observed == manager)
            || state.uid != [MCP_UID; 4]
            || state.gid != [MCP_UID; 4]
            || !state.groups.is_empty()
            || state.capabilities != [0; 5]
            || !state.no_new_privs
            || state.seccomp != 2
        {
            return Err(Fault::Identity);
        }
        verify_mcp_stdio(child, executable, stdin, stdout)?;
        let proc_root = std::path::Path::new("/proc");
        let request_pipe = stdin.pipe_identity(libc::O_RDONLY)?;
        let response_pipe = stdout.pipe_identity(libc::O_WRONLY)?;
        if request_pipe == response_pipe {
            return Err(Fault::Identity);
        }
        let readers = required_task_pipe_fds(proc_root, child.pid, request_pipe, 0, false, budget)
            .map_err(|_| Fault::Identity)?;
        let writers = required_task_pipe_fds(proc_root, child.pid, response_pipe, 1, true, budget)
            .map_err(|_| Fault::Identity)?;
        if readers.len() < 2
            || !readers
                .iter()
                .map(|row| (row.tid, row.start_ticks))
                .eq(writers.iter().map(|row| (row.tid, row.start_ticks)))
        {
            return Err(Fault::Identity);
        }
        verify_mcp_stdio(child, executable, stdin, stdout)
    }
}

#[derive(Default)]
struct ExchangeDiagnostics {
    mcp_stderr: Option<String>,
    caller_wait_status: Option<i32>,
    mcp_wait_status: Option<i32>,
}

/// Explicit fixed-host investigation entry, limited to the local handshake.
pub(super) fn fixed_stdio_trial() -> std::process::ExitCode {
    use super::{cgroup::Group, contract::Role, guard::Guard, os, os::Fault, registry::Registry};
    use std::{fs, path::Path, process::ExitCode};

    let mut counts = super::registry::Counts::default();
    let mut untracked_errno = None;
    let mut trial_reason = None;
    let mut trial_errno = None;
    let mut trial_child_exit = None;
    let mut trial_child_signal = None;
    let mut diagnostics = ExchangeDiagnostics::default();
    let mut phase = "preflight";
    let mut recovery_reason = None;
    let mut root_cleanup_reason = None;
    let result: Result<(), Fault> = (|| {
        if unsafe { libc::geteuid() } != 0 || fs::read_dir("/proc/self/task")?.count() != 1 {
            return Err(Fault::Identity);
        }
        let guard = Guard::acquire()?;
        if !super::runtime::initial_uid_available(Role::B.uid())?
            || !super::runtime::initial_uid_available(MCP_UID)?
        {
            return Err(Fault::Identity);
        }
        let artifact = FixedMcpArtifact::open()?;
        let base = Path::new("/run/tempest-fixed-mcp-stdio");
        os::private_directory(base)?;
        let base_fd = fs::File::open(base)?;
        let roots = [base.join("caller"), base.join("mcp")];
        let mut root_fds = Vec::new();
        let exchange = (|| {
            for root in &roots {
                os::private_directory(root)?;
                root_fds.push(fs::File::open(root)?);
            }
            phase = "cgroup_create";
            let mut group = Group::create()?;
            let mut registry = Registry::default();
            let result = run_fixed_exchange(
                &artifact,
                &mut group,
                &guard,
                &mut registry,
                [&roots[0], &roots[1]],
                Instant::now() + Duration::from_secs(10),
                (&mut phase, &mut diagnostics),
            );
            if let Err(Fault::UntrackedChildCleanup(errno)) = result {
                untracked_errno = Some(errno);
            }
            trial_reason = result.as_ref().err().map(Fault::reason);
            match result {
                Err(Fault::Kernel(errno)) => trial_errno = Some(errno),
                Err(Fault::Child(status)) => trial_child_exit = Some(status),
                Err(Fault::ChildSignal(signal, _)) => trial_child_signal = Some(signal),
                _ => {}
            }
            let recovery = recover_fixed_exchange(&mut group, &mut registry, &mut counts);
            recovery_reason = recovery.as_ref().err().map(Fault::reason);
            recovery?;
            result
        })();
        let mut cleanup = Ok(());
        for (root, fd) in roots.iter().zip(root_fds.iter()).rev() {
            if let Err(error) = os::remove_owned_empty_directory(root, fd) {
                cleanup = Err(error);
            }
        }
        let base_cleanup = os::remove_owned_empty_directory(base, &base_fd);
        let cleanup = cleanup.and(base_cleanup);
        root_cleanup_reason = cleanup.as_ref().err().map(Fault::reason);
        cleanup?;
        exchange
    })();
    let reason = result.as_ref().err().map(Fault::reason);
    println!(
        "{}",
        serde_json::json!({
            "scope": "fixed_mcp_stdio_fixture",
            "passed": result.is_ok(),
            "production_authorized": false,
            "reason": reason,
            "trial_reason": trial_reason,
            "trial_phase": phase,
            "trial_errno": trial_errno,
            "trial_child_exit": trial_child_exit,
            "trial_child_signal": trial_child_signal,
            "mcp_stderr": diagnostics.mcp_stderr,
            "caller_wait_status": diagnostics.caller_wait_status,
            "mcp_wait_status": diagnostics.mcp_wait_status,
            "recovery_reason": recovery_reason,
            "root_cleanup_reason": root_cleanup_reason,
            "untracked_cleanup_errno": untracked_errno,
            "recovery": counts,
        })
    );
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Run the two children in an armed fixture group. The caller supplies
/// fresh roots and retains group recovery ownership on every return path.
fn run_fixed_exchange(
    artifact: &FixedMcpArtifact,
    group: &mut super::cgroup::Group,
    guard: &super::guard::Guard,
    registry: &mut super::registry::Registry,
    roots: [&std::path::Path; 2],
    deadline: Instant,
    diagnostics: (&mut &'static str, &mut ExchangeDiagnostics),
) -> Result<(), super::os::Fault> {
    use super::{contract::Role, identity::Descriptor, os};
    use std::os::fd::AsFd;

    let (phase, diagnostics) = diagnostics;
    *phase = "pipes";
    let [caller_root, mcp_root] = roots;
    let (request_read, request_write) = os::pipe()?;
    let (response_read, response_write) = os::pipe()?;
    let stdin = Descriptor::bind(request_read.as_raw_fd())?;
    let stdout = Descriptor::bind(response_write.as_raw_fd())?;
    let caller_ends = [
        request_write.as_raw_fd() as u32,
        response_read.as_raw_fd() as u32,
    ];
    let (caller_gate, release) = os::pipe()?;
    let (ready, ready_writer) = os::pipe()?;
    let (bootstrap, start) = os::pipe()?;
    let (stderr_read, stderr) = os::pipe()?;
    os::syscall(unsafe { libc::fcntl(stderr_read.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) })?;

    let expected = mcp_stdio_fixture::expected_results();
    *phase = "caller_spawn";
    let caller = bind_fresh_child(spawn_fixed_caller(
        caller_root,
        [caller_gate, request_write, response_read, ready_writer],
        [&expected[0], &expected[1]],
        deadline,
    )?)?;
    *phase = "caller_attach";
    let caller_record = track_fresh_child(registry, Role::B, &caller)?;
    group.attach(Role::B, caller.pid)?;
    registry.attached(caller_record)?;
    *phase = "caller_ready";
    mcp_stdio_fixture::expect_control_byte(ready, b'Y', deadline)?;

    *phase = "mcp_spawn";
    let mcp = bind_fresh_child(artifact.spawn_waiting(
        mcp_root,
        [request_read.as_fd(), response_write.as_fd(), stderr.as_fd()],
        [bootstrap.as_fd(), start.as_fd()],
        release.as_fd(),
    )?)?;
    drop((request_read, response_write, bootstrap, stderr));
    *phase = "mcp_attach";
    let mcp_record = FixedMcpArtifact::attach_and_start(group, registry, Role::A, &mcp, start)?;
    *phase = "mcp_runtime_wait";
    let runtime = artifact.wait_for_runtime(&mcp, deadline);
    if runtime.is_err() {
        diagnostics.mcp_stderr = read_mcp_stderr(stderr_read);
        return runtime;
    }
    *phase = "mcp_frozen_inspection";
    artifact.inspect_before_exchange(
        group,
        guard,
        [(Role::B, &caller), (Role::A, &mcp)],
        [(&stdin, caller_ends[0]), (&stdout, caller_ends[1])],
        deadline,
    )?;
    *phase = "caller_release";
    if Instant::now() >= deadline {
        return Err(os::Fault::Kernel(libc::ETIMEDOUT));
    }
    use std::io::Write;
    std::fs::File::from(release).write_all(b"R")?;
    *phase = "exchange_exit";
    let result = reap_fixed_exchange(
        [(&caller, caller_record), (&mcp, mcp_record)],
        registry,
        deadline,
        diagnostics,
    );
    if result.is_err() {
        diagnostics.mcp_stderr = read_mcp_stderr(stderr_read);
    }
    result
}

fn read_mcp_stderr(reader: OwnedFd) -> Option<String> {
    use std::io::Read;

    let mut buffer = [0; 2048];
    let size = std::fs::File::from(reader).read(&mut buffer).ok()?;
    (size != 0).then(|| String::from_utf8_lossy(&buffer[..size]).into_owned())
}

/// Stop the group even when a child failed before completing its exchange.
fn recover_fixed_exchange(
    group: &mut super::cgroup::Group,
    registry: &mut super::registry::Registry,
    counts: &mut super::registry::Counts,
) -> Result<(), super::os::Fault> {
    let stop = group.kill();
    let reap = registry.stop_stdio_fixture_children(counts);
    let cleanup = group.cleanup();
    reap?;
    cleanup?;
    stop
}

fn bind_fresh_child(pid: libc::pid_t) -> Result<super::identity::Process, super::os::Fault> {
    super::identity::Process::bind(pid as u32).or_else(|error| {
        stop_untracked_child(pid)?;
        Err(error)
    })
}

fn track_fresh_child(
    registry: &mut super::registry::Registry,
    role: super::contract::Role,
    child: &super::identity::Process,
) -> Result<super::registry::RecordId, super::os::Fault> {
    registry.track(role, child, true).or_else(|error| {
        stop_untracked_child(child.pid as libc::pid_t)?;
        Err(error)
    })
}

fn stop_untracked_child(pid: libc::pid_t) -> Result<(), super::os::Fault> {
    use super::os::Fault;
    let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(0);

    // This PID is our direct child and has never been reaped.
    let signal = unsafe { libc::kill(pid, libc::SIGKILL) };
    let signal_error = (signal < 0).then(errno).filter(|code| *code != libc::ESRCH);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let mut status = 0;
        match unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } {
            result if result == pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) => {
                return signal_error.map_or(Ok(()), |code| Err(Fault::UntrackedChildCleanup(code)));
            }
            0 => std::thread::sleep(Duration::from_millis(2)),
            result if result < 0 => {
                let code = errno();
                if code != libc::EINTR {
                    return Err(Fault::UntrackedChildCleanup(code));
                }
            }
            _ => return Err(Fault::UntrackedChildCleanup(libc::EIO)),
        }
    }
    Err(Fault::UntrackedChildCleanup(libc::ETIMEDOUT))
}

/// Start the fixed caller with inherited pipes. The ready byte tells the
/// supervisor that the child has closed its copies of the other endpoints.
fn spawn_fixed_caller(
    root: &std::path::Path,
    pipes: [OwnedFd; 4],
    expected: [&Value; 2],
    deadline: Instant,
) -> Result<libc::pid_t, super::os::Fault> {
    use super::{capsule, contract::Role, identity::Process, os, seccomp};

    let parent = Process::bind(std::process::id())?;
    let pid = os::clone_isolated()?;
    if pid != 0 {
        return Ok(pid);
    }
    super::lease::clear();
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0
        || !parent.alive().unwrap_or(false)
    {
        unsafe { libc::_exit(125) };
    }
    let [gate, requests, responses, ready] = pipes;
    let keep = [
        gate.as_raw_fd(),
        requests.as_raw_fd(),
        responses.as_raw_fd(),
        ready.as_raw_fd(),
        parent.fd(),
    ];
    if os::close_except(&keep).is_err()
        || capsule::prepare_mcp_caller_root(root).is_err()
        || capsule::drop_privileges(Role::B.uid()).is_err()
        || !parent.alive().unwrap_or(false)
        || seccomp::install(Role::B, false).is_err()
    {
        unsafe { libc::_exit(125) };
    }
    drop(parent);
    use std::io::Write;
    if std::fs::File::from(ready).write_all(b"Y").is_err() {
        unsafe { libc::_exit(125) };
    }
    run_fixed_caller(gate, requests, responses, expected, deadline)
}

/// Run the local fixture caller after the supervisor's thaw confirmation.
fn run_fixed_caller(
    gate: OwnedFd,
    requests: OwnedFd,
    responses: OwnedFd,
    expected: [&Value; 2],
    deadline: Instant,
) -> ! {
    let result = exchange_after_release(gate, requests, responses, expected, deadline);
    unsafe {
        libc::_exit(match result {
            Ok(()) => 0,
            Err(super::os::Fault::Identity) => 125,
            Err(_) => 126,
        })
    }
}

fn exchange_after_release(
    gate: OwnedFd,
    requests: OwnedFd,
    responses: OwnedFd,
    expected: [&Value; 2],
    deadline: Instant,
) -> Result<(), super::os::Fault> {
    mcp_stdio_fixture::expect_control_byte(gate, b'R', deadline)
        .map_err(|_| super::os::Fault::Identity)?;
    let [initialize, catalog] = expected;
    mcp_stdio_fixture::exchange(requests, responses, initialize, catalog, deadline)?;
    Ok(())
}

/// Reap both tracked direct children before accepting a completed exchange.
fn reap_fixed_exchange(
    children: [(&super::identity::Process, super::registry::RecordId); 2],
    registry: &mut super::registry::Registry,
    deadline: Instant,
    diagnostics: &mut ExchangeDiagnostics,
) -> Result<(), super::os::Fault> {
    use super::os::Fault;

    let [caller, mcp] = children
        .map(|(process, record)| super::runtime::reap_status(process, record, registry, deadline));
    diagnostics.caller_wait_status = caller.as_ref().ok().copied();
    diagnostics.mcp_wait_status = mcp.as_ref().ok().copied();
    for status in [caller?, mcp?] {
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(Fault::Identity);
        }
    }
    Ok(())
}

/// Verify the loader and recursively required libraries for the fixed ELF.
fn fixed_mcp_libraries() -> Result<Vec<super::os::Snapshot>, super::os::Fault> {
    use super::os::{Fault, Snapshot};
    use std::path::Path;

    // Require a pinned hash for every capsule destination at compile time.
    const EXPECTED: [&str; super::capsule::LIBRARIES.len()] = [
        "d93224d2b0dab4247598be683adca02f5cf00586f99c187579cd7e92058fb7cb",
        "5dcc4d25466e29ca390ed6fabb371c69b65dff6fa4e91c34561057a020d6994a",
        "755a371e86cc9f564ab54f66140747700fb0a103f698f659f2060f707897e09a",
        "5fc0940888e9d2e1a00e66d6b1a559c36364ee867683652e1074fa576952cc3f",
    ];
    super::capsule::LIBRARIES
        .into_iter()
        .zip(EXPECTED)
        .map(|((source, _), sha256)| {
            let snapshot = Snapshot::trusted(Path::new(source))?;
            if snapshot.sha256 != sha256 {
                return Err(Fault::Identity);
            }
            Ok(snapshot)
        })
        .collect()
}

/// A caller holds the original pidfd and keeps the worker frozen while
/// observing both standard streams. Release also requires the group-level
/// membership and pipe-holder checks.
fn verify_mcp_stdio(
    child: &super::identity::Process,
    executable: (u64, u64),
    stdin: &super::identity::Descriptor,
    stdout: &super::identity::Descriptor,
) -> Result<(), super::os::Fault> {
    use super::os::Fault;

    let identity = child.identity()?;
    if identity.code != executable
        || !stdin.matches(child.pid, libc::STDIN_FILENO)?
        || !stdout.matches(child.pid, libc::STDOUT_FILENO)?
        || child.identity()? != identity
    {
        return Err(Fault::Identity);
    }
    Ok(())
}

#[path = "mcp_stdio_fixture.rs"]
pub(super) mod mcp_stdio_fixture;

struct UniqueValue(serde_json::Value);

impl<'de> serde::Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(serde_json::Value::Number)
                    .map(UniqueValue)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(serde_json::Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(serde_json::Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(values.into()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut object: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((name, value)) = object.next_entry::<String, UniqueValue>()? {
                    if values.insert(name.clone(), value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(UniqueValue(values.into()))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Process {
    pub pid: u32,
    pub start_ticks: u64,
    pub cgroup_inode: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Binding {
    pub run_nonce: String,
    pub vm_nonce: String,
    pub session_sha256: String,
    pub executable_sha256: String,
    pub catalog_sha256: String,
    pub supervisor: Process,
}
fn hex(s: &str, length: usize) -> bool {
    s.len() == length
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Binding {
    fn valid(&self) -> bool {
        hex(&self.run_nonce, 32)
            && hex(&self.vm_nonce, 32)
            && [
                &self.session_sha256,
                &self.executable_sha256,
                &self.catalog_sha256,
            ]
            .iter()
            .all(|s| hex(s, 64))
            && self.supervisor.pid > 0
            && self.supervisor.start_ticks > 0
            && self.supervisor.cgroup_inode > 0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Rejection {
    Binding,
    Pipe,
    HoldersUnknown,
    Holders,
    Catalog,
    Schema,
    Frame,
    Id,
    Budget,
    Deadline,
    Response,
    OsIsolationUnavailable,
}

/// Owned ends stay with the parent until a future OS launcher performs the handoff.
/// No claim about peer credentials follows from the shared inode.
pub(super) struct ParentPipe {
    read: OwnedFd,
    write: OwnedFd,
    identity: (u64, u64),
}
impl ParentPipe {
    pub fn new(read: OwnedFd, write: OwnedFd) -> Result<Self, Rejection> {
        fn inspect(fd: &OwnedFd, access: i32) -> Result<(u64, u64), Rejection> {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
            if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0
                || st.st_mode & libc::S_IFMT != libc::S_IFIFO
                || flags < 0
                || flags & libc::O_PATH != 0
                || flags & libc::O_ACCMODE != access
            {
                return Err(Rejection::Pipe);
            }
            Ok((st.st_dev, st.st_ino))
        }
        let identity = inspect(&read, libc::O_RDONLY)?;
        if inspect(&write, libc::O_WRONLY)? != identity {
            return Err(Rejection::Pipe);
        }
        Ok(Self {
            read,
            write,
            identity,
        })
    }
    pub(super) fn into_ends(self) -> (OwnedFd, OwnedFd) {
        (self.read, self.write)
    }

    pub(super) fn identity(&self) -> (u64, u64) {
        self.identity
    }

    pub fn verify_parent_ends(&self) -> Result<(), Rejection> {
        let copy_read = self.read.try_clone().map_err(|_| Rejection::Pipe)?;
        let copy_write = self.write.try_clone().map_err(|_| Rejection::Pipe)?;
        let observed = Self::new(copy_read, copy_write)?;
        if observed.identity != self.identity {
            return Err(Rejection::Pipe);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Holder {
    pub process: Process,
    pub tid: u32,
    pub task_start_ticks: u64,
    pub fd: u32,
    pub writes: bool,
}
/// A future privileged scanner must supply complete host-side holders, including dup FDs.
/// B/G observations are separate and cannot stand in for this snapshot.
pub(super) fn verify_holders(
    expected: &[Holder],
    observed: Option<&[Holder]>,
) -> Result<(), Rejection> {
    let observed = observed.ok_or(Rejection::HoldersUnknown)?;
    let a: BTreeSet<_> = expected.iter().collect();
    let b: BTreeSet<_> = observed.iter().collect();
    if a.len() != expected.len()
        || b.len() != observed.len()
        || a != b
        || a.is_empty()
        || a.iter().any(|h| {
            h.process.pid == 0
                || h.process.start_ticks == 0
                || h.process.cgroup_inode == 0
                || h.tid == 0
                || h.task_start_ticks == 0
        })
    {
        return Err(Rejection::Holders);
    }
    Ok(())
}

/// Deliberately limited schema subset for reviewed dummy fixtures, not a generic
/// JSON Schema implementation. Production catalog compilation remains a gate.
#[derive(Clone, Debug)]
pub(super) enum Schema {
    String {
        max_chars: usize,
    },
    Strings {
        max_items: usize,
        max_item_chars: usize,
    },
    Object(Vec<(String, Schema)>),
}
impl Schema {
    fn valid_definition(&self, depth: usize) -> bool {
        if depth > 4 {
            return false;
        }
        match self {
            Self::String { max_chars } => (1..=4096).contains(max_chars),
            Self::Strings {
                max_items,
                max_item_chars,
            } => (1..=64).contains(max_items) && (1..=4096).contains(max_item_chars),
            Self::Object(fields) => {
                fields.len() <= 16
                    && fields.iter().map(|(k, _)| k).collect::<BTreeSet<_>>().len() == fields.len()
                    && fields.iter().all(|(k, v)| {
                        !k.is_empty() && k.len() <= 64 && v.valid_definition(depth + 1)
                    })
            }
        }
    }
    fn catalog_schema(&self) -> Value {
        use serde_json::json;
        match self {
            Self::String { max_chars } => json!({"type":"string","maxLength":max_chars}),
            Self::Strings {
                max_items,
                max_item_chars,
            } => {
                json!({"type":"array","maxItems":max_items,"items":{"type":"string","maxLength":max_item_chars}})
            }
            Self::Object(fields) => {
                let properties: serde_json::Map<String, Value> = fields
                    .iter()
                    .map(|(k, v)| (k.clone(), v.catalog_schema()))
                    .collect();
                json!({"type":"object","properties":properties,"required":fields.iter().map(|(k,_)|k).collect::<Vec<_>>(),"additionalProperties":false})
            }
        }
    }
    fn accepts(&self, value: &Value) -> bool {
        match self {
            Self::String { max_chars } => value
                .as_str()
                .is_some_and(|s| s.chars().count() <= *max_chars),
            Self::Strings {
                max_items,
                max_item_chars,
            } => value.as_array().is_some_and(|a| {
                a.len() <= *max_items
                    && a.iter().all(|v| {
                        v.as_str()
                            .is_some_and(|s| s.chars().count() <= *max_item_chars)
                    })
            }),
            Self::Object(fields) => value.as_object().is_some_and(|o| {
                o.len() == fields.len()
                    && fields
                        .iter()
                        .all(|(k, v)| o.get(k).is_some_and(|x| v.accepts(x)))
            }),
        }
    }
}
pub(super) struct Tool {
    pub name: String,
    pub catalog_entry: Value,
    pub schema: Schema,
}
#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub calls: u64,
    pub frame_bytes: usize,
    pub lifetime: Duration,
}
pub(super) struct Gate {
    binding: Binding,
    tools: Vec<Tool>,
    limits: Limits,
    deadline: Instant,
    used: u64,
    ids: BTreeSet<u64>,
    pending: Option<u64>,
    closed: bool,
}
impl Gate {
    pub fn new(
        binding: Binding,
        tools: Vec<Tool>,
        observed_catalog: &[Value],
        limits: Limits,
        now: Instant,
    ) -> Result<Self, Rejection> {
        if !binding.valid() {
            return Err(Rejection::Binding);
        }
        if tools.is_empty()
            || tools.len() > 16
            || tools.len() != observed_catalog.len()
            || tools.iter().map(|t| &t.name).collect::<BTreeSet<_>>().len() != tools.len()
            || tools.iter().zip(observed_catalog).any(|(t, o)| {
                !matches!(t.name.as_str(), "dummy_exec" | "dummy_http")
                    || t.catalog_entry != *o
                    || t.catalog_entry["name"] != t.name
                    || !t.schema.valid_definition(0)
                    || t.catalog_entry["inputSchema"] != t.schema.catalog_schema()
            })
        {
            return Err(Rejection::Catalog);
        }
        use sha2::{Digest, Sha256};
        let encoded = serde_json::to_vec(observed_catalog).map_err(|_| Rejection::Catalog)?;
        if encoded.len() > 65536
            || format!("{:x}", Sha256::digest(encoded)) != binding.catalog_sha256
        {
            return Err(Rejection::Catalog);
        }
        if !(1..=1000).contains(&limits.calls)
            || !(1..=65536).contains(&limits.frame_bytes)
            || limits.lifetime.is_zero()
            || limits.lifetime > Duration::from_secs(600)
        {
            return Err(Rejection::Budget);
        }
        let deadline = now
            .checked_add(limits.lifetime)
            .ok_or(Rejection::Deadline)?;
        Ok(Self {
            binding,
            tools,
            limits,
            deadline,
            used: 0,
            ids: BTreeSet::new(),
            pending: None,
            closed: false,
        })
    }
    fn current(&self, binding: &Binding, now: Instant) -> Result<(), Rejection> {
        if self.closed {
            return Err(Rejection::Response);
        }
        if &self.binding != binding {
            return Err(Rejection::Binding);
        }
        if now >= self.deadline {
            return Err(Rejection::Deadline);
        }
        Ok(())
    }
    pub fn admit(
        &mut self,
        binding: &Binding,
        frame: &[u8],
        now: Instant,
    ) -> Result<Value, Rejection> {
        let result = self.admit_checked(binding, frame, now);
        if result.is_err() {
            self.closed = true;
        }
        result
    }
    // Every rejected request closes this prototype route. Rejected requests
    // never dispatch, and an earlier pending response cannot reopen it.
    fn admit_checked(
        &mut self,
        binding: &Binding,
        frame: &[u8],
        now: Instant,
    ) -> Result<Value, Rejection> {
        self.current(binding, now)?;
        if frame.len() > self.limits.frame_bytes {
            return Err(Rejection::Frame);
        }
        let value = serde_json::from_slice::<UniqueValue>(frame)
            .map_err(|_| Rejection::Frame)?
            .0;
        let object = value.as_object().ok_or(Rejection::Frame)?;
        if object.len() != 4 || value["jsonrpc"] != "2.0" || value["method"] != "tools/call" {
            return Err(Rejection::Schema);
        }
        let id = value["id"]
            .as_u64()
            .filter(|v| *v > 0)
            .ok_or(Rejection::Id)?;
        if self.pending.is_some() || self.ids.contains(&id) {
            return Err(Rejection::Id);
        }
        let params = value["params"]
            .as_object()
            .filter(|p| p.len() == 2)
            .ok_or(Rejection::Schema)?;
        let tool = self
            .tools
            .iter()
            .find(|t| params.get("name") == Some(&Value::String(t.name.clone())))
            .ok_or(Rejection::Schema)?;
        if !params
            .get("arguments")
            .is_some_and(|v| tool.schema.accepts(v))
        {
            return Err(Rejection::Schema);
        }
        if self.used >= self.limits.calls {
            return Err(Rejection::Budget);
        }
        self.used += 1;
        self.ids.insert(id);
        self.pending = Some(id);
        Ok(value)
    }
    pub fn complete(
        &mut self,
        binding: &Binding,
        frame: &[u8],
        now: Instant,
    ) -> Result<(), Rejection> {
        let current = self.current(binding, now);
        self.closed = true;
        current?;
        if frame.len() > self.limits.frame_bytes {
            return Err(Rejection::Frame);
        }
        let v = serde_json::from_slice::<UniqueValue>(frame)
            .map_err(|_| Rejection::Frame)?
            .0;
        if v["jsonrpc"] != "2.0"
            || self.pending.is_none()
            || v["id"].as_u64() != self.pending
            || v.get("result").is_some() == v.get("error").is_some()
            || v.as_object().is_none_or(|o| o.len() != 3)
        {
            return Err(Rejection::Response);
        }
        if !v.get("result").is_some_and(Value::is_object) {
            let error = v
                .get("error")
                .and_then(Value::as_object)
                .ok_or(Rejection::Response)?;
            if error.get("code").and_then(Value::as_i64).is_none()
                || !error
                    .get("message")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.len() <= 4096)
                || error
                    .keys()
                    .any(|k| !matches!(k.as_str(), "code" | "message" | "data"))
            {
                return Err(Rejection::Response);
            }
        }
        self.pending = None;
        self.closed = false;
        Ok(())
    }
    /// Fixture connection point remains closed until an actual OS backend can
    /// constrain the trusted MCP child. Static argv/env and validators are not proof.
    pub fn connect_fixture(&self) -> Result<(), Rejection> {
        Err(Rejection::OsIsolationUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::fd::FromRawFd;

    #[test]
    fn caller_gate_eof_sends_no_initialize() {
        use std::io::Read;

        let (gate, release) = pipe();
        let (request_read, requests) = pipe();
        let (responses, _response_write) = pipe();
        drop(release);
        assert_eq!(
            exchange_after_release(
                gate,
                requests,
                responses,
                [&Value::Null; 2],
                Instant::now() + Duration::from_secs(1),
            ),
            Err(crate::os::Fault::Identity),
        );
        assert_eq!(std::fs::File::from(request_read).read(&mut [0]).unwrap(), 0);
    }

    fn process() -> Process {
        Process {
            pid: 42,
            start_ticks: 100,
            cgroup_inode: 7,
        }
    }
    fn fixture() -> (Binding, Vec<Tool>, Vec<Value>) {
        use sha2::{Digest, Sha256};
        let schema = Schema::Object(vec![
            ("command".into(), Schema::String { max_chars: 32 }),
            (
                "args".into(),
                Schema::Strings {
                    max_items: 4,
                    max_item_chars: 32,
                },
            ),
        ]);
        let entry = json!({"name":"dummy_exec","inputSchema":schema.catalog_schema()});
        let catalog = vec![entry.clone()];
        let binding = Binding {
            run_nonce: "1".repeat(32),
            vm_nonce: "2".repeat(32),
            session_sha256: "3".repeat(64),
            executable_sha256: "4".repeat(64),
            catalog_sha256: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&catalog).unwrap())
            ),
            supervisor: process(),
        };
        (
            binding,
            vec![Tool {
                name: "dummy_exec".into(),
                catalog_entry: entry,
                schema,
            }],
            catalog,
        )
    }
    fn limits() -> Limits {
        Limits {
            calls: 2,
            frame_bytes: 1024,
            lifetime: Duration::from_secs(5),
        }
    }
    fn request(id: u64) -> Vec<u8> {
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"dummy_exec","arguments":{"command":"dummy","args":[]}}})).unwrap()
    }
    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }
    #[test]
    fn actual_pipe_owned_ends_are_checked_but_do_not_authorize_a_peer() {
        let (r, w) = pipe();
        let p = ParentPipe::new(r, w).unwrap();
        p.verify_parent_ends().unwrap();
        let (r, _) = pipe();
        let (_, w) = pipe();
        assert!(matches!(ParentPipe::new(r, w), Err(Rejection::Pipe)));
        let (r, w) = pipe();
        assert!(matches!(ParentPipe::new(w, r), Err(Rejection::Pipe)));
        let (binding, tools, catalog) = fixture();
        let gate = Gate::new(binding, tools, &catalog, limits(), Instant::now()).unwrap();
        assert_eq!(
            gate.connect_fixture(),
            Err(Rejection::OsIsolationUnavailable)
        );
    }
    #[test]
    fn stdio_observation_checks_exec_and_pipe_direction() {
        use crate::identity::{Descriptor, Process};
        use std::os::unix::fs::MetadataExt;
        use std::process::{Command, Stdio};

        let (request_read, request_write) = crate::os::pipe().unwrap();
        let (response_read, response_write) = crate::os::pipe().unwrap();
        let stdin = Descriptor::bind(request_read.as_raw_fd()).unwrap();
        let stdout = Descriptor::bind(response_write.as_raw_fd()).unwrap();
        let wrong_stdin = Descriptor::bind(request_write.as_raw_fd()).unwrap();
        let code = std::fs::metadata("/bin/cat").unwrap();
        let mut child = Command::new("/bin/cat")
            .env_clear()
            .stdin(Stdio::from(request_read))
            .stdout(Stdio::from(response_write))
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let observed = (|| {
            let process = Process::bind(child.id())?;
            let executable = (code.dev(), code.ino());
            Ok::<_, crate::os::Fault>([
                verify_mcp_stdio(&process, executable, &stdin, &stdout).is_ok(),
                verify_mcp_stdio(&process, (0, 0), &stdin, &stdout).is_err(),
                verify_mcp_stdio(&process, executable, &wrong_stdin, &stdout).is_err(),
            ])
        })();
        drop((request_write, response_read));
        assert!(child.wait().unwrap().success());
        assert_eq!(observed.unwrap(), [true; 3]);
    }

    #[test]
    fn path_only_alias_is_not_a_read_endpoint() {
        use std::os::unix::fs::OpenOptionsExt;

        let (read, write) = crate::os::pipe().unwrap();
        let path_only = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(format!("/proc/self/fd/{}", read.as_raw_fd()))
            .unwrap();
        assert!(matches!(
            ParentPipe::new(path_only.into(), write),
            Err(Rejection::Pipe)
        ));
    }

    #[test]
    fn duplicate_fd_unknown_scan_and_reused_pid_fail_holder_contract() {
        let expected = [Holder {
            process: process(),
            tid: process().pid,
            task_start_ticks: process().start_ticks,
            fd: 3,
            writes: true,
        }];
        verify_holders(&expected, Some(&expected)).unwrap();
        assert_eq!(
            verify_holders(&expected, None),
            Err(Rejection::HoldersUnknown)
        );
        let mut extra = expected.to_vec();
        extra.push(Holder {
            fd: 4,
            ..expected[0].clone()
        });
        assert_eq!(
            verify_holders(&expected, Some(&extra)),
            Err(Rejection::Holders)
        );
        extra[0].process.start_ticks += 1;
        assert_eq!(
            verify_holders(&expected, Some(&extra[..1])),
            Err(Rejection::Holders)
        );
        assert_eq!(
            verify_holders(&expected, Some(&[])),
            Err(Rejection::Holders)
        );
    }
    #[test]
    fn exact_catalog_schema_and_digest_are_all_required() {
        let (binding, tools, mut catalog) = fixture();
        catalog[0]["name"] = "other".into();
        assert!(matches!(
            Gate::new(binding, tools, &catalog, limits(), Instant::now()),
            Err(Rejection::Catalog)
        ));
        let (binding, mut tools, catalog) = fixture();
        tools[0].schema = Schema::Object(vec![]);
        assert!(matches!(
            Gate::new(binding, tools, &catalog, limits(), Instant::now()),
            Err(Rejection::Catalog)
        ));
        let (mut binding, tools, catalog) = fixture();
        binding.catalog_sha256 = "0".repeat(64);
        assert!(matches!(
            Gate::new(binding, tools, &catalog, limits(), Instant::now()),
            Err(Rejection::Catalog)
        ));
    }
    #[test]
    fn foreign_run_vm_session_binary_and_process_are_rejected_before_dispatch() {
        let (binding, _, _) = fixture();
        let now = Instant::now();
        for field in 0..6 {
            let (_, tools, catalog) = fixture();
            let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
            let mut foreign = binding.clone();
            match field {
                0 => foreign.run_nonce = "0".repeat(32),
                1 => foreign.vm_nonce = "0".repeat(32),
                2 => foreign.session_sha256 = "0".repeat(64),
                3 => foreign.executable_sha256 = "0".repeat(64),
                4 => foreign.supervisor.start_ticks += 1,
                _ => foreign.supervisor.cgroup_inode += 1,
            }
            assert_eq!(
                gate.admit(&foreign, &request(1), now),
                Err(Rejection::Binding)
            );
        }
    }
    #[test]
    fn arbitrary_upstream_management_tool_and_extra_arguments_are_rejected() {
        let (binding, tools, catalog) = fixture();
        let now = Instant::now();
        let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
        for method in ["sandbox_up", "exec", "initialize"] {
            let (_, tools, catalog) = fixture();
            let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
            let mut value: Value = serde_json::from_slice(&request(1)).unwrap();
            value["method"] = method.into();
            assert_eq!(
                gate.admit(&binding, &serde_json::to_vec(&value).unwrap(), now),
                Err(Rejection::Schema)
            );
        }
        for name in ["export", "claim", "other_run", "upstream_command"] {
            let (_, tools, catalog) = fixture();
            let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
            let mut value: Value = serde_json::from_slice(&request(1)).unwrap();
            value["params"]["name"] = name.into();
            assert_eq!(
                gate.admit(&binding, &serde_json::to_vec(&value).unwrap(), now),
                Err(Rejection::Schema)
            );
        }
        let mut value: Value = serde_json::from_slice(&request(1)).unwrap();
        value["params"]["arguments"]["host"] = "127.0.0.1".into();
        assert_eq!(
            gate.admit(&binding, &serde_json::to_vec(&value).unwrap(), now),
            Err(Rejection::Schema)
        );
        assert_eq!(gate.used, 0);
    }
    #[test]
    fn sequential_ids_pair_responses_and_budget_is_not_extended() {
        let (binding, tools, catalog) = fixture();
        let now = Instant::now();
        let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
        gate.admit(&binding, &request(1), now).unwrap();
        gate.complete(&binding, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#, now)
            .unwrap();
        gate.admit(&binding, &request(2), now).unwrap();
        gate.complete(&binding, br#"{"jsonrpc":"2.0","id":2,"result":{}}"#, now)
            .unwrap();
        assert_eq!(
            gate.admit(&binding, &request(3), now),
            Err(Rejection::Budget)
        );
        let (binding, tools, catalog) = fixture();
        let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
        assert_eq!(
            gate.admit(&binding, &request(4), now + Duration::from_secs(5)),
            Err(Rejection::Deadline)
        );
    }
    #[test]
    fn wrong_response_poisoning_prevents_fresh_id_or_late_recovery() {
        let (binding, tools, catalog) = fixture();
        let now = Instant::now();
        let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
        gate.admit(&binding, &request(1), now).unwrap();
        assert_eq!(
            gate.complete(&binding, br#"{"jsonrpc":"2.0","id":2,"result":{}}"#, now),
            Err(Rejection::Response)
        );
        assert_eq!(
            gate.admit(&binding, &request(2), now),
            Err(Rejection::Response)
        );
        assert_eq!(
            gate.complete(&binding, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#, now),
            Err(Rejection::Response)
        );
    }
    #[test]
    fn malformed_oversize_and_unbounded_configuration_are_refused() {
        let (binding, tools, catalog) = fixture();
        let now = Instant::now();
        let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
        assert_eq!(gate.admit(&binding, b"{", now), Err(Rejection::Frame));
        let (binding, tools, catalog) = fixture();
        let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
        assert_eq!(
            gate.admit(&binding, &vec![b' '; 1025], now),
            Err(Rejection::Frame)
        );
        let (binding, tools, catalog) = fixture();
        let mut invalid = limits();
        invalid.calls = u64::MAX;
        assert!(matches!(
            Gate::new(binding, tools, &catalog, invalid, now),
            Err(Rejection::Budget)
        ));
    }
    #[test]
    fn malformed_jsonrpc_error_closes_the_route_contract() {
        let (binding, tools, catalog) = fixture();
        let now = Instant::now();
        let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
        gate.admit(&binding, &request(1), now).unwrap();
        assert_eq!(
            gate.complete(&binding, br#"{"jsonrpc":"2.0","id":1,"error":3}"#, now),
            Err(Rejection::Response)
        );
        assert_eq!(
            gate.admit(&binding, &request(2), now),
            Err(Rejection::Response)
        );
    }

    #[test]
    fn rejected_requests_cannot_be_followed_by_valid_dispatch() {
        let now = Instant::now();
        for failure in 0..5 {
            let (binding, tools, catalog) = fixture();
            let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
            let result = match failure {
                0 => gate.admit(&binding, b"{", now),
                1 => {
                    let mut foreign = binding.clone();
                    foreign.vm_nonce = "0".repeat(32);
                    gate.admit(&foreign, &request(1), now)
                }
                2 => gate.admit(&binding, &request(1), now + Duration::from_secs(5)),
                3 => {
                    gate.admit(&binding, &request(1), now).unwrap();
                    gate.admit(&binding, &request(2), now)
                }
                _ => {
                    gate.admit(&binding, &request(1), now).unwrap();
                    gate.complete(&binding, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#, now)
                        .unwrap();
                    gate.admit(&binding, &request(1), now)
                }
            };
            assert!(result.is_err());
            assert_eq!(
                gate.admit(&binding, &request(3), now),
                Err(Rejection::Response)
            );
            assert_eq!(
                gate.complete(&binding, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#, now),
                Err(Rejection::Response)
            );
        }
    }

    #[test]
    fn duplicate_keys_at_any_depth_close_requests_and_responses() {
        let now = Instant::now();
        for frame in [
            br#"{"jsonrpc":"2.0","id":9,"id":1,"method":"tools/call","params":{"name":"dummy_exec","arguments":{"command":"dummy","args":[]}}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":9,"\u0069d":1,"method":"tools/call","params":{"name":"dummy_exec","arguments":{"command":"dummy","args":[]}}}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"other","method":"tools/call","params":{"name":"dummy_exec","arguments":{"command":"dummy","args":[]}}}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{},"params":{"name":"dummy_exec","arguments":{"command":"dummy","args":[]}}}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dummy_exec","arguments":{"command":"other","command":"dummy","args":[]}}}"#,
        ] {
            let (binding, tools, catalog) = fixture();
            let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
            assert_eq!(gate.admit(&binding, frame, now), Err(Rejection::Frame));
            assert_eq!(gate.used, 0);
            assert_eq!(gate.admit(&binding, &request(2), now), Err(Rejection::Response));
        }
        for frame in [
            br#"{"jsonrpc":"2.0","id":2,"id":1,"result":{}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"a","text":"b"}]}}"#,
        ] {
            let (binding, tools, catalog) = fixture();
            let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
            gate.admit(&binding, &request(1), now).unwrap();
            assert_eq!(gate.complete(&binding, frame, now), Err(Rejection::Frame));
            assert_eq!(
                gate.admit(&binding, &request(2), now),
                Err(Rejection::Response)
            );
        }
    }

    #[test]
    fn schema_lengths_count_unicode_characters_while_frames_bound_bytes() {
        let schema = Schema::String { max_chars: 1 };
        assert_eq!(schema.catalog_schema()["maxLength"], 1);
        assert!(schema.accepts(&json!("あ")));
        assert!(!schema.accepts(&json!("あい")));
        let array = Schema::Strings {
            max_items: 1,
            max_item_chars: 1,
        };
        assert!(array.accepts(&json!(["あ"])));
        assert!(!array.accepts(&json!(["あい"])));
    }
}
