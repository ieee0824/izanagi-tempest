//! Fixed-name, run-owned kernel resource group. Supervisor never joins it.
use super::{contract::Role, os::Fault};
use std::{
    ffi::CString,
    fs, io,
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
    thread,
    time::{Duration, Instant},
};

pub(super) const ROOT: &str = "/sys/fs/cgroup/tempest-linux-isolation-probe";

pub(super) struct Group {
    armed: bool,
    identity: (u64, u64),
    directory: fs::File,
}

/// No normal Group API and no Drop cleanup. Only an exclusive death proof
/// authorizes use of the already validated identity and duplicated directory FD.
pub(super) struct RecoveryGroup {
    identity: (u64, u64),
    directory: fs::File,
}
impl RecoveryGroup {
    fn verify_pinned(&self) -> Result<(), Fault> {
        use std::os::unix::fs::MetadataExt;
        let pinned = self.directory.metadata()?;
        if !pinned.is_dir() || (pinned.dev(), pinned.ino()) != self.identity {
            return Err(Fault::Identity);
        }
        Ok(())
    }
    fn verify(&self) -> Result<(), Fault> {
        use std::os::unix::fs::MetadataExt;
        let pinned = self.directory.metadata()?;
        let current = fs::symlink_metadata(ROOT)?;
        if !current.is_dir()
            || (current.dev(), current.ino()) != self.identity
            || (pinned.dev(), pinned.ino()) != self.identity
        {
            return Err(Fault::Identity);
        }
        Ok(())
    }
    pub(super) fn recover(
        self,
        proof: &super::watchdog::DeadGuardian<'_>,
        registry: &mut super::registry::Registry,
        counts: &mut super::registry::Counts,
    ) -> Result<(), Fault> {
        self.verify_pinned()?;
        if matches!(fs::symlink_metadata(ROOT), Err(error) if error.kind() == io::ErrorKind::NotFound)
        {
            counts.cgroup_populated = Some(false);
            return registry.stop_and_reap(proof, counts);
        }
        self.verify()?;
        let mut evidence_failure = None;
        // Snapshot is bounded by the fixed parent pids.max=48; populated=0
        // remains independently necessary because fork can race this snapshot.
        for role in Role::ALL {
            use super::registry::SnapshotStage;
            let mut stage = SnapshotStage::ReadMembers;
            let result = (|| {
                let directory = match open_at(
                    &self.directory,
                    role.name(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                ) {
                    Ok(directory) => directory,
                    Err(Fault::Kernel(libc::ENOENT)) => return Ok(()),
                    Err(error) => return Err(error),
                };
                let members = read(&directory, "cgroup.procs")?;
                if members.len() > 1024 {
                    return Err(Fault::Identity);
                }
                for pid in members.split_whitespace().take(49) {
                    stage = SnapshotStage::Bind;
                    let process = super::identity::Process::bind_snapshot(
                        pid.parse().map_err(|_| Fault::Identity)?,
                    )?;
                    stage = SnapshotStage::Membership;
                    if !process.recovery_member(role)? {
                        return Err(Fault::Identity);
                    }
                    stage = SnapshotStage::Track;
                    registry.track(role, &process, false)?;
                }
                Ok::<_, Fault>(())
            })();
            if let Err(error) = result {
                if counts.snapshot_stage.is_none() {
                    counts.snapshot_stage = Some(stage);
                    counts.snapshot_reason = Some(error.reason());
                    counts.snapshot_errno = match error {
                        Fault::Kernel(errno) => Some(errno),
                        _ => None,
                    };
                }
                evidence_failure.get_or_insert(error);
            }
        }
        self.verify()?;
        let stopped = write(&self.directory, "cgroup.kill", "1");
        // Stop unattached direct children even if cgroup.kill failed.
        let reaped = registry.stop_and_reap(proof, counts);
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            self.verify()?;
            let events = read(&self.directory, "cgroup.events")?;
            counts.cgroup_populated = events.lines().find_map(|line| match line {
                "populated 0" => Some(false),
                "populated 1" => Some(true),
                _ => None,
            });
            if counts.cgroup_populated == Some(false) {
                break;
            }
            if Instant::now() >= until {
                return Err(Fault::Kernel(libc::EBUSY));
            }
            thread::sleep(Duration::from_millis(10));
        }
        stopped?;
        reaped?;
        if let Some(error) = evidence_failure {
            return Err(error);
        }
        for role in Role::ALL {
            match rmdir(&self.directory, role.name()) {
                Ok(()) | Err(Fault::Kernel(libc::ENOENT)) => (),
                Err(error) => return Err(error),
            }
        }
        self.verify()?;
        // Top-level identity-check/unlink race with another privileged actor
        // remains a separate gate, as in the normal cleanup path.
        fs::remove_dir(ROOT)?;
        Ok(())
    }
}

fn open_directory() -> Result<fs::File, Fault> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(ROOT)?)
}

fn component(name: &str) -> Result<CString, Fault> {
    if name.is_empty() || matches!(name, "." | "..") || name.contains('/') {
        return Err(Fault::Path);
    }
    CString::new(name).map_err(|_| Fault::Path)
}

fn open_at(directory: &fs::File, name: &str, flags: i32) -> Result<fs::File, Fault> {
    let name = component(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn write(directory: &fs::File, name: &str, value: &str) -> Result<(), Fault> {
    use std::io::Write;
    open_at(directory, name, libc::O_WRONLY)?.write_all(value.as_bytes())?;
    Ok(())
}

fn read(directory: &fs::File, name: &str) -> Result<String, Fault> {
    use std::io::Read;
    let mut value = String::new();
    open_at(directory, name, libc::O_RDONLY)?.read_to_string(&mut value)?;
    Ok(value)
}

fn parse_frozen(events: &str) -> Result<bool, Fault> {
    if !events.ends_with('\n') {
        return Err(Fault::Identity);
    }
    let mut frozen = None;
    for line in events.lines() {
        if line.split_ascii_whitespace().next() != Some("frozen") {
            continue;
        }
        if frozen.is_some() {
            return Err(Fault::Identity);
        }
        frozen = Some(match line {
            "frozen 0" => false,
            "frozen 1" => true,
            _ => return Err(Fault::Identity),
        });
    }
    frozen.ok_or(Fault::Identity)
}

fn wait_for_freezer_state(
    expected: bool,
    until: Instant,
    mut read_state: impl FnMut() -> Result<bool, Fault>,
) -> Result<(), Fault> {
    loop {
        if Instant::now() >= until {
            return Err(Fault::Identity);
        }
        let frozen = read_state()?;
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Fault::Identity);
        }
        if frozen == expected {
            return Ok(());
        }
        thread::sleep(remaining.min(Duration::from_millis(5)));
    }
}

fn after_freezer_confirmation<T>(
    confirm: impl FnOnce() -> Result<(), Fault>,
    inspect: impl FnOnce() -> Result<T, Fault>,
) -> Result<T, Fault> {
    confirm()?;
    inspect()
}

fn mkdir(directory: &fs::File, name: &str) -> Result<(), Fault> {
    let name = component(name)?;
    super::os::syscall(unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o755) })
}

fn rmdir(directory: &fs::File, name: &str) -> Result<(), Fault> {
    let name = component(name)?;
    super::os::syscall(unsafe {
        libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
    })
}

impl Group {
    pub(super) fn recovery_handle(&self) -> Result<RecoveryGroup, Fault> {
        self.verify()?;
        Ok(RecoveryGroup {
            identity: self.identity,
            directory: super::os::duplicate_fd(self.directory.as_raw_fd())?.into(),
        })
    }
    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
    pub(super) fn arm(&mut self) {
        self.armed = true;
    }
    pub(super) fn identity(&self) -> (u64, u64) {
        self.identity
    }

    pub(super) fn adopt(identity: (u64, u64)) -> Result<Self, Fault> {
        let group = Self {
            armed: true,
            identity,
            directory: open_directory()?,
        };
        group.verify()?;
        Ok(group)
    }

    fn verify(&self) -> Result<(), Fault> {
        super::lease::pulse()?;
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(ROOT)?;
        let pinned = self.directory.metadata()?;
        if !metadata.is_dir()
            || (metadata.dev(), metadata.ino()) != self.identity
            || (pinned.dev(), pinned.ino()) != self.identity
        {
            return Err(Fault::Identity);
        }
        Ok(())
    }

    pub(super) fn recover(&mut self) -> Result<(), Fault> {
        // Parent may have completed cleanup already; never adopt a replacement.
        match fs::symlink_metadata(ROOT) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.armed = false;
                Ok(())
            }
            _ => self.cleanup(),
        }
    }
    pub(super) fn create() -> Result<Self, Fault> {
        let path = Path::new(ROOT);
        // A leftover group is never adopted or overwritten by a new probe.
        fs::create_dir(path)?;
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(path)?;
        let mut group = Self {
            armed: true,
            identity: (metadata.dev(), metadata.ino()),
            directory: open_directory()?,
        };
        let setup = (|| {
            for (name, value) in [
                ("memory.max", "536870912"),
                ("memory.swap.max", "0"),
                ("pids.max", "48"),
                ("cpu.max", "50000 100000"),
                ("cgroup.subtree_control", "+cpu +memory +pids"),
            ] {
                write(&group.directory, name, value)?;
            }
            for role in Role::ALL {
                mkdir(&group.directory, role.name())?;
                let child = open_at(
                    &group.directory,
                    role.name(),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                )?;
                for (name, value) in [
                    ("memory.max", "134217728"),
                    ("memory.swap.max", "0"),
                    ("pids.max", "12"),
                    ("cpu.max", "20000 100000"),
                ] {
                    write(&child, name, value)?;
                    // Kernel-normalized whitespace is not policy variance.
                    if read(&child, name)?.trim() != value {
                        return Err(Fault::Identity);
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = setup {
            // Do not turn a cleanup failure into successful initialization.
            if group.cleanup().is_err() {
                return Err(Fault::Kernel(libc::EBUSY));
            }
            return Err(error);
        }
        Ok(group)
    }

    pub(super) fn attach(&self, role: Role, pid: u32) -> Result<(), Fault> {
        self.verify()?;
        let child = open_at(
            &self.directory,
            role.name(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        write(&child, "cgroup.procs", &pid.to_string())
    }

    pub(super) fn bound(&self, role: Role, pid: u32) -> Result<bool, Fault> {
        self.verify()?;
        let value = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
        Ok(value
            .lines()
            .any(|line| line == format!("0::/tempest-linux-isolation-probe/{}", role.name())))
    }

    pub(super) fn pids_events(&self) -> Result<u64, Fault> {
        self.verify()?;
        let child = open_at(
            &self.directory,
            Role::A.name(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        read(&child, "pids.events")?
            .lines()
            .find_map(|line| line.strip_prefix("max "))
            .ok_or(Fault::Identity)?
            .parse()
            .map_err(|_| Fault::Identity)
    }

    pub(super) fn pids_members(&self) -> Result<Vec<u32>, Fault> {
        self.verify()?;
        let child = open_at(
            &self.directory,
            Role::A.name(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        if read(&child, "pids.current")?.trim() != "12" || read(&child, "pids.max")?.trim() != "12"
        {
            return Err(Fault::Identity);
        }
        self.members(Role::A)
    }

    pub(super) fn members(&self, role: Role) -> Result<Vec<u32>, Fault> {
        self.verify()?;
        let child = open_at(
            &self.directory,
            role.name(),
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?;
        read(&child, "cgroup.procs")?
            .split_whitespace()
            .map(|pid| pid.parse().map_err(|_| Fault::Identity))
            .collect()
    }

    pub(super) fn memory_events(&self, role: Option<Role>) -> Result<[u64; 3], Fault> {
        self.verify()?;
        let directory = if let Some(role) = role {
            open_at(
                &self.directory,
                role.name(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?
        } else {
            self.directory.try_clone()?
        };
        let limit = if role.is_some() {
            "134217728"
        } else {
            "536870912"
        };
        if read(&directory, "memory.max")?.trim() != limit
            || read(&directory, "memory.swap.max")?.trim() != "0"
        {
            return Err(Fault::Identity);
        }
        let events = read(&directory, "memory.events.local")?;
        let counter = |key: &str| -> Result<u64, Fault> {
            events
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .ok_or(Fault::Identity)?
                .parse()
                .map_err(|_| Fault::Identity)
        };
        Ok([counter("max ")?, counter("oom ")?, counter("oom_kill ")?])
    }

    #[allow(dead_code)]
    pub(super) fn request_frozen(&self, frozen: bool) -> Result<(), Fault> {
        self.verify()?;
        write(
            &self.directory,
            "cgroup.freeze",
            if frozen { "1" } else { "0" },
        )
    }

    #[allow(dead_code)]
    pub(super) fn wait_frozen(&self, expected: bool, until: Instant) -> Result<(), Fault> {
        wait_for_freezer_state(expected, until, || self.frozen())
    }

    /// Keep ownership of the dedicated group through observation and consumption.
    /// The observer's result stays local and no frozen proof survives thaw.
    #[allow(dead_code)]
    pub(super) fn inspect_while_frozen<T: PartialEq, const N: usize>(
        &mut self,
        _guard: &super::guard::Guard,
        until: Instant,
        workers: [(Role, &super::identity::Process); N],
        manager_pipes: &[super::holder_scan::ManagerPipe<'_>],
        observe: impl FnOnce(&Self) -> Result<T, Fault>,
        expected: &T,
    ) -> Result<(), Fault> {
        if !self.armed
            || !matches!(N, 1 | 2)
            || manager_pipes.len() != N
            || (N == 2 && manager_pipes[0].identity == manager_pipes[1].identity)
            || Instant::now() >= until
            || workers
                .iter()
                .any(|(_, worker)| worker.pid == 0 || worker.pid == std::process::id())
            || (N == 2 && (workers[0].0 == workers[1].0 || workers[0].1.pid == workers[1].1.pid))
        {
            return Err(Fault::Identity);
        }
        self.verify()?;
        let membership = fs::read_to_string("/proc/self/cgroup")?;
        let mut unified = membership
            .lines()
            .filter_map(|line| line.strip_prefix("0::"));
        let manager_group = unified.next().ok_or(Fault::Identity)?;
        let trial_group = Path::new(ROOT)
            .strip_prefix("/sys/fs/cgroup")
            .map_err(|_| Fault::Identity)?;
        if unified.next().is_some()
            || !manager_group.starts_with('/')
            || Path::new(manager_group)
                .strip_prefix("/")
                .map_err(|_| Fault::Identity)?
                .starts_with(trial_group)
            || !read(&self.directory, "cgroup.procs")?.trim().is_empty()
        {
            return Err(Fault::Identity);
        }
        let check_workers = || {
            if !read(&self.directory, "cgroup.procs")?.trim().is_empty() {
                return Err(Fault::Identity);
            }
            for role in Role::ALL {
                let expected = workers.iter().find(|(placed, _)| *placed == role);
                let members = self.members(role)?;
                if let Some((_, worker)) = expected {
                    if members != [worker.pid] {
                        return Err(Fault::Identity);
                    }
                } else if !members.is_empty() {
                    return Err(Fault::Identity);
                }
            }
            for (role, worker) in workers {
                use super::holder_scan::{Budget, start_ticks};
                let mut budget = Budget {
                    deadline: until,
                    bytes_left: 65536,
                    entries_left: 0,
                };
                let path = std::path::PathBuf::from(format!("/proc/{}/stat", worker.pid));
                if !worker.alive()?
                    || !self.bound(role, worker.pid)?
                    || budget
                        .read(&path, 65536)
                        .and_then(|data| start_ticks(&data, worker.pid))
                        .map_err(|_| Fault::Identity)?
                        != worker.birth
                    || !worker.alive()?
                {
                    return Err(Fault::Identity);
                }
            }
            let mut budget = super::holder_scan::Budget {
                deadline: until,
                bytes_left: 0,
                entries_left: 8192,
            };
            for pipe in manager_pipes {
                if super::holder_scan::manager_pipe_fds(pipe.identity, &mut budget)
                    .map_err(|_| Fault::Identity)?
                    != pipe.expected
                {
                    return Err(Fault::Identity);
                }
            }
            Ok(())
        };
        check_workers()?;
        let result = (|| {
            self.request_frozen(true)?;
            after_freezer_confirmation(
                || self.wait_frozen(true, until),
                || {
                    check_workers()?;
                    let observation = observe(self)?;
                    check_workers()?;
                    if Instant::now() >= until || !self.frozen()? || Instant::now() >= until {
                        return Err(Fault::Identity);
                    }
                    // This comparison is the only consumption of the observation.
                    // No callback can publish an admission before thaw succeeds.
                    if &observation != expected {
                        return Err(Fault::Identity);
                    }
                    drop(observation);
                    check_workers()?;
                    if Instant::now() >= until || !self.frozen()? || Instant::now() >= until {
                        return Err(Fault::Identity);
                    }
                    Ok(())
                },
            )?;
            self.request_frozen(false)?;
            self.wait_frozen(false, until)
        })();
        if result.is_err() {
            // Preserve the armed group's recovery path if stop fails.
            self.kill()?;
        }
        result
    }

    /// Separate from requesting a freeze: observe the kernel state to EOF.
    #[allow(dead_code)]
    pub(super) fn frozen(&self) -> Result<bool, Fault> {
        use std::io::Read;
        self.verify()?;
        let mut events = String::new();
        open_at(&self.directory, "cgroup.events", libc::O_RDONLY)?
            .take(4097)
            .read_to_string(&mut events)?;
        if events.len() > 4096 {
            return Err(Fault::Identity);
        }
        self.verify()?;
        parse_frozen(&events)
    }

    pub(super) fn kill(&self) -> Result<(), Fault> {
        self.verify()?;
        write(&self.directory, "cgroup.kill", "1")
    }

    pub(super) fn empty(&self) -> Result<bool, Fault> {
        self.verify()?;
        let events = read(&self.directory, "cgroup.events")?;
        events
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
            .map(|value| value == "0")
            .ok_or(Fault::Identity)
    }

    pub(super) fn cleanup(&mut self) -> Result<(), Fault> {
        if !self.armed {
            return Ok(());
        }
        let path = Path::new(ROOT);
        self.kill()?;
        let until = Instant::now() + Duration::from_secs(3);
        while !self.empty()? {
            if Instant::now() >= until {
                return Err(Fault::Kernel(libc::EBUSY));
            }
            thread::sleep(Duration::from_millis(10));
        }
        for role in Role::ALL {
            match rmdir(&self.directory, role.name()) {
                Ok(()) => (),
                Err(Fault::Kernel(libc::ENOENT)) => (),
                Err(e) => return Err(e),
            }
        }
        fs::remove_dir(path)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        // Last-resort shutdown on early returns; normal completion must check
        // cleanup() explicitly and retain a failed run lock on any error.
        let _ = self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "fixed Linux host with root cgroup access; run in an isolated test process"]
    fn fixed_dummy_frozen_holder_and_progress() {
        fixed_dummy(DummyCase::Positive);
    }

    #[test]
    #[ignore = "fixed Linux host with root cgroup access"]
    fn fixed_dummy_rejects_extra_pipe_fd() {
        fixed_dummy(DummyCase::ExtraFd);
    }

    #[test]
    #[ignore = "fixed Linux host with root cgroup access"]
    fn fixed_dummy_rejects_wrong_role() {
        fixed_dummy(DummyCase::WrongRole);
    }

    #[test]
    #[ignore = "fixed Linux host with root cgroup access"]
    fn fixed_dummy_rejects_exited_worker() {
        fixed_dummy(DummyCase::ExitedWorker);
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum DummyCase {
        Positive,
        ExtraFd,
        WrongRole,
        ExitedWorker,
    }

    fn fixed_dummy(case: DummyCase) {
        use super::*;
        use crate::{
            guard::Guard,
            holder_scan::{Budget, TaskPipeFd, task_pipe_fds},
            identity::Process,
        };
        use std::{
            os::unix::fs::MetadataExt,
            sync::atomic::{AtomicU64, Ordering},
        };
        let guard = Guard::acquire().unwrap();
        let mut group = Group::create().unwrap();
        let bytes = std::mem::size_of::<AtomicU64>();
        let shared = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(shared, libc::MAP_FAILED);
        let counter = shared.cast::<AtomicU64>();
        unsafe { counter.write(AtomicU64::new(0)) };
        let mut descriptors = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let read_end = unsafe { fs::File::from_raw_fd(descriptors[0]) };
        let write_end = unsafe { fs::File::from_raw_fd(descriptors[1]) };
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                libc::close(guard.fd());
                libc::close(descriptors[0]);
                if case == DummyCase::ExtraFd && libc::dup(descriptors[1]) < 0 {
                    libc::_exit(1);
                }
                let interval = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 1_000_000,
                };
                loop {
                    (*counter).fetch_add(1, Ordering::Relaxed);
                    libc::nanosleep(&interval, std::ptr::null_mut());
                }
            }
        }
        drop(write_end);
        let sample = || unsafe { (*counter).load(Ordering::Relaxed) };
        let result = (|| -> Result<(), Fault> {
            let worker = Process::bind(child as u32)?;
            let placement = if case == DummyCase::WrongRole {
                Role::A
            } else {
                Role::B
            };
            group.attach(placement, worker.pid)?;
            let initial = sample();
            let progress = |baseline| {
                let deadline = Instant::now() + Duration::from_secs(1);
                while sample() <= baseline {
                    if Instant::now() >= deadline {
                        return Err(Fault::Identity);
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                Ok(())
            };
            progress(initial)?;
            eprintln!("dummy phase=before initial={initial} observed={}", sample());
            if case == DummyCase::ExitedWorker {
                worker.kill()?;
                let until = Instant::now() + Duration::from_secs(1);
                while worker.alive()? {
                    if Instant::now() >= until {
                        return Err(Fault::Identity);
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                eprintln!("dummy worker_exit_observed=1");
            }
            let metadata = read_end.metadata()?;
            let deadline = Instant::now() + Duration::from_secs(2);
            let expected = vec![TaskPipeFd {
                tid: worker.pid,
                start_ticks: worker.birth,
                fd: descriptors[1] as u32,
                writes: true,
            }];
            let mut frozen = 0;
            let mut observed_holders = None;
            let inspection = group.inspect_while_frozen(
                &guard,
                deadline,
                [(Role::B, &worker)],
                &[crate::holder_scan::ManagerPipe {
                    identity: (metadata.dev(), metadata.ino()),
                    expected: &[(descriptors[0] as u32, false)],
                }],
                |_| {
                    frozen = sample();
                    let actual = task_pipe_fds(
                        Path::new("/proc"),
                        worker.pid,
                        (metadata.dev(), metadata.ino()),
                        &mut Budget {
                            deadline,
                            bytes_left: 262144,
                            entries_left: 8192,
                        },
                    )
                    .map_err(|_| Fault::Identity)?;
                    thread::sleep(Duration::from_millis(10));
                    let observed = sample();
                    eprintln!(
                        "dummy phase=frozen start={frozen} end={observed} holders={}",
                        actual.len()
                    );
                    if observed != frozen {
                        return Err(Fault::Identity);
                    }
                    observed_holders = Some(actual.len());
                    Ok(actual)
                },
                &expected,
            );
            if case != DummyCase::Positive {
                let expected_count = if case == DummyCase::ExtraFd {
                    Some(2)
                } else {
                    None
                };
                if !matches!(inspection, Err(Fault::Identity)) || observed_holders != expected_count
                {
                    return Err(Fault::Identity);
                }
                eprintln!("dummy rejected holders={observed_holders:?}");
                return Ok(());
            }
            inspection?;
            progress(frozen)?;
            eprintln!("dummy phase=thawed frozen={frozen} observed={}", sample());
            Ok(())
        })();
        let reaped = unsafe {
            libc::kill(child, libc::SIGKILL);
            let mut reaped = libc::waitpid(child, std::ptr::null_mut(), 0);
            while reaped < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                reaped = libc::waitpid(child, std::ptr::null_mut(), 0);
            }
            libc::munmap(shared, bytes);
            reaped
        };
        group.cleanup().unwrap();
        assert_eq!(reaped, child);
        eprintln!("dummy worker_reaped=1 group_removed=1");
        result.unwrap();
    }

    #[test]
    fn simulated_freezer_noncompletion_reaches_deadline() {
        let until = Instant::now() + Duration::from_millis(20);
        let result = wait_for_freezer_state(true, until, || Ok(false));
        assert!(matches!(result, Err(Fault::Identity)));
        assert!(Instant::now() >= until);
    }

    #[test]
    fn simulated_freezer_completion_after_deadline_is_rejected() {
        let until = Instant::now() + Duration::from_millis(20);
        let result = wait_for_freezer_state(true, until, || {
            thread::sleep(until.saturating_duration_since(Instant::now()));
            while Instant::now() < until {
                thread::yield_now();
            }
            Ok(true)
        });
        assert!(matches!(result, Err(Fault::Identity)));
    }

    #[test]
    fn expired_freeze_confirmation_never_enters_observation_or_comparison() {
        let expired = Instant::now() - Duration::from_millis(1);
        let result = after_freezer_confirmation(
            || wait_for_freezer_state(true, expired, || panic!("expired read")),
            || -> Result<(), Fault> { panic!("expired inspection") },
        );
        assert!(matches!(result, Err(Fault::Identity)));
    }

    #[test]
    #[ignore = "fixed Linux host with root cgroup access"]
    fn fixed_dummy_two_workers_hold_only_crossed_pipe_ends() {
        fixed_dummy_crossed_pipe_workers(false);
    }

    #[test]
    #[ignore = "fixed Linux host with root cgroup access"]
    fn fixed_dummy_exchanges_bytes_after_thaw() {
        fixed_dummy_crossed_pipe_workers(true);
    }

    fn fixed_dummy_crossed_pipe_workers(exchange: bool) {
        use crate::guard::Guard;
        use crate::holder_scan::{Budget, ManagerPipe, TaskPipeFd, task_pipe_fds};
        use crate::identity::Process;
        use std::os::unix::fs::MetadataExt;

        let guard = Guard::acquire().unwrap();
        let mut group = Group::create().unwrap();
        let (read_a, write_a) = io::pipe().unwrap();
        let (read_b, write_b) = io::pipe().unwrap();
        let pipe_id = |fd| {
            let m = fs::metadata(format!("/proc/self/fd/{fd}")).unwrap();
            (m.dev(), m.ino())
        };
        let ids = [pipe_id(read_a.as_raw_fd()), pipe_id(read_b.as_raw_fd())];
        let ends = [
            [read_a.as_raw_fd(), write_b.as_raw_fd()],
            [read_b.as_raw_fd(), write_a.as_raw_fd()],
        ];
        let mut children = Vec::new();
        let mut gates = Vec::<io::PipeWriter>::new();
        let result = (|| -> Result<(), Fault> {
            for index in 0..2 {
                use io::Read;
                let excluded = ends[1 - index];
                let (gate_read, gate_write) = io::pipe()?;
                let (mut ready_read, ready_write) = io::pipe()?;
                let pid = unsafe { libc::fork() };
                if pid < 0 {
                    return Err(io::Error::last_os_error().into());
                }
                if pid == 0 {
                    unsafe {
                        libc::close(guard.fd());
                        libc::close(gate_write.as_raw_fd());
                        for gate in &gates {
                            libc::close(gate.as_raw_fd());
                        }
                        for fd in excluded {
                            libc::close(fd);
                        }
                        libc::close(ready_read.as_raw_fd());
                        if libc::write(ready_write.as_raw_fd(), b"Y".as_ptr().cast(), 1) != 1 {
                            libc::_exit(1);
                        }
                        libc::close(ready_write.as_raw_fd());
                        if exchange {
                            let mut token = 0u8;
                            let released = libc::read(
                                gate_read.as_raw_fd(),
                                (&mut token as *mut u8).cast(),
                                1,
                            );
                            libc::close(gate_read.as_raw_fd());
                            if released != 1 || token != b'R' {
                                libc::_exit(2);
                            }
                            fixed_dummy_exchange_child(index, ends[index]);
                        }
                        loop {
                            libc::pause();
                        }
                    }
                }
                children.push(pid);
                drop(gate_read);
                gates.push(gate_write);
                drop(ready_write);
                let mut ready = libc::pollfd {
                    fd: ready_read.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut ready, 1, 1000) } != 1 {
                    return Err(Fault::Identity);
                }
                let mut byte = [0];
                ready_read.read_exact(&mut byte)?;
                if byte != *b"Y" {
                    return Err(Fault::Identity);
                }
            }
            drop((read_a, write_a, read_b, write_b));
            let a = Process::bind(children[0] as u32)?;
            let b = Process::bind(children[1] as u32)?;
            group.attach(Role::A, a.pid)?;
            group.attach(Role::B, b.pid)?;
            let deadline = Instant::now() + Duration::from_secs(2);
            let manager = ids.map(|identity| ManagerPipe {
                identity,
                expected: &[],
            });
            let observations = [(&a, 0, 0), (&a, 1, 1), (&b, 0, 1), (&b, 1, 0)];
            let expected = observations
                .iter()
                .map(|(child, direction, _pipe)| {
                    let child_index = usize::from(child.pid == b.pid);
                    vec![TaskPipeFd {
                        tid: child.pid,
                        start_ticks: child.birth,
                        fd: ends[child_index][*direction] as u32,
                        writes: *direction == 1,
                    }]
                })
                .collect::<Vec<_>>();
            group.inspect_while_frozen(
                &guard,
                deadline,
                [(Role::A, &a), (Role::B, &b)],
                &manager,
                |_| {
                    let mut budget = Budget {
                        deadline,
                        bytes_left: 262144,
                        entries_left: 8192,
                    };
                    observations
                        .iter()
                        .map(|(child, _, pipe)| {
                            task_pipe_fds(Path::new("/proc"), child.pid, ids[*pipe], &mut budget)
                                .map_err(|_| Fault::Identity)
                        })
                        .collect()
                },
                &expected,
            )?;
            if exchange {
                use io::Write;
                for gate in &mut gates {
                    gate.write_all(b"R")?;
                }
                gates.clear();
                let deadline = Instant::now() + Duration::from_secs(2);
                while a.alive()? || b.alive()? {
                    if Instant::now() >= deadline {
                        return Err(Fault::Identity);
                    }
                    thread::sleep(Duration::from_millis(2));
                }
            }
            Ok(())
        })();
        let mut all_reaped = true;
        for pid in children {
            unsafe {
                if !exchange || result.is_err() {
                    libc::kill(pid, libc::SIGKILL);
                }
                let mut status = 0;
                let reaped = loop {
                    let reaped = libc::waitpid(pid, &mut status, 0);
                    if reaped >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                    {
                        break reaped;
                    }
                };
                all_reaped &= reaped == pid
                    && (!exchange
                        || result.is_err()
                        || (libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0));
            }
        }
        group.cleanup().unwrap();
        assert!(all_reaped);
        result.unwrap();
    }

    unsafe fn fixed_dummy_exchange_child(index: usize, [input, output]: [i32; 2]) -> ! {
        let mut received = 0u8;
        let send = |byte: u8| unsafe {
            libc::write(output, (&byte as *const u8).cast(), 1) == 1 && libc::close(output) == 0
        };
        let mut receive = |expected| unsafe {
            libc::read(input, (&mut received as *mut u8).cast(), 1) == 1
                && received == expected
                && libc::read(input, (&mut received as *mut u8).cast(), 1) == 0
        };
        let passed = if index == 0 {
            send(b'Q') && receive(b'A')
        } else {
            receive(b'Q') && send(b'A')
        };
        unsafe { libc::_exit(if passed { 0 } else { 3 }) }
    }

    #[test]
    fn frozen_event_requires_a_unique_complete_value() {
        assert!(matches!(
            super::parse_frozen("populated 1\nfrozen 1\n"),
            Ok(true)
        ));
        assert!(matches!(super::parse_frozen("frozen 0\n"), Ok(false)));
        for invalid in [
            "",
            "populated 1\n",
            "frozen 1",
            "frozen 2\n",
            "frozen 1\nfrozen 1\n",
            "frozen\nfrozen 1\n",
        ] {
            assert!(super::parse_frozen(invalid).is_err());
        }
    }

    use super::*;

    #[test]
    fn control_write_remains_bound_to_directory_after_path_replacement() {
        let base = std::env::temp_dir().join(format!(
            "tempest-cgroup-fd-{}",
            crate::private_io::random_hex().unwrap()
        ));
        super::super::os::private_directory(&base).unwrap();
        let path = base.join("group");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("cgroup.kill"), b"0").unwrap();
        let pinned = fs::File::open(&path).unwrap();
        fs::rename(&path, base.join("original")).unwrap();
        fs::create_dir(&path).unwrap();
        fs::write(path.join("cgroup.kill"), b"0").unwrap();
        // Simulate replacement AFTER the caller's identity check. openat must
        // still target the held directory, never the newly named group.
        write(&pinned, "cgroup.kill", "1").unwrap();
        assert_eq!(fs::read(base.join("original/cgroup.kill")).unwrap(), b"1");
        assert_eq!(fs::read(path.join("cgroup.kill")).unwrap(), b"0");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn control_symlinks_and_parent_components_are_not_followed() {
        let base = std::env::temp_dir().join(format!(
            "tempest-cgroup-link-{}",
            crate::private_io::random_hex().unwrap()
        ));
        super::super::os::private_directory(&base).unwrap();
        fs::write(base.join("foreign"), b"0").unwrap();
        std::os::unix::fs::symlink(base.join("foreign"), base.join("cgroup.kill")).unwrap();
        let directory = fs::File::open(&base).unwrap();
        assert!(write(&directory, "cgroup.kill", "1").is_err());
        assert_eq!(fs::read(base.join("foreign")).unwrap(), b"0");
        for name in ["", ".", "..", "../foreign", "a/b"] {
            assert_eq!(component(name), Err(Fault::Path));
        }
        fs::remove_dir_all(base).unwrap();
    }
}
