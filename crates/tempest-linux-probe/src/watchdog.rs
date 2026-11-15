//! Root-only lease guardian. Recovery never races a live mutating owner.
use super::{
    cgroup::{Group, RecoveryGroup},
    guard::Guard,
    identity::Process,
    lease,
    os::{self, Fault},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    time::{Duration, Instant},
};

const RUN: &str = "/run/tempest-linux-isolation-probe";
const LEASE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Reason {
    OwnerDead,
    LeaseExpired,
    ExplicitDone,
    Relinquish,
    RecoveryFailed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Transition {
    OwnerStopping,
    WatchdogOwned,
    Recovered,
    Released,
    Failed,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Status {
    pub(super) reason: Reason,
    pub(super) trigger: Reason,
    pub(super) transition: Transition,
    pub(super) owner_dead: bool,
    pub(super) elapsed_ms: u64,
}

pub(super) struct DeadGuardian<'a> {
    _guard: &'a Guard,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Startup,
    ParentOwned,
    DeadObserved,
    Relinquished,
    Done,
    ParentRecovery,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ParentTransition {
    GuardianDead,
    ParentOwned,
    Recovered,
    Failed,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ParentReason {
    GuardianDied,
    RecoveryFailed,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum DrainState {
    NotRead,
    Empty,
    Complete,
    Partial,
    Invalid,
}
#[derive(Clone, Copy, Serialize)]
pub(super) struct ParentStatus {
    schema_version: u8,
    reason: ParentReason,
    pub(super) transition: ParentTransition,
    guardian_dead: bool,
    guardian_reaped: bool,
    guardian_exit: Option<i32>,
    guardian_signal: Option<i32>,
    status_drain: DrainState,
    counts: super::registry::Counts,
    elapsed_ms: u64,
}

fn status(fd: i32, started: Instant, trigger: Reason, transition: Transition, owner_dead: bool) {
    let value = Status {
        reason: if transition == Transition::Failed {
            Reason::RecoveryFailed
        } else {
            trigger
        },
        trigger,
        transition,
        owner_dead,
        elapsed_ms: started.elapsed().as_millis().min(3_600_000) as u64,
    };
    if let Ok(mut bytes) = serde_json::to_vec(&value) {
        bytes.push(b'\n');
        if bytes.len() <= 512 {
            let until = Instant::now() + Duration::from_millis(50);
            loop {
                if unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) }
                    == bytes.len() as isize
                {
                    break;
                }
                if !matches!(
                    io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN | libc::EINTR)
                ) || Instant::now() >= until
                {
                    break;
                }
                let mut poll = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut poll, 1, 5) } < 0 {
                    break;
                }
            }
        }
    }
}

fn remove_run(pinned: &File) -> Result<(), Fault> {
    let current = match fs::symlink_metadata(RUN) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let original = pinned.metadata()?;
    if !current.is_dir()
        || current.uid() != 0
        || current.mode() & 0o7777 != 0o700
        || (current.dev(), current.ino()) != (original.dev(), original.ino())
    {
        return Err(Fault::Identity);
    }
    fs::remove_dir_all(RUN)?;
    Ok(())
}

fn recover(
    mut group: Group,
    owner: &Process,
    pinned: &File,
    output: i32,
    started: Instant,
    trigger: Reason,
) -> Result<(), Fault> {
    let mut dead = !owner.alive()?;
    if trigger != Reason::Relinquish && !dead {
        status(output, started, trigger, Transition::OwnerStopping, false);
        owner.kill()?;
        let until = Instant::now() + Duration::from_secs(3);
        while owner.alive()? {
            if Instant::now() >= until {
                return Err(Fault::WatchdogRecovery);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        dead = true;
    }
    if trigger != Reason::Relinquish && !dead {
        return Err(Fault::WatchdogRecovery);
    }
    // Explicit relinquish is acknowledged only after the parent has forbidden
    // every future Group operation and dropped/disarmed its Group handle.
    status(output, started, trigger, Transition::WatchdogOwned, dead);
    group.arm();
    group.recover()?;
    remove_run(pinned)?;
    status(output, started, trigger, Transition::Recovered, dead);
    Ok(())
}

fn child(owner: Process, pinned: File, read: OwnedFd, output: OwnedFd, guard: &Guard) -> ! {
    lease::clear();
    // Losing an audit reader must not interrupt resource recovery.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    let started = Instant::now();
    let mut trigger = Reason::RecoveryFailed;
    let result = (|| {
        os::syscall(unsafe { libc::setsid() })?;
        os::close_except(&[
            owner.fd(),
            pinned.as_raw_fd(),
            read.as_raw_fd(),
            output.as_raw_fd(),
            guard.fd(),
        ])?;
        let mut group = Group::create()?;
        let (dev, ino) = group.identity();
        let mut ack = [0_u8; 20];
        ack[..4].copy_from_slice(b"TSG1");
        ack[4..12].copy_from_slice(&dev.to_ne_bytes());
        ack[12..].copy_from_slice(&ino.to_ne_bytes());
        // An atomic pipe ACK transfers startup ownership to the parent. While
        // the parent owns it, even error unwinding must not cleanup the group.
        group.disarm();
        let written = unsafe { libc::write(output.as_raw_fd(), ack.as_ptr().cast(), ack.len()) };
        if written != 20 {
            if written <= 0 {
                group.arm();
            }
            return Err(Fault::Identity);
        }
        let mut renewed = Instant::now();
        let mut control_closed = false;
        loop {
            let mut polls = [
                libc::pollfd {
                    fd: if control_closed { -1 } else { read.as_raw_fd() },
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: owner.fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let result = unsafe { libc::poll(polls.as_mut_ptr(), 2, 50) };
            if result < 0 {
                if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            }
            let poll = &polls[0];
            if poll.revents & libc::POLLIN != 0 {
                let mut value = 0_u8;
                if unsafe { libc::read(poll.fd, (&mut value as *mut u8).cast(), 1) } != 1 {
                    break;
                }
                match value {
                    b'H' => renewed = Instant::now(),
                    b'D' => {
                        if Path::new(super::cgroup::ROOT).exists() || Path::new(RUN).exists() {
                            break;
                        }
                        status(
                            output.as_raw_fd(),
                            started,
                            Reason::ExplicitDone,
                            Transition::Released,
                            false,
                        );
                        return Ok(());
                    }
                    b'R' => {
                        trigger = Reason::Relinquish;
                        break;
                    }
                    _ => break,
                }
            }
            if !owner.alive()? {
                trigger = Reason::OwnerDead;
                break;
            }
            if renewed.elapsed() >= LEASE {
                trigger = Reason::LeaseExpired;
                break;
            }
            if poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                // Pipe closure precedes pidfd readiness during normal exit.
                // Stop polling the closed pipe and wait for owner death or the
                // lease, rather than misclassifying that ordering as failure.
                control_closed = true;
            }
        }
        recover(group, &owner, &pinned, output.as_raw_fd(), started, trigger)
    })();
    if result.is_err() {
        status(
            output.as_raw_fd(),
            started,
            trigger,
            Transition::Failed,
            !owner.alive().unwrap_or(true),
        );
    }
    unsafe {
        libc::_exit(if result.is_ok() { 0 } else { 1 });
    }
}

pub(super) struct Watchdog {
    pid: i32,
    control: OwnedFd,
    input: OwnedFd,
    guardian: OwnedFd,
    active: bool,
    last: Option<Status>,
    mode: Mode,
    recovery: Option<RecoveryGroup>,
    started: Instant,
}

impl Watchdog {
    pub(super) fn start(guard: &Guard) -> Result<(Self, Group), Fault> {
        lease::clear();
        let owner = Process::bind(std::process::id())?;
        let pinned = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(RUN)?;
        let (read, write) = os::pipe()?;
        let (input, output) = os::pipe()?;
        for fd in [&write, &output] {
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error().into());
            }
            os::syscall(unsafe {
                libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
            })?;
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error().into());
        }
        if pid == 0 {
            child(owner, pinned, read, output, guard);
        }
        drop(read);
        drop(output);
        let raw_guardian = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if raw_guardian < 0 {
            // PID is our own fresh unreaped child. Keep every resource marked
            // unconfirmed if the kernel cannot give us a stable death handle.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
            return Err(Fault::GuardianUnconfirmed);
        }
        let guardian = unsafe { OwnedFd::from_raw_fd(raw_guardian as i32) };
        let mut watchdog = Self {
            pid,
            control: write,
            input,
            guardian,
            active: true,
            last: None,
            mode: Mode::Startup,
            recovery: None,
            started: Instant::now(),
        };
        let startup = (|| {
            let mut poll = libc::pollfd {
                fd: watchdog.input.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, 5000) } <= 0 {
                return Err(Fault::Identity);
            }
            let mut ack = [0_u8; 20];
            if unsafe {
                libc::read(
                    watchdog.input.as_raw_fd(),
                    ack.as_mut_ptr().cast(),
                    ack.len(),
                )
            } != 20
                || &ack[..4] != b"TSG1"
            {
                return Err(Fault::Identity);
            }
            let identity = (
                u64::from_ne_bytes(ack[4..12].try_into().map_err(|_| Fault::Identity)?),
                u64::from_ne_bytes(ack[12..].try_into().map_err(|_| Fault::Identity)?),
            );
            lease::activate(watchdog.control.as_raw_fd(), watchdog.guardian.as_raw_fd());
            lease::pulse()?;
            let group = Group::adopt(identity)?;
            watchdog.recovery = Some(group.recovery_handle()?);
            Ok(group)
        })();
        let group = match startup {
            Ok(group) => group,
            Err(_) => {
                watchdog.stop_startup()?;
                return Err(Fault::GuardianStartupStopped);
            }
        };
        watchdog.mode = Mode::ParentOwned;
        Ok((watchdog, group))
    }

    fn stop_startup(&mut self) -> Result<(), Fault> {
        lease::forbid();
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.guardian.as_raw_fd(),
                libc::SIGKILL,
                0,
                0,
            )
        };
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            return Err(Fault::GuardianUnconfirmed);
        }
        let _ = self.wait();
        if self.active {
            return Err(Fault::GuardianUnconfirmed);
        }
        // A reaped guardian can no longer create a group after our return.
        // Any already created but unproved group remains visible and causes
        // resources_removed=false; never adopt it from its fixed path alone.
        Ok(())
    }

    pub(super) fn write_metadata(&self) -> Result<(), Fault> {
        use std::io::Write;
        let bytes = serde_json::to_vec(
            &serde_json::json!({"watchdog_pid":self.pid,"status_fd":self.input.as_raw_fd()}),
        )
        .map_err(|_| Fault::Identity)?;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(Path::new(RUN).join("watchdog.channel"))?
            .write_all(&bytes)?;
        Ok(())
    }

    pub(super) fn status(&self) -> Option<Status> {
        self.last
    }

    pub(super) fn guardian_alive(&self) -> Option<bool> {
        let mut poll = libc::pollfd {
            fd: self.guardian.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
            return None;
        }
        if poll.revents & libc::POLLIN != 0 {
            Some(false)
        } else if poll.revents == 0 {
            Some(true)
        } else {
            None
        }
    }

    fn drain_status(&mut self) -> DrainState {
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0_u8; 512];
            let count = unsafe {
                libc::read(
                    self.input.as_raw_fd(),
                    chunk.as_mut_ptr().cast(),
                    chunk.len(),
                )
            };
            if count < 0 {
                if io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN) {
                    break;
                }
                return DrainState::Invalid;
            }
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..count as usize]);
            if bytes.len() > 2048 {
                return DrainState::Invalid;
            }
        }
        if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
            return DrainState::Partial;
        }
        for line in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            if line.len() > 512 {
                return DrainState::Invalid;
            }
            match serde_json::from_slice(line) {
                Ok(status) => self.last = Some(status),
                Err(_) => return DrainState::Invalid,
            }
        }
        if bytes.is_empty() {
            DrainState::Empty
        } else {
            DrainState::Complete
        }
    }

    pub(super) fn parent_recovery(
        &mut self,
        guard: &Guard,
        pinned: &File,
        registry: &mut super::registry::Registry,
        wait_for_death: bool,
    ) -> Option<Vec<ParentStatus>> {
        if self.mode != Mode::ParentOwned {
            return None;
        }
        let mut poll = libc::pollfd {
            fd: self.guardian.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, if wait_for_death { 5000 } else { 0 }) } <= 0
            || poll.revents & libc::POLLIN == 0
        {
            return None;
        }
        lease::forbid();
        self.mode = Mode::DeadObserved;
        let waited = self.wait(); // Terminal nonzero status still proves reap.
        let guardian_exit = match waited {
            Ok(()) => Some(0),
            Err(Fault::Child(code)) => Some(code),
            _ => None,
        };
        let guardian_signal = match waited {
            Err(Fault::ChildSignal(signal, _)) => Some(signal),
            _ => None,
        };
        let drain = if self.active {
            DrainState::NotRead
        } else {
            self.drain_status()
        };
        let started = self.started;
        let make = |transition, reaped, counts| ParentStatus {
            schema_version: 1,
            reason: if transition == ParentTransition::Failed {
                ParentReason::RecoveryFailed
            } else {
                ParentReason::GuardianDied
            },
            transition,
            guardian_dead: true,
            guardian_reaped: reaped,
            guardian_exit,
            guardian_signal,
            status_drain: drain,
            counts,
            elapsed_ms: started.elapsed().as_millis().min(3_600_000) as u64,
        };
        let mut counts = registry.counts();
        let mut statuses = vec![make(ParentTransition::GuardianDead, !self.active, counts)];
        if self.active {
            counts.fail(super::registry::Unconfirmed::EvidenceMissing);
            statuses.push(make(ParentTransition::Failed, false, counts));
            return Some(statuses);
        }
        // Never reclaim after an acknowledged normal release, nor after R/D.
        if matches!(drain, DrainState::Invalid | DrainState::Partial)
            || self.last.is_some_and(|status| {
                matches!(
                    status.transition,
                    Transition::Released | Transition::Recovered
                )
            })
        {
            counts.fail(super::registry::Unconfirmed::EvidenceMissing);
            statuses.push(make(ParentTransition::Failed, true, counts));
            return Some(statuses);
        }
        self.mode = Mode::ParentRecovery;
        let proof = DeadGuardian { _guard: guard };
        statuses.push(make(ParentTransition::ParentOwned, true, counts));
        let recovered = (|| {
            let group = self.recovery.take().ok_or(Fault::Identity)?;
            group.recover(&proof, registry, &mut counts)?;
            remove_run(pinned)?;
            if Path::new(super::cgroup::ROOT).exists() || Path::new(RUN).exists() {
                return Err(Fault::Identity);
            }
            Ok::<_, Fault>(())
        })();
        statuses.push(match recovered {
            Ok(()) => make(ParentTransition::Recovered, true, counts),
            Err(_) => {
                counts.fail(super::registry::Unconfirmed::EvidenceMissing);
                make(ParentTransition::Failed, true, counts)
            }
        });
        Some(statuses)
    }

    fn receive(&mut self, target: Transition) -> Result<(), Fault> {
        let until = Instant::now() + Duration::from_secs(5);
        let mut bytes = Vec::new();
        loop {
            if Instant::now() >= until {
                return Err(Fault::WatchdogRecovery);
            }
            let mut poll = libc::pollfd {
                fd: self.input.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut poll, 1, 20) } < 0 {
                return Err(io::Error::last_os_error().into());
            }
            if poll.revents & libc::POLLIN != 0 {
                let mut byte = 0_u8;
                if unsafe { libc::read(poll.fd, (&mut byte as *mut u8).cast(), 1) } != 1 {
                    return Err(Fault::WatchdogRecovery);
                }
                if byte == b'\n' {
                    let value: Status =
                        serde_json::from_slice(&bytes).map_err(|_| Fault::Identity)?;
                    self.last = Some(value);
                    bytes.clear();
                    if value.transition == Transition::Failed {
                        return Err(Fault::WatchdogRecovery);
                    }
                    if value.transition == target {
                        return Ok(());
                    }
                } else {
                    if bytes.len() >= 512 {
                        return Err(Fault::Identity);
                    }
                    bytes.push(byte);
                }
            } else if poll.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(Fault::WatchdogRecovery);
            }
        }
    }

    fn wait(&mut self) -> Result<(), Fault> {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if result == self.pid {
                if !libc::WIFEXITED(status) && !libc::WIFSIGNALED(status) {
                    return Err(Fault::Identity);
                }
                self.active = false;
                return if libc::WIFEXITED(status) {
                    if libc::WEXITSTATUS(status) == 0 {
                        Ok(())
                    } else {
                        Err(Fault::Child(libc::WEXITSTATUS(status)))
                    }
                } else if libc::WIFSIGNALED(status) {
                    Err(Fault::ChildSignal(
                        libc::WTERMSIG(status),
                        libc::WCOREDUMP(status),
                    ))
                } else {
                    Err(Fault::Identity)
                };
            }
            if result < 0 {
                return Err(io::Error::last_os_error().into());
            }
            if Instant::now() >= until {
                return Err(Fault::WatchdogRecovery);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn send_command(&mut self, byte: u8) -> Result<(), Fault> {
        lease::forbid();
        if unsafe { libc::write(self.control.as_raw_fd(), (&byte as *const u8).cast(), 1) } != 1 {
            // One byte to the nonblocking pipe is atomic. Failure means no
            // command was delivered; retain ParentOwned for death/reap proof.
            return Err(Fault::WatchdogRecovery);
        }
        self.mode = if byte == b'R' {
            Mode::Relinquished
        } else {
            Mode::Done
        };
        Ok(())
    }

    fn command(&mut self, byte: u8, target: Transition) -> Result<(), Fault> {
        self.send_command(byte)?;
        let received = self.receive(target);
        let waited = self.wait();
        received?;
        waited
    }
    pub(super) fn finish(&mut self) -> Result<(), Fault> {
        self.command(b'D', Transition::Released)
    }
    pub(super) fn relinquish(&mut self) -> Result<(), Fault> {
        self.command(b'R', Transition::Recovered)
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        if self.active && self.mode == Mode::ParentOwned {
            let _ = self.relinquish();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_delivery_requires_a_successful_atomic_write() {
        let (read, control) = os::pipe().unwrap();
        let (input, _output) = os::pipe().unwrap();
        let process = Process::bind(std::process::id()).unwrap();
        let mut watch = Watchdog {
            pid: std::process::id() as i32,
            control,
            input,
            guardian: os::duplicate_fd(process.fd()).unwrap(),
            active: false,
            last: None,
            mode: Mode::ParentOwned,
            recovery: None,
            started: Instant::now(),
        };
        let flags = unsafe { libc::fcntl(watch.control.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(
            unsafe {
                libc::fcntl(
                    watch.control.as_raw_fd(),
                    libc::F_SETFL,
                    flags | libc::O_NONBLOCK,
                )
            },
            0
        );
        let block = [0_u8; 4096];
        while unsafe {
            libc::write(
                watch.control.as_raw_fd(),
                block.as_ptr().cast(),
                block.len(),
            )
        } > 0
        {}
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );
        assert_eq!(watch.send_command(b'R'), Err(Fault::WatchdogRecovery));
        assert!(watch.mode == Mode::ParentOwned);
        drop(read);
        assert_eq!(watch.send_command(b'R'), Err(Fault::WatchdogRecovery));
        assert!(watch.mode == Mode::ParentOwned);
        let (reader, writer) = os::pipe().unwrap();
        watch.control = writer;
        watch.send_command(b'R').unwrap();
        assert!(watch.mode == Mode::Relinquished);
        let mut byte = 0_u8;
        assert_eq!(
            unsafe { libc::read(reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) },
            1
        );
        assert_eq!(byte, b'R');
        lease::clear();
    }
}
