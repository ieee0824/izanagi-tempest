//! Bounded, root-owned PIDFD ledger independent of a baseline's Worker values.
use super::{contract::Role, identity::Process, os::Fault, watchdog::DeadGuardian};
use serde::Serialize;
use std::{
    io,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RecordId(u64);

struct Entry {
    id: RecordId,
    process: Process,
    role: Role,
    direct: bool,
    attached: bool,
}

#[derive(Default)]
pub(super) struct Registry {
    entries: Vec<Entry>,
    next_id: u64,
}
#[derive(Default, Clone, Copy, Serialize)]
pub(super) struct Counts {
    pub(super) registry_total: usize,
    pub(super) direct: usize,
    pub(super) descendants: usize,
    pub(super) unattached: usize,
    pub(super) dead_pidfds: usize,
    pub(super) reaped: usize,
    pub(super) reap_unconfirmed: usize,
    pub(super) cgroup_populated: Option<bool>,
    pub(super) unconfirmed_reason: Option<Unconfirmed>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Unconfirmed {
    Echild,
    PidfdAlive,
    EvidenceMissing,
    SignalFailed,
    WaitFailed,
}
impl Counts {
    pub(super) fn fail(&mut self, reason: Unconfirmed) {
        self.unconfirmed_reason.get_or_insert(reason);
    }
}
impl Registry {
    pub(super) fn counts(&self) -> Counts {
        let direct = self.entries.iter().filter(|entry| entry.direct).count();
        Counts {
            registry_total: self.entries.len(),
            direct,
            descendants: self.entries.len() - direct,
            unattached: self
                .entries
                .iter()
                .filter(|entry| entry.direct && !entry.attached)
                .count(),
            reap_unconfirmed: direct,
            ..Counts::default()
        }
    }
    pub(super) fn track(
        &mut self,
        role: Role,
        process: &Process,
        direct: bool,
    ) -> Result<RecordId, Fault> {
        if let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.process.pid == process.pid)
        {
            return if entry.process.birth == process.birth
                && entry.role == role
                && (!direct || entry.direct)
            {
                Ok(entry.id)
            } else {
                Err(Fault::Identity)
            };
        }
        if self.entries.len() >= 48 {
            return Err(Fault::Identity);
        }
        let process = process.duplicate()?;
        let next_id = self.next_id.checked_add(1).ok_or(Fault::Identity)?;
        let id = RecordId(next_id);
        self.next_id = next_id;
        self.entries.push(Entry {
            id,
            process,
            role,
            direct,
            attached: !direct,
        });
        Ok(id)
    }
    pub(super) fn attached(&mut self, id: RecordId) -> Result<(), Fault> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.id == id && entry.direct && !entry.attached)
            .ok_or(Fault::Identity)?;
        entry.attached = true;
        Ok(())
    }
    // Only called after waitpid returned this record's direct child with a
    // terminal status. IDs are never reused, including after finish/cleanup.
    pub(super) fn reaped(&mut self, id: RecordId) -> Result<(), Fault> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.id == id && entry.direct)
            .ok_or(Fault::Identity)?;
        self.entries.remove(index);
        Ok(())
    }
    pub(super) fn finish(&mut self) -> Result<(), Fault> {
        for entry in &self.entries {
            if entry.direct || entry.process.alive()? {
                return Err(Fault::Identity);
            }
        }
        self.entries.clear();
        Ok(())
    }
    pub(super) fn stop_and_reap(
        &mut self,
        _proof: &DeadGuardian<'_>,
        counts: &mut Counts,
    ) -> Result<(), Fault> {
        self.stop_and_reap_verified(counts)
    }

    // The only production entry is the proof-taking wrapper above. Keeping
    // the operation private also lets tests exercise real owned child waits
    // without manufacturing the guardian ownership proof.
    fn stop_and_reap_verified(&mut self, counts: &mut Counts) -> Result<(), Fault> {
        let populated = counts.cgroup_populated;
        *counts = self.counts();
        counts.cgroup_populated = populated;
        let mut failure = None;
        for entry in &self.entries {
            if entry.direct {
                if let Err(error) = entry.process.kill() {
                    counts.fail(Unconfirmed::SignalFailed);
                    failure.get_or_insert(error);
                }
            }
        }
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            let mut alive = false;
            counts.dead_pidfds = 0;
            for entry in &self.entries {
                match entry.process.alive() {
                    Ok(false) => counts.dead_pidfds += 1,
                    Ok(true) => alive = true,
                    Err(error) => {
                        counts.fail(Unconfirmed::EvidenceMissing);
                        return Err(error);
                    }
                }
            }
            if !alive {
                break;
            }
            if Instant::now() >= until {
                counts.fail(Unconfirmed::PidfdAlive);
                return Err(Fault::Kernel(libc::EBUSY));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        for entry in &self.entries {
            if entry.direct {
                let mut status = 0;
                let waited =
                    unsafe { libc::waitpid(entry.process.pid as i32, &mut status, libc::WNOHANG) };
                if waited != entry.process.pid as i32
                    || !(libc::WIFEXITED(status) || libc::WIFSIGNALED(status))
                {
                    let error = if waited < 0 {
                        let error = io::Error::last_os_error();
                        counts.fail(if error.raw_os_error() == Some(libc::ECHILD) {
                            Unconfirmed::Echild
                        } else {
                            Unconfirmed::WaitFailed
                        });
                        error.into()
                    } else {
                        counts.fail(Unconfirmed::WaitFailed);
                        Fault::Identity
                    };
                    failure.get_or_insert(error);
                } else {
                    counts.reaped += 1;
                    counts.reap_unconfirmed -= 1;
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        self.entries.clear();
        Ok(())
    }
}

#[cfg(test)]
mod record_tests {
    use super::*;
    use std::os::fd::{AsRawFd, OwnedFd};

    struct BlockedChild {
        process: Process,
        _gate: OwnedFd,
    }

    impl BlockedChild {
        fn spawn() -> Self {
            let (read, write) = crate::os::pipe().unwrap();
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                // Use only async-signal-safe operations after fork in the
                // multithreaded test harness. The parent retains the gate.
                unsafe {
                    libc::close(write.as_raw_fd());
                    let mut byte = 0_u8;
                    while libc::read(read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) < 0 {}
                    libc::_exit(0);
                }
            }
            let process = match Process::bind(pid as u32) {
                Ok(process) => process,
                Err(error) => {
                    // This fresh child has not been reaped and cannot reuse
                    // its PID; after bind, all test cleanup uses its PIDFD.
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                        libc::waitpid(pid, std::ptr::null_mut(), 0);
                    }
                    panic!("could not bind test child: {error:?}");
                }
            };
            Self {
                process,
                _gate: write,
            }
        }
    }

    impl Drop for BlockedChild {
        fn drop(&mut self) {
            let _ = self.process.kill();
            let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // A successful registry recovery may already have reaped it.
            // P_PIDFD cannot target a process that later reused its PID.
            unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    self.process.fd() as u32,
                    &mut status,
                    libc::WEXITED,
                );
            }
        }
    }

    #[test]
    fn recovery_counts_confirm_unattached_child_death_and_reap() {
        let child = BlockedChild::spawn();
        let mut registry = Registry::default();
        registry.track(Role::A, &child.process, true).unwrap();
        let mut counts = Counts {
            cgroup_populated: Some(false),
            ..Counts::default()
        };

        registry.stop_and_reap_verified(&mut counts).unwrap();

        assert_eq!(counts.registry_total, 1);
        assert_eq!(counts.direct, 1);
        assert_eq!(counts.descendants, 0);
        assert_eq!(counts.unattached, 1);
        assert_eq!(counts.dead_pidfds, 1);
        assert_eq!(counts.reaped, 1);
        assert_eq!(counts.reap_unconfirmed, 0);
        assert_eq!(counts.cgroup_populated, Some(false));
        assert_eq!(counts.unconfirmed_reason, None);
        assert!(!child.process.alive().unwrap());
        assert!(registry.entries.is_empty());
    }

    #[test]
    fn unrecorded_external_reap_retains_echild_failure_evidence() {
        let child = BlockedChild::spawn();
        let mut registry = Registry::default();
        let record = registry.track(Role::A, &child.process, true).unwrap();
        registry.attached(record).unwrap();
        child.process.kill().unwrap();
        let mut poll = libc::pollfd {
            fd: child.process.fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 2000) }, 1);
        assert_ne!(poll.revents & libc::POLLIN, 0);
        let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    child.process.fd() as u32,
                    &mut status,
                    libc::WEXITED,
                )
            },
            0
        );
        assert_eq!(status.si_code, libc::CLD_KILLED);
        assert_eq!(unsafe { status.si_status() }, libc::SIGKILL);
        // Deliberately omit the normal reaper's RecordId update. Readable
        // PIDFD alone must not turn this bookkeeping inconsistency into success.
        let mut counts = Counts::default();
        assert_eq!(
            registry.stop_and_reap_verified(&mut counts),
            Err(Fault::Kernel(libc::ECHILD))
        );
        assert_eq!(counts.registry_total, 1);
        assert_eq!(counts.direct, 1);
        assert_eq!(counts.descendants, 0);
        assert_eq!(counts.unattached, 0);
        assert_eq!(counts.dead_pidfds, 1);
        assert_eq!(counts.reaped, 0);
        assert_eq!(counts.reap_unconfirmed, 1);
        assert_eq!(counts.cgroup_populated, None);
        assert_eq!(counts.unconfirmed_reason, Some(Unconfirmed::Echild));
        assert_eq!(registry.entries.len(), 1);
        assert_eq!(registry.entries[0].id, record);
    }

    #[test]
    fn stale_record_cannot_remove_a_later_record_for_the_same_process() {
        // Exercise ledger transitions without sending a signal or waiting on
        // the current process. Kernel terminal waits are covered by fixtures.
        let process = Process::bind(std::process::id()).unwrap();
        let mut registry = Registry::default();
        let first = registry.track(Role::A, &process, true).unwrap();
        assert_eq!(registry.track(Role::A, &process, false).unwrap(), first);
        registry.reaped(first).unwrap();
        registry.finish().unwrap();
        let second = registry.track(Role::A, &process, true).unwrap();
        assert_ne!(first, second);
        assert_eq!(registry.reaped(first), Err(Fault::Identity));
        assert_eq!(registry.attached(first), Err(Fault::Identity));
        registry.attached(second).unwrap();
        assert_eq!(registry.attached(second), Err(Fault::Identity));
        registry.reaped(second).unwrap();
        assert_eq!(registry.reaped(second), Err(Fault::Identity));
    }

    #[test]
    fn snapshot_cannot_promote_descendant_to_direct_child() {
        let process = Process::bind(std::process::id()).unwrap();
        let mut registry = Registry::default();
        let descendant = registry.track(Role::A, &process, false).unwrap();
        assert_eq!(
            registry.track(Role::A, &process, false).unwrap(),
            descendant
        );
        assert_eq!(
            registry.track(Role::A, &process, true),
            Err(Fault::Identity)
        );
        assert_eq!(
            registry.track(Role::B, &process, false),
            Err(Fault::Identity)
        );
        assert_eq!(registry.attached(descendant), Err(Fault::Identity));
        assert_eq!(registry.reaped(descendant), Err(Fault::Identity));
        assert_eq!(
            registry.track(Role::A, &process, false).unwrap(),
            descendant
        );
    }
}
