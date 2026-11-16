//! Bounded, root-owned PIDFD ledger independent of a baseline's Worker values.
use super::{contract::Role, identity::Process, os::Fault, watchdog::DeadGuardian};
use serde::Serialize;
use std::{
    io,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RecordId(u64);

/// Data-only evidence; no namespace or root descriptor survives cleanup.
#[derive(Default)]
#[allow(dead_code)] // Connected to the fixed two-run supervisor in the next step.
pub(super) struct StateSequence {
    active: Option<([u8; 16], [RecordId; 3])>,
    previous: Option<([u8; 16], [RecordId; 3])>,
    completed: u8,
    failed: bool,
}

#[allow(dead_code)]
impl StateSequence {
    pub(super) fn begin(
        &mut self,
        run: u8,
        nonce: [u8; 16],
        records: [RecordId; 3],
    ) -> Result<(), Fault> {
        let unique =
            records[0] != records[1] && records[0] != records[2] && records[1] != records[2];
        let fresh = self.previous.is_none_or(|(old_nonce, old_records)| {
            nonce != old_nonce
                && records
                    .iter()
                    .all(|id| old_records.iter().all(|old| id.0 > old.0))
        });
        if self.failed
            || self.active.is_some()
            || run != self.completed + 1
            || run > 2
            || !unique
            || !fresh
        {
            self.failed = true;
            return Err(Fault::Identity);
        }
        self.active = Some((nonce, records));
        Ok(())
    }

    pub(super) fn finish(
        &mut self,
        nonce: [u8; 16],
        records: [RecordId; 3],
        cleanup_complete: bool,
    ) -> Result<(), Fault> {
        if self.failed || self.active != Some((nonce, records)) || !cleanup_complete {
            self.failed = true;
            return Err(Fault::Identity);
        }
        self.previous = self.active.take();
        self.completed += 1;
        Ok(())
    }
}

#[cfg(test)]
mod state_sequence_tests {
    use super::*;
    fn ids(start: u64) -> [RecordId; 3] {
        [RecordId(start), RecordId(start + 1), RecordId(start + 2)]
    }
    #[test]
    fn two_generations_require_completed_cleanup() {
        let mut sequence = StateSequence::default();
        sequence.begin(1, [1; 16], ids(1)).unwrap();
        sequence.finish([1; 16], ids(1), true).unwrap();
        sequence.begin(2, [2; 16], ids(4)).unwrap();
        sequence.finish([2; 16], ids(4), true).unwrap();
        assert!(sequence.begin(3, [3; 16], ids(7)).is_err());
    }
    #[test]
    fn invalid_order_nonce_records_and_cleanup_fail_closed() {
        let mut sequence = StateSequence::default();
        assert!(sequence.begin(2, [2; 16], ids(4)).is_err());
        for (nonce, records, cleanup) in [
            ([2; 16], ids(1), true),
            ([1; 16], ids(4), true),
            ([1; 16], ids(1), false),
        ] {
            let mut sequence = StateSequence::default();
            sequence.begin(1, [1; 16], ids(1)).unwrap();
            assert!(sequence.finish(nonce, records, cleanup).is_err());
            assert!(sequence.begin(2, [3; 16], ids(7)).is_err());
        }
        for (nonce, records) in [([1; 16], ids(4)), ([2; 16], ids(1))] {
            let mut sequence = StateSequence::default();
            sequence.begin(1, [1; 16], ids(1)).unwrap();
            sequence.finish([1; 16], ids(1), true).unwrap();
            assert!(sequence.begin(2, nonce, records).is_err());
        }
    }
}

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
    pub(super) snapshot_stage: Option<SnapshotStage>,
    pub(super) snapshot_reason: Option<&'static str>,
    pub(super) snapshot_errno: Option<i32>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SnapshotStage {
    ReadMembers,
    Bind,
    Membership,
    Track,
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
        let snapshot = (
            counts.snapshot_stage,
            counts.snapshot_reason,
            counts.snapshot_errno,
        );
        *counts = self.counts();
        counts.cgroup_populated = populated;
        (
            counts.snapshot_stage,
            counts.snapshot_reason,
            counts.snapshot_errno,
        ) = snapshot;
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
    fn pinned_dead_child_can_be_reaped_when_fresh_binding_is_rejected() {
        let child = BlockedChild::spawn();
        let mut registry = Registry::default();
        let record = registry.track(Role::A, &child.process, true).unwrap();
        registry.attached(record).unwrap();
        assert_eq!(
            Process::snapshot_read_error(-1, Fault::Kernel(libc::EACCES)),
            Fault::Kernel(libc::EACCES)
        );
        assert_eq!(
            Process::snapshot_read_error(child.process.fd(), Fault::Kernel(libc::ENOENT)),
            Fault::Kernel(libc::ENOENT)
        );
        child.process.kill().unwrap();
        let mut poll = libc::pollfd {
            fd: child.process.fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 3000) }, 1);
        assert_eq!(
            Process::snapshot_read_error(child.process.fd(), Fault::Kernel(libc::ENOENT)),
            Fault::ExitedAfterListing
        );
        // A fresh snapshot cannot bind this unreaped zombie as live, while
        // the existing PIDFD ledger still proves which direct child to reap.
        assert!(matches!(
            Process::bind(child.process.pid),
            Err(Fault::Identity)
        ));
        assert!(matches!(
            Process::bind_snapshot(child.process.pid),
            Err(Fault::ExitedAfterListing)
        ));
        let mut counts = Counts::default();
        registry.stop_and_reap_verified(&mut counts).unwrap();
        assert_eq!(counts.dead_pidfds, 1);
        assert_eq!(counts.reaped, 1);
        assert_eq!(counts.reap_unconfirmed, 0);
        assert_eq!(counts.unconfirmed_reason, None);
        assert!(registry.entries.is_empty());
    }

    #[test]
    fn recovery_counts_confirm_unattached_child_death_and_reap() {
        let child = BlockedChild::spawn();
        let mut registry = Registry::default();
        registry.track(Role::A, &child.process, true).unwrap();
        let mut counts = Counts {
            cgroup_populated: Some(false),
            snapshot_stage: Some(SnapshotStage::Bind),
            snapshot_reason: Some("kernel"),
            snapshot_errno: Some(libc::ESRCH),
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
        assert_eq!(counts.snapshot_stage, Some(SnapshotStage::Bind));
        assert_eq!(counts.snapshot_reason, Some("kernel"));
        assert_eq!(counts.snapshot_errno, Some(libc::ESRCH));
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
