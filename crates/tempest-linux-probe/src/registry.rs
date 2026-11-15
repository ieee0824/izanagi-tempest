//! Bounded, root-owned PIDFD ledger independent of a baseline's Worker values.
use super::{contract::Role, identity::Process, os::Fault, watchdog::DeadGuardian};
use serde::Serialize;
use std::{
    io,
    time::{Duration, Instant},
};

struct Entry {
    process: Process,
    role: Role,
    direct: bool,
    attached: bool,
}
#[derive(Default)]
pub(super) struct Registry {
    entries: Vec<Entry>,
}
#[derive(Default, Clone, Copy, Serialize)]
pub(super) struct Counts {
    pub(super) direct: usize,
    pub(super) descendants: usize,
    pub(super) unattached: usize,
    pub(super) dead_pidfds: usize,
    pub(super) reaped: usize,
}
impl Registry {
    pub(super) fn track(
        &mut self,
        role: Role,
        process: &Process,
        direct: bool,
    ) -> Result<(), Fault> {
        if let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.process.pid == process.pid)
        {
            return if entry.process.birth == process.birth && entry.role == role {
                Ok(())
            } else {
                Err(Fault::Identity)
            };
        }
        if self.entries.len() >= 48 {
            return Err(Fault::Identity);
        }
        self.entries.push(Entry {
            process: process.duplicate()?,
            role,
            direct,
            attached: !direct,
        });
        Ok(())
    }
    pub(super) fn attached(&mut self, process: &Process) -> Result<(), Fault> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| {
                entry.process.pid == process.pid
                    && entry.process.birth == process.birth
                    && entry.direct
            })
            .ok_or(Fault::Identity)?;
        entry.attached = true;
        Ok(())
    }
    // Only called after waitpid returned this fresh, unreaped child PID.
    pub(super) fn reaped(&mut self, pid: u32) {
        self.entries
            .retain(|entry| !(entry.direct && entry.process.pid == pid));
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
    pub(super) fn stop_and_reap(&mut self, _proof: &DeadGuardian<'_>) -> Result<Counts, Fault> {
        let mut counts = Counts::default();
        let mut failure = None;
        for entry in &self.entries {
            if entry.direct {
                counts.direct += 1;
                counts.unattached += usize::from(!entry.attached);
                if let Err(error) = entry.process.kill() {
                    failure.get_or_insert(error);
                }
            } else {
                counts.descendants += 1;
            }
        }
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            let mut alive = false;
            for entry in &self.entries {
                alive |= entry.process.alive()?;
            }
            if !alive {
                break;
            }
            if Instant::now() >= until {
                return Err(Fault::Kernel(libc::EBUSY));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        counts.dead_pidfds = self.entries.len();
        for entry in &self.entries {
            if entry.direct {
                let mut status = 0;
                let waited =
                    unsafe { libc::waitpid(entry.process.pid as i32, &mut status, libc::WNOHANG) };
                if waited != entry.process.pid as i32
                    || !(libc::WIFEXITED(status) || libc::WIFSIGNALED(status))
                {
                    failure.get_or_insert(if waited < 0 {
                        io::Error::last_os_error().into()
                    } else {
                        Fault::Identity
                    });
                } else {
                    counts.reaped += 1;
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        self.entries.clear();
        Ok(counts)
    }
}
