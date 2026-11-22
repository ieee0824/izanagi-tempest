//! Parent-updated, fork-shared signed revocation freshness; never an operation cap.
use super::host_login_diagnostic::SharedLease;
use crate::host_channel::ReceiptLease;
use std::{io, sync::Mutex, time::Instant};

pub(super) struct Snapshot {
    pub(super) lease: ReceiptLease,
    pub(super) state_sha256: [u8; 32],
}

struct Cached {
    revision: u64,
    state_sha256: [u8; 32],
}

pub(super) struct Freshness {
    owner: libc::pid_t,
    operation_deadline: Instant,
    shared: SharedLease,
    cached: Mutex<Cached>,
}

impl Freshness {
    pub(super) fn new(mut initial: Snapshot, operation_deadline: Instant) -> io::Result<Self> {
        initial.lease.expires_at = initial.lease.expires_at.min(operation_deadline);
        if initial.lease.sequence == 0 || Instant::now() >= initial.lease.expires_at {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(Self {
            owner: unsafe { libc::getpid() },
            operation_deadline,
            shared: SharedLease::new(&initial.lease)?,
            cached: Mutex::new(Cached {
                revision: initial.lease.sequence,
                state_sha256: initial.state_sha256,
            }),
        })
    }

    pub(super) fn current_or_update(
        &self,
        read: impl FnOnce() -> io::Result<Snapshot>,
    ) -> io::Result<Instant> {
        let result = (|| {
            let current = self.shared.current()?;
            if unsafe { libc::getpid() } != self.owner {
                return Ok(current.expires_at);
            }
            let mut cached = self.cached.lock().map_err(|_| io::ErrorKind::Other)?;
            // Never give late new signatures a chance to revive the old lease.
            self.shared.current()?;
            let mut candidate = read()?;
            self.shared.current()?;
            if candidate.lease.sequence < cached.revision
                || candidate.lease.sequence == cached.revision
                    && candidate.state_sha256 != cached.state_sha256
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            if candidate.lease.sequence > cached.revision {
                candidate.lease.expires_at =
                    candidate.lease.expires_at.min(self.operation_deadline);
                if Instant::now() >= candidate.lease.expires_at {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                self.shared.publish(&candidate.lease)?;
                cached.revision = candidate.lease.sequence;
                cached.state_sha256 = candidate.state_sha256;
            }
            // Identical revision reads (including after wall-clock changes)
            // retain the original monotonic expiry rather than publishing again.
            self.shared.current().map(|lease| lease.expires_at)
        })();
        if result.is_err() {
            self.shared.stop();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn snapshot(revision: u64, digest: u8, expires_at: Instant) -> Snapshot {
        Snapshot {
            lease: ReceiptLease {
                expires_at,
                sequence: revision,
            },
            state_sha256: [digest; 32],
        }
    }

    #[test]
    fn only_new_revision_can_renew_and_operation_deadline_always_caps_it() {
        let now = Instant::now();
        let hard = now + Duration::from_secs(5);
        let state = Freshness::new(snapshot(1, 1, now + Duration::from_secs(1)), hard).unwrap();
        let same = state
            .current_or_update(|| Ok(snapshot(1, 1, now + Duration::from_secs(30))))
            .unwrap();
        assert!(same <= now + Duration::from_secs(1));
        let next = state
            .current_or_update(|| Ok(snapshot(2, 2, now + Duration::from_secs(30))))
            .unwrap();
        assert!(next > now + Duration::from_secs(1) && next <= hard);
    }

    #[test]
    fn expired_or_invalid_state_never_revives() {
        let now = Instant::now();
        let state = Freshness::new(
            snapshot(1, 1, now + Duration::from_secs(5)),
            now + Duration::from_secs(30),
        )
        .unwrap();
        assert!(
            state
                .current_or_update(|| Ok(snapshot(1, 2, now + Duration::from_secs(10))))
                .is_err()
        );
        assert!(
            state
                .current_or_update(|| Ok(snapshot(2, 2, now + Duration::from_secs(10))))
                .is_err()
        );
        let state = Freshness::new(
            snapshot(1, 1, Instant::now() + Duration::from_millis(20)),
            now + Duration::from_secs(30),
        )
        .unwrap();
        assert!(
            state
                .current_or_update(|| {
                    std::thread::sleep(Duration::from_millis(30));
                    Ok(snapshot(2, 2, Instant::now() + Duration::from_secs(10)))
                })
                .is_err()
        );
        assert!(
            state
                .current_or_update(|| Ok(snapshot(3, 3, Instant::now() + Duration::from_secs(10))))
                .is_err()
        );
    }

    #[test]
    fn forked_child_observes_parent_without_reading_or_renewing() {
        let now = Instant::now();
        let state = Freshness::new(
            snapshot(1, 1, now + Duration::from_secs(1)),
            now + Duration::from_secs(5),
        )
        .unwrap();
        let (mut parent, mut child) = std::os::unix::net::UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        child
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            std::panic::set_hook(Box::new(|_| unsafe { libc::_exit(101) }));
            drop(parent);
            use std::io::{Read, Write};
            let mut byte = [0];
            if child.read_exact(&mut byte).is_err() {
                unsafe { libc::_exit(1) }
            }
            let valid = state
                .current_or_update(|| panic!("child must never read signed originals"))
                .is_ok_and(|expires| expires > now + Duration::from_secs(1));
            let sent = child.write_all(&[u8::from(valid)]).is_ok();
            unsafe { libc::_exit(i32::from(!valid || !sent)) }
        }
        drop(child);
        use std::io::{Read, Write};
        state
            .current_or_update(|| Ok(snapshot(2, 2, now + Duration::from_secs(4))))
            .unwrap();
        parent.write_all(&[1]).unwrap();
        let mut byte = [0];
        parent.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [1]);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
    }
}
