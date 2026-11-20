//! One-use authorization state for the fixed manual login.
use std::{
    ffi::CString,
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Scope<'a> {
    pub executable_sha256: &'a str,
    pub arguments: &'a [&'a str],
    pub authority: &'a str,
}

pub(super) struct Permit<'a> {
    pub id: u128,
    pub expires_at: std::time::Instant,
    pub scope: Scope<'a>,
}

/// The permit and expected scope must come from authenticated administrator
/// inputs. The ledger must be an already verified private directory and must
/// never be rolled back or cleared while its permit IDs can still be presented.
pub(super) fn consume(
    ledger: &File,
    permit: &Permit<'_>,
    expected: Scope<'_>,
    now: std::time::Instant,
) -> io::Result<()> {
    if permit.scope != expected {
        return Err(refused("manual login permit scope mismatch"));
    }
    if now >= permit.expires_at {
        return Err(refused("manual login permit expired"));
    }
    close_permit(ledger, permit.id)
}

/// Revocation and consumption compete for the same record. Either operation
/// permanently closes the permit ID in this ledger.
#[cfg(test)]
pub(super) fn revoke(ledger: &File, id: u128) -> io::Result<()> {
    close_permit(ledger, id)
}

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn close_permit(ledger: &File, id: u128) -> io::Result<()> {
    let name = CString::new(format!("{id:032x}")).expect("hex contains no NUL");
    let fd = unsafe {
        libc::openat(
            ledger.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return Err(if error.kind() == io::ErrorKind::AlreadyExists {
            refused("manual login permit already consumed or revoked")
        } else {
            error
        });
    }
    let record = unsafe { File::from_raw_fd(fd) };
    // Keep the record even if a sync fails. A caller can start the process
    // only after both syncs have succeeded.
    record.sync_all()?;
    ledger.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        time::{Duration, Instant, UNIX_EPOCH},
    };

    struct Ledger(PathBuf);

    impl Ledger {
        fn new() -> Self {
            use std::os::unix::fs::DirBuilderExt;
            let path = std::env::temp_dir().join(format!(
                "tempest-login-permit-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Ledger {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    const SCOPE: Scope<'static> = Scope {
        executable_sha256: "fixed-dummy-digest",
        arguments: &["auth", "login"],
        authority: "auth.example.invalid:443",
    };

    #[test]
    fn rejects_expired_wrong_scope_and_revoked_permits() {
        let tmp = Ledger::new();
        let ledger = File::open(&tmp.0).unwrap();
        let now = Instant::now();
        let permit = Permit {
            id: 1,
            expires_at: now + Duration::from_secs(60),
            scope: SCOPE,
        };
        assert_eq!(
            consume(&ledger, &permit, SCOPE, permit.expires_at)
                .unwrap_err()
                .to_string(),
            "manual login permit expired"
        );
        for scope in [
            Scope {
                executable_sha256: "other-dummy-digest",
                ..SCOPE
            },
            Scope {
                arguments: &["auth", "status"],
                ..SCOPE
            },
            Scope {
                authority: "other.example.invalid:443",
                ..SCOPE
            },
        ] {
            assert_eq!(
                consume(&ledger, &permit, scope, now)
                    .unwrap_err()
                    .to_string(),
                "manual login permit scope mismatch"
            );
        }
        assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 0);
        revoke(&ledger, permit.id).unwrap();
        assert_eq!(
            consume(&ledger, &permit, SCOPE, now).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn rejects_when_the_consumption_record_cannot_be_created() {
        let tmp = Ledger::new();
        let ledger = File::create(tmp.0.join("not-a-directory")).unwrap();
        let now = Instant::now();
        let permit = Permit {
            id: 3,
            expires_at: now + Duration::from_secs(60),
            scope: SCOPE,
        };
        let result = consume(&ledger, &permit, SCOPE, now);
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::ENOTDIR));
    }

    #[test]
    fn commits_before_start_and_rejects_concurrent_reuse() {
        let tmp = Ledger::new();
        let ledger = File::open(&tmp.0).unwrap();
        let now = Instant::now();
        let permit = Permit {
            id: 2,
            expires_at: now + Duration::from_secs(60),
            scope: SCOPE,
        };
        let barrier = std::sync::Barrier::new(2);
        let starts = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|threads| {
            for _ in 0..2 {
                threads.spawn(|| {
                    barrier.wait();
                    if consume(&ledger, &permit, SCOPE, now).is_ok() {
                        assert!(tmp.0.join(format!("{:032x}", permit.id)).is_file());
                        starts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(starts.into_inner(), 1);
        assert!(consume(&File::open(&tmp.0).unwrap(), &permit, SCOPE, now).is_err());
    }
}
