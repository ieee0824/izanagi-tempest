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
    pub target_id: &'a str,
    pub approved_ips_revision: u64,
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
) -> io::Result<File> {
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
    close_permit(ledger, id).map(drop)
}

fn refused(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn close_permit(ledger: &File, id: u128) -> io::Result<File> {
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
    ledger.sync_all()?;
    Ok(record)
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
        target_id: "dummy-target",
        approved_ips_revision: 1,
    };

    fn check_revocation_pending(path: &std::path::Path) -> io::Result<()> {
        if path.try_exists()? {
            return Err(refused("revocation update pending"));
        }
        Ok(())
    }

    #[test]
    fn revocation_and_consumption_order_preserves_failed_records() {
        use std::os::unix::fs::OpenOptionsExt;
        use std::process::Command;

        let tmp = Ledger::new();
        let pending = tmp.0.join("pending");
        let ledger_path = tmp.0.join("records");
        fs::create_dir(&ledger_path).unwrap();
        let ledger = File::open(&ledger_path).unwrap();
        let lock_file = tmp.0.join("lock");
        File::create(&lock_file).unwrap();
        let lock = || {
            let fd = File::open(&lock_file).unwrap();
            assert_eq!(unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX) }, 0);
            fd
        };
        let permit = |id| Permit {
            id,
            expires_at: Instant::now() + Duration::from_secs(30),
            scope: SCOPE,
        };
        let consume_locked = |id| {
            let _guard = lock();
            check_revocation_pending(&pending)?;
            consume(&ledger, &permit(id), SCOPE, Instant::now())
        };
        let revoke_locked = |ledger_fd: &File, id| -> io::Result<()> {
            let _guard = lock();
            let marker = File::create_new(&pending)?;
            marker.sync_all()?;
            File::open(&tmp.0)?.sync_all()?;
            let result = revoke(ledger_fd, id);
            if result.is_ok()
                || result.as_ref().is_err_and(|error| {
                    error.to_string() == "manual login permit already consumed or revoked"
                })
            {
                fs::remove_file(&pending)?;
                File::open(&tmp.0)?.sync_all()?;
            }
            result
        };

        revoke_locked(&ledger, 21).unwrap();
        assert!(!pending.exists());
        assert_eq!(
            consume_locked(21).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        consume_locked(22).unwrap();
        let mut child = Command::new("/bin/sleep").arg("60").spawn().unwrap();
        let closure = revoke_locked(&ledger, 22);
        let still_running = child.try_wait().unwrap().is_none();
        if still_running {
            child.kill().unwrap();
        }
        child.wait().unwrap();
        assert_eq!(closure.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(
            still_running,
            "a ledger collision must not terminate the child"
        );
        assert!(!pending.exists());
        assert_eq!(
            consume_locked(22).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        let unsyncable = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(&ledger_path)
            .unwrap();
        assert_eq!(
            revoke_locked(&unsyncable, 23).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
        assert!(pending.is_file());
        let record = ledger_path.join(format!("{:032x}", 23));
        assert!(record.is_file());
        assert_eq!(
            consume_locked(23).unwrap_err().to_string(),
            "revocation update pending"
        );
        let mut checker = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "claude_offline::login_permit::tests::check_failed_revocation_from_fresh_process",
                "--ignored",
            ])
            .env("TEMPEST_TEST_FAILED_REVOCATION_FIXTURE", &tmp.0)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = checker.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = checker.kill();
                checker.wait().unwrap();
                panic!("revocation checker timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(status.success(), "revocation checker failed: {status}");
        assert!(pending.is_file());
        assert!(record.is_file());
        assert_eq!(fs::read_dir(&ledger_path).unwrap().count(), 3);
    }

    #[test]
    #[ignore = "subprocess fixture driven by revocation_and_consumption_order_preserves_failed_records"]
    fn check_failed_revocation_from_fresh_process() {
        let Some(path) = std::env::var_os("TEMPEST_TEST_FAILED_REVOCATION_FIXTURE") else {
            return;
        };
        let path = PathBuf::from(path);
        let lock = File::open(path.join("lock")).unwrap();
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
        let pending = path.join("pending");
        assert_eq!(
            check_revocation_pending(&pending).unwrap_err().to_string(),
            "revocation update pending"
        );
        let ledger_path = path.join("records");
        let ledger = File::open(&ledger_path).unwrap();
        let now = Instant::now();
        let permit = Permit {
            id: 23,
            expires_at: now + Duration::from_secs(30),
            scope: SCOPE,
        };
        assert_eq!(
            consume(&ledger, &permit, SCOPE, now)
                .unwrap_err()
                .to_string(),
            "manual login permit already consumed or revoked"
        );
        let record = ledger_path.join(format!("{:032x}", permit.id));
        assert!(record.is_file(), "record must remain closed");
    }

    #[test]
    fn unavailable_or_stale_revocation_state_does_not_consume() {
        #[derive(Clone, Copy)]
        struct Status<'a> {
            permit_id: u128,
            target_id: &'a str,
            revision: u64,
            valid_until: u64,
            revoked: bool,
        }

        let tmp = Ledger::new();
        let ledger = File::open(&tmp.0).unwrap();
        let now = Instant::now();
        let permit = Permit {
            id: 14,
            expires_at: now + Duration::from_secs(30),
            scope: SCOPE,
        };
        let status = Status {
            permit_id: permit.id,
            target_id: SCOPE.target_id,
            revision: 7,
            valid_until: 105,
            revoked: false,
        };
        // Model an authenticated snapshot read under the same management
        // lock that orders the current revision and final ledger consumption.
        let consume_with_status =
            |ledger: &File, snapshot: Option<Status<'_>>, current_revision: Option<u64>| {
                let status = snapshot.ok_or_else(|| refused("revocation state unavailable"))?;
                if status.permit_id != permit.id
                    || status.target_id != SCOPE.target_id
                    || Some(status.revision) != current_revision
                    || status.valid_until <= 100
                    || status.revoked
                {
                    return Err(refused("revocation state does not permit consumption"));
                }
                consume(ledger, &permit, SCOPE, now)
            };
        for (snapshot, current_revision) in [
            (None, Some(7)),
            (Some(status), None),
            (Some(status), Some(8)),
            (
                Some(Status {
                    valid_until: 100,
                    ..status
                }),
                Some(7),
            ),
            (
                Some(Status {
                    permit_id: 15,
                    ..status
                }),
                Some(7),
            ),
            (
                Some(Status {
                    target_id: "another-target",
                    ..status
                }),
                Some(7),
            ),
            (
                Some(Status {
                    revoked: true,
                    ..status
                }),
                Some(7),
            ),
        ] {
            assert_eq!(
                consume_with_status(&ledger, snapshot, current_revision)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 0);
        }

        let eligible = Ledger::new();
        let eligible_fd = File::open(&eligible.0).unwrap();
        consume_with_status(&eligible_fd, Some(status), Some(7)).unwrap();
        assert_eq!(
            consume_with_status(&eligible_fd, Some(status), Some(7))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::read_dir(&eligible.0).unwrap().count(), 1);

        revoke(&ledger, permit.id).unwrap();
        assert_eq!(
            consume_with_status(&ledger, Some(status), Some(7))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 1);
    }

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
    fn failed_directory_sync_preserves_the_closed_permit() {
        use std::os::unix::fs::OpenOptionsExt;

        let tmp = Ledger::new();
        let unsyncable = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(&tmp.0)
            .unwrap();
        let now = Instant::now();
        let permit = Permit {
            id: 4,
            expires_at: now + Duration::from_secs(60),
            scope: SCOPE,
        };
        assert_eq!(
            consume(&unsyncable, &permit, SCOPE, now)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBADF)
        );
        assert!(tmp.0.join(format!("{:032x}", permit.id)).is_file());
        let ledger = File::open(&tmp.0).unwrap();
        assert_eq!(
            consume(&ledger, &permit, SCOPE, now).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
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
