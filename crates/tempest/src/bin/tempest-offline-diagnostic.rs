//! Fixed offline version diagnostic with private evidence verification.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux {
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::{self, Read, Write},
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
        path::Path,
        process::ExitCode,
    };
    use tempest::direct_evidence::{
        Binding, EvidenceRef, IsolationProvenance, Scope, Source, verify_isolation_provenance,
    };
    use tempest_linux_probe::OfflineObservation;

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn verify_generation(
        directory: &File,
        parent: &IsolationProvenance,
        claim: Option<&IsolationProvenance>,
    ) -> bool {
        verify_isolation_provenance(directory, Some(parent), claim).is_ok()
    }

    fn seal(observation: &OfflineObservation) -> io::Result<bool> {
        let mut nonce = [0; 16];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        let run_id: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let root = Path::new("/var/lib").join(format!("tempest-offline-evidence-{run_id}"));
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        let result = (|| {
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(&root)?;
            let bytes = serde_json::to_vec(&serde_json::json!({
                "kind": "fixed_offline_version_diagnostic",
                "run_id": run_id,
                "supervisor_observation": observation,
            }))?;
            let parent = IsolationProvenance {
                slot_id: "fixed-offline-version-diagnostic".into(),
                target_id: format!(
                    "{}:{}",
                    observation.work_identity.0, observation.work_identity.1
                ),
                observer_id: "offline-grant-supervisor".into(),
                evidence: EvidenceRef {
                    source: Source::OsObservation,
                    scope: Scope::ProcessIsolation,
                    binding: Binding {
                        run_id,
                        profile_sha256: digest(b"fixed_offline_version_diagnostic:v1"),
                        binary_sha256: observation.expected_binary_sha256.into(),
                    },
                    artifact_sha256: digest(&bytes),
                },
            };
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root.join("process-isolation.json"))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            directory.sync_all()?;
            Ok(verify_generation(&directory, &parent, Some(&parent)))
        })();
        fs::remove_dir_all(&root)?;
        result
    }

    fn report(exit: ExitCode, evidence_verified: bool) -> ExitCode {
        let status = if evidence_verified {
            "verified"
        } else {
            "missing"
        };
        let _ = writeln!(io::stderr().lock(), "offline diagnostic evidence: {status}");
        exit
    }

    pub fn run() -> ExitCode {
        let (exit, observation) = tempest_linux_probe::claude_offline_version_observed();
        let evidence_verified = observation
            .as_ref()
            .is_some_and(|value| seal(value).unwrap_or(false));
        report(exit, evidence_verified)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn diagnostic_evidence_cannot_change_exit_or_enter_direct_reporting() {
            let root =
                std::env::temp_dir().join(format!("tempest-offline-test-{}", std::process::id()));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            let directory = File::open(&root).unwrap();
            let parent = IsolationProvenance {
                slot_id: "fixed-offline-version-diagnostic".into(),
                target_id: "fixed-target".into(),
                observer_id: "fixed-observer".into(),
                evidence: EvidenceRef {
                    source: Source::OsObservation,
                    scope: Scope::ProcessIsolation,
                    binding: Binding {
                        run_id: "00".repeat(16),
                        profile_sha256: digest(b"fixed profile"),
                        binary_sha256: digest(b"fixed binary"),
                    },
                    artifact_sha256: digest(b"fixed diagnostic"),
                },
            };
            let missing = verify_generation(&directory, &parent, Some(&parent));
            assert!(!missing);
            assert_eq!(report(ExitCode::SUCCESS, missing), ExitCode::SUCCESS);
            fs::write(root.join("process-isolation.json"), b"changed diagnostic").unwrap();
            let mismatch = verify_generation(&directory, &parent, Some(&parent));
            assert!(!mismatch);
            assert_eq!(report(ExitCode::SUCCESS, mismatch), ExitCode::SUCCESS);
            fs::remove_dir_all(root).unwrap();
            assert_eq!(report(ExitCode::FAILURE, true), ExitCode::FAILURE);
            let diagnostic = serde_json::json!({
                "kind":"fixed_offline_version_diagnostic",
                "run_id":"00".repeat(16),
                "supervisor_observation": {},
            });
            assert!(
                serde_json::from_value::<tempest::direct_evidence::DirectInvestigationReport>(
                    diagnostic
                )
                .is_err()
            );
        }
    }
}

fn main() -> std::process::ExitCode {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return linux::run();

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    std::process::ExitCode::FAILURE
}
