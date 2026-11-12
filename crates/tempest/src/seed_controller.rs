//! One-shot seed ownership for the run controller. Does not own VM lifetime.
use crate::plan::{CredentialBinding, ExecutionPlan, Stage};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tempest_model::{
    Diagnostic,
    guest::{AccessKeys, ProbeRequest},
    scenario::{Check, Setup},
};

#[derive(Default)]
enum SeedState {
    #[default]
    Unattempted,
    Awaiting,
    Bound(CredentialBinding),
    Aborted,
}

/// Exclusive run reservation is retained on disk even after failure or drop.
/// Restart/resume and retry within this run are deliberately unsupported.
pub struct SeedController {
    run_id: String,
    directory: PathBuf,
    plan: ExecutionPlan,
    primary: SeedState,
    retest: SeedState,
    aborted: bool,
    used_key_hashes: HashSet<String>,
    registries: BTreeMap<String, BTreeMap<String, String>>,
}

fn failure(reason: &str) -> Diagnostic {
    Diagnostic::new("runtime.seed", reason)
}

impl SeedController {
    pub fn create(root: &Path, run_id: &str, plan: ExecutionPlan) -> io::Result<Self> {
        if run_id.is_empty()
            || run_id.len() > 128
            || !run_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(io::Error::other("invalid run ID"));
        }
        let root = root.canonicalize()?;
        let metadata = root.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(io::Error::other("runs root must be owned with mode 0700"));
        }
        let directory = root.join(run_id);
        // mkdir is exclusive. Never reconstruct a controller from an old run.
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        File::open(root)?.sync_all()?;
        Ok(Self {
            run_id: run_id.to_owned(),
            directory,
            plan,
            primary: SeedState::Unattempted,
            retest: SeedState::Unattempted,
            aborted: false,
            used_key_hashes: HashSet::new(),
            registries: BTreeMap::new(),
        })
    }

    fn state(&self, stage: Stage) -> &SeedState {
        match stage {
            Stage::Primary => &self.primary,
            Stage::Retest => &self.retest,
        }
    }
    fn state_mut(&mut self, stage: Stage) -> &mut SeedState {
        match stage {
            Stage::Primary => &mut self.primary,
            Stage::Retest => &mut self.retest,
        }
    }
    fn abort(&mut self) {
        self.aborted = true;
        self.primary = SeedState::Aborted;
        self.retest = SeedState::Aborted;
    }
    fn binding(&self, stage: Stage) -> Result<&CredentialBinding, Diagnostic> {
        if self.aborted
            || matches!(self.primary, SeedState::Awaiting)
            || matches!(self.retest, SeedState::Awaiting)
        {
            return Err(failure("run aborted; discard VM and use a new run ID"));
        }
        match self.state(stage) {
            SeedState::Bound(binding) => Ok(binding),
            _ => Err(failure("no verified seed response for this stage")),
        }
    }

    /// Persist intent before publishing the request. Cancellation leaves Awaiting:
    /// no credentials become usable and no second transport call is permitted.
    /// The caller must discard the VM on Err, cancellation, or any later abort.
    /// Retest transport must target its own new VM, never the primary VM.
    pub async fn seed<F, Fut>(&mut self, stage: Stage, send: F) -> Result<(), Diagnostic>
    where
        F: FnOnce(Setup) -> Fut,
        Fut: Future<Output = Result<AccessKeys, Diagnostic>>,
    {
        if self.aborted
            || matches!(self.primary, SeedState::Awaiting)
            || matches!(self.retest, SeedState::Awaiting)
            || !matches!(self.state(stage), SeedState::Unattempted)
        {
            self.abort();
            return Err(failure(
                "seed already attempted or run aborted; do not resend",
            ));
        }
        let setup = match stage {
            Stage::Primary => self.plan.setup().clone(),
            Stage::Retest => self
                .plan
                .retest()
                .ok_or_else(|| failure("retest not configured"))?
                .setup()
                .clone(),
        };
        *self.state_mut(stage) = SeedState::Awaiting;
        let marker = match stage {
            Stage::Primary => "primary-seed-attempt.json",
            Stage::Retest => "retest-seed-attempt.json",
        };
        let persist = || -> io::Result<()> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(self.directory.join(marker))?;
            serde_json::to_writer(
                &mut file,
                &serde_json::json!({
                    "run_id": self.run_id, "stage":stage, "state":"seed_attempt_started"
                }),
            )?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            File::open(&self.directory)?.sync_all()
        };
        if persist().is_err() {
            self.abort();
            return Err(failure(
                "seed intent could not be persisted; transport not invoked",
            ));
        }
        let keys = match send(setup).await {
            Ok(keys) => keys,
            Err(_) => {
                self.abort();
                return Err(failure(
                    "seed failed or response lost; discard VM, do not resend",
                ));
            }
        };
        let hashes: HashSet<String> = keys
            .values()
            .map(|key| format!("{:x}", Sha256::digest(key.as_bytes())))
            .collect();
        if !hashes.is_disjoint(&self.used_key_hashes) {
            self.abort();
            return Err(failure("seed reused a prior stage key; discard VM"));
        }
        let binding = match stage {
            Stage::Primary => self.plan.bind(&self.run_id, &keys),
            Stage::Retest => self
                .plan
                .retest()
                .expect("configured retest")
                .bind(&self.run_id, &keys),
        };
        match binding {
            Ok(binding) => {
                let name = match stage {
                    Stage::Primary => "primary",
                    Stage::Retest => "retest",
                };
                self.registries.insert(
                    name.into(),
                    keys.iter()
                        .map(|(name, key)| {
                            (
                                name.clone(),
                                format!("{:x}", Sha256::digest(key.as_bytes())),
                            )
                        })
                        .collect(),
                );
                self.used_key_hashes.extend(hashes);
                *self.state_mut(stage) = SeedState::Bound(binding);
                Ok(())
            }
            Err(_) => {
                self.abort();
                Err(failure("invalid seed registry; discard VM, do not resend"))
            }
        }
    }

    pub fn agent_prompt(&self) -> Result<String, Diagnostic> {
        self.plan
            .agent_prompt(&self.run_id, self.binding(Stage::Primary)?)
    }
    pub fn probe(&self, stage: Stage, check: &Check) -> Result<ProbeRequest, Diagnostic> {
        Ok(self.binding(stage)?.probe(check))
    }
    /// Registry comparison only, not proof of authentication or authorization.
    pub fn accepts_claim(&self, stage: Stage, key: &str) -> Result<bool, Diagnostic> {
        Ok(self.binding(stage)?.accepts_claim(key))
    }
    pub fn binding_metadata(&self, stage: Stage) -> Result<impl Serialize + '_, Diagnostic> {
        self.binding(stage)
    }
    pub fn registry_metadata(&self, stage: Stage) -> Result<&BTreeMap<String, String>, Diagnostic> {
        self.binding(stage)?;
        Ok(&self.registries[match stage {
            Stage::Primary => "primary",
            Stage::Retest => "retest",
        }])
    }
}
