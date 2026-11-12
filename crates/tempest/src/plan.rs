//! Runtime resolution only: static validity does not choose an actor or prove authorization.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use tempest_model::{
    Diagnostic, ValidatedScenario,
    guest::{AccessKeys, ProbeRequest},
    scenario::{Check, Outcome, Setup},
};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActorSource {
    UniqueUser,
    Explicit,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Primary,
    Retest,
}

/// Necessary plan conditions only, never a claim that a repair succeeded.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RepairIntent {
    NotConfigured,
    DifferentActor,
    NoMatchingDenyCheck,
    TargetedRepairCheck,
}

#[derive(Debug, Clone)]
pub struct ExecutionPlan {
    actor: String,
    actor_source: ActorSource,
    setup: Setup,
    task: String,
    expect: Vec<Check>,
    self_check: Option<Check>,
    retest: Option<RetestPlan>,
}

#[derive(Debug, Clone)]
pub struct RetestPlan {
    actor: String,
    setup: Setup,
    checks: Vec<Check>,
    repair_intent: RepairIntent,
}

/// Audit metadata binds one seed's key and policy revision to one run/stage.
/// The raw worker key stays in memory and is omitted from serialization/Debug.
#[derive(Clone, Serialize)]
pub struct CredentialBinding {
    run_id: String,
    stage: Stage,
    actor: String,
    policy_sha256: String,
    access_key_sha256: String,
    #[serde(skip)]
    access_key_id: String,
}
impl std::fmt::Debug for CredentialBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialBinding")
            .field("run_id", &self.run_id)
            .field("stage", &self.stage)
            .field("actor", &self.actor)
            .field("policy_sha256", &self.policy_sha256)
            .field("access_key_sha256", &self.access_key_sha256)
            .finish()
    }
}

impl ExecutionPlan {
    pub fn resolve(validated: &ValidatedScenario, actor: Option<&str>) -> Result<Self, Diagnostic> {
        let input = validated.scenario();
        let (actor, actor_source) = match actor {
            Some(name) if input.setup.users.iter().any(|user| user.name == name) => {
                (name.to_owned(), ActorSource::Explicit)
            }
            Some(_) => return Err(Diagnostic::new("runtime.actor", "unknown setup user")),
            None if input.setup.users.len() == 1 => {
                (input.setup.users[0].name.clone(), ActorSource::UniqueUser)
            }
            None => {
                return Err(Diagnostic::new(
                    "runtime.actor",
                    "multiple setup users require an explicit --actor; static validation remains valid",
                ));
            }
        };
        let self_check = input.expected_finding.as_ref().map(|f| f.evidence.clone());
        let retest = input.retest.as_ref().map(|retest| {
            // Static validation resolved omission only for a unique setup user.
            let retest_actor = retest.user.as_ref().expect("validated retest user");
            let mut setup = input.setup.clone();
            setup
                .users
                .iter_mut()
                .find(|u| &u.name == retest_actor)
                .expect("validated retest user exists")
                .policy = retest.policy.clone();
            let repair_intent = match &self_check {
                None => RepairIntent::NotConfigured,
                Some(_) if retest_actor != &actor => RepairIntent::DifferentActor,
                Some(finding)
                    if retest.expect.iter().any(|check| {
                        check.api == finding.api
                            && check.resource == finding.resource
                            && check.result == Outcome::Deny
                    }) =>
                {
                    RepairIntent::TargetedRepairCheck
                }
                Some(_) => RepairIntent::NoMatchingDenyCheck,
            };
            RetestPlan {
                actor: retest_actor.clone(),
                setup,
                checks: retest.expect.clone(),
                repair_intent,
            }
        });
        Ok(Self {
            actor,
            actor_source,
            setup: input.setup.clone(),
            task: input.task.clone(),
            expect: input.expect.clone(),
            self_check,
            retest,
        })
    }
    pub fn actor(&self) -> &str {
        &self.actor
    }
    pub fn setup(&self) -> &Setup {
        &self.setup
    }
    pub fn expect(&self) -> &[Check] {
        &self.expect
    }
    pub fn self_check(&self) -> Option<&Check> {
        self.self_check.as_ref()
    }
    pub fn retest(&self) -> Option<&RetestPlan> {
        self.retest.as_ref()
    }
    pub fn bind(&self, run_id: &str, keys: &AccessKeys) -> Result<CredentialBinding, Diagnostic> {
        bind(run_id, Stage::Primary, &self.actor, &self.setup, keys)
    }
    /// Only task, one selected worker credential and public protocol instructions.
    pub fn agent_prompt(
        &self,
        run_id: &str,
        binding: &CredentialBinding,
    ) -> Result<String, Diagnostic> {
        let policy = &self
            .setup
            .users
            .iter()
            .find(|u| u.name == self.actor)
            .expect("resolved actor")
            .policy;
        if binding.run_id != run_id
            || binding.stage != Stage::Primary
            || binding.actor != self.actor
            || binding.policy_sha256 != policy_digest(policy)
        {
            return Err(Diagnostic::new(
                "runtime.credentials",
                "credential binding does not match the primary run, actor and policy revision",
            ));
        }
        Ok(format!(
            "{}\n\n認証情報と接続条件:\nUser: {}\nAccessKeyId: {}\nSecretAccessKey: local-dummy\nRegion: us-east-1\nEndpoint: http://127.0.0.1:4566\nS3: path-style\n\n最終出力の末尾にJSONオブジェクトを記載してください。形式: {{\"findings\":[{{\"api\":\"service:Action\",\"resource\":\"arn:...\",\"result\":\"allow\",\"note\":\"...\"}}]}}\n",
            self.task, self.actor, binding.access_key_id
        ))
    }
    /// Host preflight summary; intentionally contains neither setup nor expected resources.
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "actor": self.actor, "actor_source": self.actor_source,
            "self_check_configured": self.self_check.is_some(),
            "finding_configured": self.self_check.is_some(),
            "retest_configured": self.retest.is_some(),
            "retest_actor": self.retest.as_ref().map(|r| r.actor.as_str()),
            "repair_intent": self.retest.as_ref().map_or(RepairIntent::NotConfigured, |r| r.repair_intent),
            "runtime_checks": "not_performed"
        })
    }
}
impl RetestPlan {
    pub fn actor(&self) -> &str {
        &self.actor
    }
    pub fn setup(&self) -> &Setup {
        &self.setup
    }
    pub fn checks(&self) -> &[Check] {
        &self.checks
    }
    pub fn repair_intent(&self) -> RepairIntent {
        self.repair_intent
    }
    pub fn bind(&self, run_id: &str, keys: &AccessKeys) -> Result<CredentialBinding, Diagnostic> {
        bind(run_id, Stage::Retest, &self.actor, &self.setup, keys)
    }
}
impl CredentialBinding {
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    pub fn stage(&self) -> Stage {
        self.stage
    }
    pub fn actor(&self) -> &str {
        &self.actor
    }
    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }
    pub fn access_key_sha256(&self) -> &str {
        &self.access_key_sha256
    }

    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }
    pub fn probe(&self, check: &Check) -> ProbeRequest {
        ProbeRequest {
            access_key_id: self.access_key_id.clone(),
            api: check.api.clone(),
            resource: check.resource.clone(),
        }
    }
    /// A recorded key is a credential claim, never proof of SigV4 authentication.
    pub fn accepts_claim(&self, key: &str) -> bool {
        key == self.access_key_id
    }
}
fn bind(
    run_id: &str,
    stage: Stage,
    actor: &str,
    setup: &Setup,
    keys: &AccessKeys,
) -> Result<CredentialBinding, Diagnostic> {
    if run_id.is_empty() {
        return Err(Diagnostic::new(
            "runtime.run_id",
            "run ID must not be empty",
        ));
    }
    let users: BTreeSet<_> = setup.users.iter().map(|u| &u.name).collect();
    let supplied: BTreeSet<_> = keys.keys().collect();
    let mut unique = HashSet::new();
    if users != supplied
        || keys
            .values()
            .any(|key| key.is_empty() || !unique.insert(key))
    {
        return Err(Diagnostic::new(
            "runtime.seed",
            "seed key registry must contain one distinct nonempty key for every setup user",
        ));
    }
    let policy = &setup
        .users
        .iter()
        .find(|u| u.name == actor)
        .expect("resolved actor")
        .policy;
    let access_key_id = keys[actor].clone();
    Ok(CredentialBinding {
        run_id: run_id.to_owned(),
        stage,
        actor: actor.to_owned(),
        policy_sha256: policy_digest(policy),
        access_key_sha256: format!("{:x}", Sha256::digest(access_key_id.as_bytes())),
        access_key_id,
    })
}

fn policy_digest(policy: &tempest_model::policy::Policy) -> String {
    let bytes = serde_json::to_vec(policy).expect("typed JSON policy");
    format!("{:x}", Sha256::digest(bytes))
}
