use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, io, path::Path};

const LIMIT: u64 = 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonPlan {
    pub schema_version: u64,
    pub plan_id: String,
    pub created_ns: u64,
    pub stopping_rule: StoppingRule,
    pub slots: Vec<ComparisonSlot>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoppingRule {
    pub kind: String,
    pub slots: u64,
    pub retry: String,
    #[serde(default)]
    pub minimum_interval_seconds: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonSlot {
    pub slot_id: String,
    pub run_id: String,
    pub finding_configured: bool,
    pub retest_configured: bool,
    pub comparison_conditions: Value,
    pub evaluator_sha256: String,
}

#[derive(Debug)]
pub struct LoadedPlan {
    pub plan: ComparisonPlan,
    pub sha256: String,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn load(path: &Path) -> io::Result<LoadedPlan> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file() || metadata.len() > LIMIT {
        return Err(io::Error::other(
            "comparison plan must be a bounded regular file",
        ));
    }
    let bytes = fs::read(path)?;
    let plan: ComparisonPlan = serde_json::from_slice(&bytes)?;
    if plan.schema_version != 1
        || !identifier(&plan.plan_id)
        || plan.created_ns == 0
        || plan.stopping_rule.kind != "fixed_slots"
        || plan.stopping_rule.retry != "new_slot_only"
        || plan.stopping_rule.minimum_interval_seconds > 3600
        || plan.slots.is_empty()
        || plan.slots.len() > 1000
        || plan.stopping_rule.slots != plan.slots.len() as u64
    {
        return Err(io::Error::other("invalid comparison plan contract"));
    }
    let mut slot_ids = BTreeSet::new();
    let mut run_ids = BTreeSet::new();
    for slot in &plan.slots {
        if !identifier(&slot.slot_id)
            || !identifier(&slot.run_id)
            || !slot_ids.insert(&slot.slot_id)
            || !run_ids.insert(&slot.run_id)
            || !slot.comparison_conditions.is_object()
            || !digest(&slot.evaluator_sha256)
        {
            return Err(io::Error::other("invalid comparison plan slot"));
        }
    }
    Ok(LoadedPlan {
        plan,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    })
}

impl LoadedPlan {
    pub fn slot(
        &self,
        slot_id: &str,
        run_id: &str,
        evaluator: &str,
    ) -> io::Result<&ComparisonSlot> {
        let slot = self
            .plan
            .slots
            .iter()
            .find(|slot| slot.slot_id == slot_id)
            .ok_or_else(|| io::Error::other("comparison slot missing"))?;
        if slot.run_id != run_id || !slot.evaluator_sha256.eq_ignore_ascii_case(evaluator) {
            return Err(io::Error::other("comparison slot binding mismatch"));
        }
        Ok(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_reject_paths_and_accept_stable_ids() {
        assert!(identifier("model-a.001_retry-1"));
        for value in ["", ".", "..", "a/b", "a b"] {
            assert!(!identifier(value));
        }
    }
}
