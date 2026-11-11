use crate::policy::Policy;
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;
use std::{collections::BTreeMap, time::Duration};

/// Option without treating an explicitly supplied null as omission.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioInput {
    pub id: String,
    pub title: String,
    pub target: String,
    pub auth_mode: String,
    pub setup: Setup,
    pub task: String,
    pub expect: Vec<Check>,
    #[serde(default, deserialize_with = "present")]
    pub expected_finding: Option<Finding>,
    #[serde(default, deserialize_with = "present")]
    pub retest: Option<Retest>,
    #[serde(default)]
    pub success_criteria: Vec<Criterion>,
    #[serde(default)]
    pub budget: Budget,
    #[serde(default)]
    pub deviation: Deviation,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Setup {
    pub users: Vec<User>,
    #[serde(default)]
    pub buckets: Vec<Bucket>,
    #[serde(default)]
    pub queues: Vec<Queue>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    pub policy: Policy,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bucket {
    pub name: String,
    #[serde(default)]
    pub objects: Vec<Object>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    pub key: String,
    pub body: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Queue {
    pub name: String,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub api: String,
    pub resource: String,
    pub result: Outcome,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Allow,
    Deny,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub description: String,
    pub evidence: Check,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retest {
    #[serde(default, deserialize_with = "present")]
    pub user: Option<String>,
    pub policy: Policy,
    pub expect: Vec<Check>,
}
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Criterion {
    Text(String),
    Named(BTreeMap<String, String>),
}
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Budget {
    pub max_calls: u64,
    pub timeout: Timeout,
}
impl Default for Budget {
    fn default() -> Self {
        Self {
            max_calls: 50,
            timeout: Timeout(Duration::from_secs(900)),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeout(pub Duration);
impl<'de> Deserialize<'de> for Timeout {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        let (digits, multiplier) = [("ms", 1_u64), ("s", 1000), ("m", 60_000), ("h", 3_600_000)]
            .into_iter()
            .find_map(|(unit, mul)| text.strip_suffix(unit).map(|n| (n, mul)))
            .ok_or_else(|| {
                de::Error::custom("timeout requires nonnegative integer and ms/s/m/h unit")
            })?;
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(de::Error::custom("timeout requires nonnegative integer"));
        }
        let millis = digits
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(multiplier))
            .ok_or_else(|| de::Error::custom("timeout overflow"))?;
        Ok(Self(Duration::from_millis(millis)))
    }
}
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Deviation {
    pub allow: Vec<Value>,
    pub deny: Vec<Value>,
}

/// Constructed only by semantic validation. Static validity is no runtime guarantee.
#[derive(Debug, Clone)]
pub struct ValidatedScenario {
    pub(crate) scenario: ScenarioInput,
}
impl ValidatedScenario {
    pub fn scenario(&self) -> &ScenarioInput {
        &self.scenario
    }
    pub fn finding_present(&self) -> bool {
        self.scenario.expected_finding.is_some()
    }
    pub fn retest_present(&self) -> bool {
        self.scenario.retest.is_some()
    }
    pub fn deviation_semantics_unchecked(&self) -> bool {
        !self.scenario.deviation.allow.is_empty() || !self.scenario.deviation.deny.is_empty()
    }
}
