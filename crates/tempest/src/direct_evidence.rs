//! Investigation data only. No conversion into a launch proof or permit.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectMode {
    LinuxDirectInvestigation,
}

/// Static investigation identity, deliberately without executable/path/argv.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectInvestigationProfile {
    pub schema_version: u64,
    pub mode: DirectMode,
    pub cli_version: String,
    pub binary_sha256: String,
}

impl DirectInvestigationProfile {
    pub fn valid(&self) -> bool {
        self.schema_version == 1 && self.cli_version == "2.1.325" && hex(&self.binary_sha256, 64)
    }
    /// Digest of this typed profile's compact serde_json serialization.
    /// Not a digest of an arbitrary input JSON byte stream.
    pub fn digest(&self) -> Option<String> {
        self.valid()
            .then(|| serde_json::to_vec(self).ok())
            .flatten()
            .map(|bytes| format!("{:x}", Sha256::digest(bytes)))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnobservedReason {
    NoMeasurementPath,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    IncompleteMeasurement,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    StreamJsonListing,
    AgentSelfReport,
    PinnedBinaryStatic,
    OsObservation,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    InitializationToolListing,
    AgentClaim,
    BinaryConfiguration,
    ProcessIsolation,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub run_id: String,
    pub profile_sha256: String,
    pub binary_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub source: Source,
    pub scope: Scope,
    pub binding: Binding,
    pub artifact_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Evidence<T> {
    Unobserved {
        reason: UnobservedReason,
    },
    Unknown {
        reason: UnknownReason,
        sources: Vec<EvidenceRef>,
    },
    Observed {
        value: T,
        sources: Vec<EvidenceRef>,
    },
}

fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Binding {
    pub fn valid(&self) -> bool {
        hex(&self.run_id, 32) && hex(&self.profile_sha256, 64) && hex(&self.binary_sha256, 64)
    }
}

impl<T> Evidence<T> {
    pub fn valid(&self, binding: &Binding) -> bool {
        if !binding.valid() {
            return false;
        }
        let sources = match self {
            Self::Unobserved { .. } => return true,
            Self::Unknown { sources, .. } | Self::Observed { sources, .. } => sources,
        };
        (1..=8).contains(&sources.len())
            && sources.iter().enumerate().all(|(index, item)| {
                let scope = match item.source {
                    Source::StreamJsonListing => Scope::InitializationToolListing,
                    Source::AgentSelfReport => Scope::AgentClaim,
                    Source::PinnedBinaryStatic => Scope::BinaryConfiguration,
                    Source::OsObservation => Scope::ProcessIsolation,
                };
                item.binding == *binding
                    && item.scope == scope
                    && hex(&item.artifact_sha256, 64)
                    && !sources[..index].contains(item)
            })
    }
    pub fn is_unobserved(&self) -> bool {
        matches!(self, Self::Unobserved { .. })
    }
    fn valid_for(&self, binding: &Binding, scope: Scope) -> bool {
        self.valid(binding)
            && match self {
                Self::Unobserved { .. } => true,
                Self::Unknown { sources, .. } | Self::Observed { sources, .. } => {
                    sources.iter().all(|source| source.scope == scope)
                }
            }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectInvestigationReport {
    pub schema_version: u64,
    pub mode: DirectMode,
    pub binding: Binding,
    pub request_catalog_sha256: Evidence<String>,
    pub request_schema_sha256: Evidence<String>,
    pub request_headers: Evidence<bool>,
    pub request_count: Evidence<u64>,
    pub retry_count: Evidence<u64>,
    pub budget_enforced: Evidence<bool>,
    pub configured_budget: Evidence<u64>,
    pub initialization_tool_listing: Evidence<String>,
}

impl DirectInvestigationReport {
    pub fn valid_for_profile(&self, profile: &DirectInvestigationProfile) -> bool {
        self.valid()
            && profile.valid()
            && profile.binary_sha256 == self.binding.binary_sha256
            && profile.digest().as_deref() == Some(self.binding.profile_sha256.as_str())
    }
    pub fn valid(&self) -> bool {
        self.schema_version == 1
            && self.binding.valid()
            && self.request_catalog_sha256.is_unobserved()
            && self.request_schema_sha256.is_unobserved()
            && self.request_headers.is_unobserved()
            && self.request_count.is_unobserved()
            && self.retry_count.is_unobserved()
            && self.budget_enforced.is_unobserved()
            && self
                .configured_budget
                .valid_for(&self.binding, Scope::BinaryConfiguration)
            && self
                .initialization_tool_listing
                .valid_for(&self.binding, Scope::InitializationToolListing)
            && match &self.initialization_tool_listing {
                Evidence::Observed { value, .. } => hex(value, 64),
                _ => true,
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn profile_report_binding_and_relay_separation() {
        let mut profile = DirectInvestigationProfile {
            schema_version: 1,
            mode: DirectMode::LinuxDirectInvestigation,
            cli_version: "2.1.325".into(),
            binary_sha256: "c".repeat(64),
        };
        let mut report: DirectInvestigationReport = serde_json::from_value(report()).unwrap();
        report.binding.profile_sha256 = profile.digest().unwrap();
        assert!(report.valid_for_profile(&profile));
        let value = serde_json::to_value(&profile).unwrap();
        assert!(
            serde_json::from_value::<crate::capability_proof::LauncherProfile>(value.clone())
                .is_err()
        );
        let mut mixed = value;
        mixed["acceptance_request_count"] = serde_json::json!(0);
        assert!(serde_json::from_value::<DirectInvestigationProfile>(mixed).is_err());
        profile.binary_sha256 = "d".repeat(64);
        assert!(!report.valid_for_profile(&profile));
        profile.cli_version = "other".into();
        assert!(profile.digest().is_none());
    }
    #[test]
    fn evidence_boundaries_and_cross_field_scope_fail_closed() {
        let value = report();
        let binding: Binding = serde_json::from_value(value["binding"].clone()).unwrap();
        let source = EvidenceRef {
            source: Source::StreamJsonListing,
            scope: Scope::InitializationToolListing,
            binding: binding.clone(),
            artifact_sha256: "d".repeat(64),
        };
        for count in [0, 9] {
            let evidence = Evidence::Observed {
                value: 0,
                sources: vec![source.clone(); count],
            };
            assert!(!evidence.valid(&binding));
        }
        for field in ["run_id", "profile_sha256", "binary_sha256"] {
            let mut wrong = serde_json::to_value(&source).unwrap();
            wrong["binding"][field] =
                serde_json::json!("e".repeat(if field == "run_id" { 32 } else { 64 }));
            let wrong: EvidenceRef = serde_json::from_value(wrong).unwrap();
            assert!(
                !Evidence::Observed {
                    value: 0,
                    sources: vec![wrong]
                }
                .valid(&binding)
            );
        }
        let mut invalid = value;
        invalid["configured_budget"] = serde_json::to_value(Evidence::Observed {
            value: 0,
            sources: vec![source],
        })
        .unwrap();
        assert!(
            !serde_json::from_value::<DirectInvestigationReport>(invalid)
                .unwrap()
                .valid()
        );
    }
    fn report() -> serde_json::Value {
        let unobserved = serde_json::json!({"state":"unobserved","reason":"no_measurement_path"});
        serde_json::json!({"schema_version":1,"mode":"linux_direct_investigation",
            "binding":{"run_id":"a".repeat(32),"profile_sha256":"b".repeat(64),"binary_sha256":"c".repeat(64)},
            "request_catalog_sha256":unobserved,"request_schema_sha256":unobserved,
            "request_headers":unobserved,"request_count":unobserved,"retry_count":unobserved,
            "budget_enforced":unobserved,"configured_budget":unobserved,
            "initialization_tool_listing":unobserved})
    }
    #[test]
    fn report_rejects_forged_observed_requests_and_invalid_listing_digests() {
        let base = report();
        let source = serde_json::json!({"source":"stream_json_listing",
            "scope":"initialization_tool_listing","binding":base["binding"],
            "artifact_sha256":"d".repeat(64)});
        for (field, value) in [
            ("request_catalog_sha256", serde_json::json!("e".repeat(64))),
            ("request_schema_sha256", serde_json::json!("e".repeat(64))),
            ("request_headers", serde_json::json!(true)),
            ("request_count", serde_json::json!(0)),
            ("retry_count", serde_json::json!(0)),
            ("budget_enforced", serde_json::json!(true)),
        ] {
            let mut invalid = base.clone();
            invalid[field] =
                serde_json::json!({"state":"observed","value":value,"sources":[source]});
            assert!(
                !serde_json::from_value::<DirectInvestigationReport>(invalid)
                    .unwrap()
                    .valid()
            );
        }
        for digest in ["", "not-a-digest", &"e".repeat(63), &"G".repeat(64)] {
            let mut invalid = base.clone();
            invalid["initialization_tool_listing"] = serde_json::json!({"state":"observed",
                "value":digest,"sources":[source]});
            assert!(
                !serde_json::from_value::<DirectInvestigationReport>(invalid)
                    .unwrap()
                    .valid()
            );
        }
    }
    #[test]
    fn direct_report_is_not_a_relay_profile_and_never_promotes_request_claims() {
        let value = report();
        assert!(
            serde_json::from_value::<DirectInvestigationReport>(value.clone())
                .unwrap()
                .valid()
        );
        assert!(
            serde_json::from_value::<crate::capability_proof::LauncherProfile>(value.clone())
                .is_err()
        );
        for field in [
            "request_catalog_sha256",
            "request_schema_sha256",
            "request_headers",
            "request_count",
            "retry_count",
            "budget_enforced",
        ] {
            let mut invalid = value.clone();
            invalid[field] = serde_json::json!({"state":"unknown","reason":"incomplete_measurement","sources":[]});
            assert!(
                !serde_json::from_value::<DirectInvestigationReport>(invalid)
                    .unwrap()
                    .valid()
            );
        }
        for mode in [serde_json::Value::Null, serde_json::json!("relay")] {
            let mut invalid = value.clone();
            invalid["mode"] = mode;
            assert!(serde_json::from_value::<DirectInvestigationReport>(invalid).is_err());
        }
        let mut invalid = value;
        invalid["schema_version"] = serde_json::json!(2);
        assert!(
            !serde_json::from_value::<DirectInvestigationReport>(invalid)
                .unwrap()
                .valid()
        );
    }
    #[test]
    fn unobserved_cannot_carry_a_value_or_unknown_reason() {
        for raw in [
            r#"{"state":"unobserved","reason":"no_measurement_path","value":0}"#,
            r#"{"state":"unobserved","reason":"arbitrary"}"#,
        ] {
            assert!(serde_json::from_str::<Evidence<u64>>(raw).is_err());
        }
    }
    #[test]
    fn source_scope_binding_and_duplicates_are_checked() {
        let binding = Binding {
            run_id: "a".repeat(32),
            profile_sha256: "b".repeat(64),
            binary_sha256: "c".repeat(64),
        };
        let source = EvidenceRef {
            source: Source::StreamJsonListing,
            scope: Scope::InitializationToolListing,
            binding: binding.clone(),
            artifact_sha256: "d".repeat(64),
        };
        assert!(
            Evidence::Observed {
                value: 0,
                sources: vec![source.clone()]
            }
            .valid(&binding)
        );
        assert!(
            !Evidence::Observed {
                value: 0,
                sources: vec![source.clone(), source.clone()]
            }
            .valid(&binding)
        );
        let mut wrong = source;
        wrong.scope = Scope::ProcessIsolation;
        assert!(
            !Evidence::Observed {
                value: 0,
                sources: vec![wrong]
            }
            .valid(&binding)
        );
    }
}
