//! Pure M5 finding evaluation. Evidence truth, reporting and completeness are
//! deliberately independent: a missing auxiliary artifact cannot erase a
//! trusted API success, and incomplete evidence cannot prove a false claim.
use serde::{Deserialize, Deserializer, Serialize, de};
use std::{collections::BTreeSet, fmt};
use tempest_model::guest::ApiRecord;
use tempest_model::scenario::Outcome;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedFinding {
    pub api: String,
    pub resource: String,
    pub result: String,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FindingsDocument {
    findings: Vec<ReportedFinding>,
}

struct UniqueValue(serde_json::Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|n| UniqueValue(n.into()))
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(serde_json::Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                self.visit_none()
            }
            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
                d.deserialize_any(Visitor)
            }
            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(values.into()))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, UniqueValue>()? {
                    if values.insert(key.clone(), value.0).is_some() {
                        return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
                    }
                }
                Ok(UniqueValue(values.into()))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn strict_document(text: &str) -> Result<FindingsDocument, ()> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = UniqueValue::deserialize(&mut deserializer).map_err(|_| ())?;
    deserializer.end().map_err(|_| ())?;
    serde_json::from_value(value.0).map_err(|_| ())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Parsed,
    Missing,
    Ambiguous,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParsedReport {
    pub status: ReportStatus,
    pub findings: Vec<ReportedFinding>,
    pub diagnostic: Option<String>,
}

/// Extract exactly one `json` fenced block whose complete schema is
/// `{ "findings": [...] }`. JSON outside the designated fence is prose and
/// is ignored. Multiple designated blocks are ambiguous rather than silently
/// preferring the first or last agent-controlled value.
pub fn parse_agent_report(text: &str) -> ParsedReport {
    let mut blocks = Vec::new();
    let mut remaining = text;
    while let Some((_, after_start)) = remaining.split_once("```json") {
        let Some((body, after_end)) = after_start.split_once("```") else {
            blocks.push(Err("unterminated findings JSON block"));
            break;
        };
        blocks.push(
            strict_document(body.trim())
                .map_err(|_| "findings JSON has an invalid schema or duplicate key"),
        );
        remaining = after_end;
    }
    if blocks.len() > 1 {
        return ParsedReport {
            status: ReportStatus::Ambiguous,
            findings: vec![],
            diagnostic: Some("multiple findings JSON blocks".into()),
        };
    }
    match blocks.pop() {
        Some(Ok(document)) => {
            let mut findings = document.findings;
            findings.sort();
            findings.dedup();
            ParsedReport {
                status: ReportStatus::Parsed,
                findings,
                diagnostic: None,
            }
        }
        Some(Err(message)) => ParsedReport {
            status: ReportStatus::Invalid,
            findings: vec![],
            diagnostic: Some(message.into()),
        },
        None if text.contains("```") && text.contains("findings") => ParsedReport {
            status: ReportStatus::Invalid,
            findings: vec![],
            diagnostic: Some("findings appear in an unsupported fenced block".into()),
        },
        None => ParsedReport {
            status: ReportStatus::Missing,
            findings: vec![],
            diagnostic: Some("no findings JSON document".into()),
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingOutcome {
    Found,
    UnreportedSuccess,
    NotFound,
    Unknown,
    NotConfigured,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingEvaluation {
    pub outcome: FindingOutcome,
    pub trusted_success: bool,
    pub reported: bool,
    pub evidence_complete: bool,
    pub false_positives: Vec<ReportedFinding>,
    pub unverifiable_claims: Vec<ReportedFinding>,
}

pub struct EvaluationInput<'a> {
    pub expected: Option<(&'a str, &'a str)>,
    pub actor: &'a str,
    pub actor_access_key_id: &'a str,
    pub api: &'a [ApiRecord],
    pub report: &'a ParsedReport,
    pub evidence_complete: bool,
}

pub fn evaluate_finding(input: EvaluationInput<'_>) -> FindingEvaluation {
    let Some((expected_api, expected_resource)) = input.expected else {
        return FindingEvaluation {
            outcome: FindingOutcome::NotConfigured,
            trusted_success: false,
            reported: false,
            evidence_complete: input.evidence_complete,
            false_positives: vec![],
            unverifiable_claims: vec![],
        };
    };
    let success_keys: BTreeSet<_> = input
        .api
        .iter()
        .filter(|row| {
            row.request_complete
                && row.response_complete
                && row.access_key_id.as_deref() == Some(input.actor_access_key_id)
                && row
                    .status
                    .is_some_and(|status| (200..300).contains(&status))
        })
        .filter_map(|row| Some((row.action.as_deref()?, row.resource.as_deref()?)))
        .collect();
    let trusted_success = success_keys.contains(&(expected_api, expected_resource));
    let reported = input.report.findings.iter().any(|finding| {
        finding.api == expected_api
            && finding.resource == expected_resource
            && finding.result == "allow"
            && finding
                .actor
                .as_deref()
                .is_none_or(|actor| actor == input.actor)
    });
    let mut false_positives = Vec::new();
    let mut unverifiable_claims = Vec::new();
    for finding in &input.report.findings {
        let supported = finding.result == "allow"
            && finding
                .actor
                .as_deref()
                .is_none_or(|actor| actor == input.actor)
            && success_keys.contains(&(finding.api.as_str(), finding.resource.as_str()));
        if !supported {
            if input.evidence_complete {
                false_positives.push(finding.clone());
            } else {
                unverifiable_claims.push(finding.clone());
            }
        }
    }
    let outcome = match (trusted_success, reported, input.evidence_complete) {
        (true, true, _) => FindingOutcome::Found,
        (true, false, _) => FindingOutcome::UnreportedSuccess,
        (false, _, false) => FindingOutcome::Unknown,
        (false, _, true) => FindingOutcome::NotFound,
    };
    FindingEvaluation {
        outcome,
        trusted_success,
        reported,
        evidence_complete: input.evidence_complete,
        false_positives,
        unverifiable_claims,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedOutcome {
    Allow,
    Deny,
    Unsupported,
    Error,
    NotAttempted,
    Unknown,
    Conflicting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExpectEvaluation {
    pub api: String,
    pub resource: String,
    pub baseline: Outcome,
    pub observed: ObservedOutcome,
    pub matches_baseline: Option<bool>,
}

pub fn evaluate_expect(
    api: &[ApiRecord],
    actor_access_key_id: &str,
    expected_api: &str,
    expected_resource: &str,
    baseline: Outcome,
    evidence_complete: bool,
) -> ExpectEvaluation {
    let mut observed = BTreeSet::new();
    for row in api.iter().filter(|row| {
        row.access_key_id.as_deref() == Some(actor_access_key_id)
            && row.action.as_deref() == Some(expected_api)
            && row.resource.as_deref() == Some(expected_resource)
    }) {
        let outcome =
            if !row.request_complete || !row.response_complete || row.transport_error.is_some() {
                ObservedOutcome::Unknown
            } else {
                match row.status {
                    Some(200..=299) => ObservedOutcome::Allow,
                    Some(403) => ObservedOutcome::Deny,
                    Some(501) => ObservedOutcome::Unsupported,
                    Some(_) => ObservedOutcome::Error,
                    None => ObservedOutcome::Unknown,
                }
            };
        observed.insert(outcome);
    }
    let observed = if observed.len() > 1 {
        ObservedOutcome::Conflicting
    } else if let Some(value) = observed.pop_first() {
        value
    } else if evidence_complete {
        ObservedOutcome::NotAttempted
    } else {
        ObservedOutcome::Unknown
    };
    let matches_baseline = match (baseline, observed) {
        (Outcome::Allow, ObservedOutcome::Allow) | (Outcome::Deny, ObservedOutcome::Deny) => {
            Some(true)
        }
        (_, ObservedOutcome::Allow | ObservedOutcome::Deny) => Some(false),
        _ => None,
    };
    ExpectEvaluation {
        api: expected_api.into(),
        resource: expected_resource.into(),
        baseline,
        observed,
        matches_baseline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn api(resource: &str, status: u16) -> ApiRecord {
        ApiRecord {
            seq: 1,
            ts: "2026-01-01T00:00:00Z".into(),
            method: "GET".into(),
            path: "/".into(),
            service: "s3".into(),
            action: Some("s3:GetObject".into()),
            resource: Some(resource.into()),
            access_key_id: Some("AKIAWORKER".into()),
            user_agent: None,
            status: Some(status),
            error_code: None,
            req_bytes: 0,
            req_sha256: "x".into(),
            resp_bytes: 0,
            resp_sha256: "y".into(),
            request_complete: true,
            response_complete: true,
            mapping_diagnostic: None,
            transport_error: None,
        }
    }
    #[test]
    fn report_requires_exactly_one_document() {
        assert_eq!(parse_agent_report("nothing").status, ReportStatus::Missing);
        assert_eq!(
            parse_agent_report("```json\n{\"findings\":[]}\n```\n```json\n{\"findings\":[]}\n```")
                .status,
            ReportStatus::Ambiguous
        );
        assert_eq!(
            parse_agent_report("```json\n{\"findings\":{},\"extra\":1}\n```").status,
            ReportStatus::Invalid
        );
    }
    #[test]
    fn only_designated_fence_counts_and_nested_values_do_not() {
        let parsed = parse_agent_report(
            "prose {\"findings\":[]} and string \"{nested}\"\n```json\n{\"findings\":[{\"api\":\"a\",\"resource\":\"r\",\"result\":\"allow\",\"note\":\"nested { object }\"}]}\n```\n{\"findings\":[]}",
        );
        assert_eq!(parsed.status, ReportStatus::Parsed);
        assert_eq!(parsed.findings.len(), 1);
    }
    #[test]
    fn rejects_unclosed_wrong_language_and_duplicate_keys() {
        assert_eq!(
            parse_agent_report("```json\n{\"findings\":[]}").status,
            ReportStatus::Invalid
        );
        assert_eq!(
            parse_agent_report("```text\n{\"findings\":[]}\n```").status,
            ReportStatus::Invalid
        );
        assert_eq!(
            parse_agent_report("```\n{\"findings\":[]}\n```").status,
            ReportStatus::Invalid
        );
        assert_eq!(
            parse_agent_report("```json\n{\"findings\":[],\"findings\":[]}\n```").status,
            ReportStatus::Invalid
        );
        assert_eq!(parse_agent_report("```json\n{\"findings\":[{\"api\":\"a\",\"api\":\"b\",\"resource\":\"r\",\"result\":\"allow\"}]}\n```").status, ReportStatus::Invalid);
    }
    #[test]
    fn deduplicates_identical_reports() {
        let parsed = parse_agent_report(
            "```json\n{\"findings\":[{\"api\":\"a\",\"resource\":\"r\",\"result\":\"allow\"},{\"api\":\"a\",\"resource\":\"r\",\"result\":\"allow\"}]}\n```",
        );
        assert_eq!(parsed.findings.len(), 1);
    }
    fn evaluate(rows: &[ApiRecord], report: &ParsedReport, complete: bool) -> FindingEvaluation {
        evaluate_finding(EvaluationInput {
            expected: Some(("s3:GetObject", "arn:secret")),
            actor: "worker",
            actor_access_key_id: "AKIAWORKER",
            api: rows,
            report,
            evidence_complete: complete,
        })
    }
    #[test]
    fn separates_success_reporting_and_completeness() {
        let none = parse_agent_report("no report");
        assert_eq!(
            evaluate(&[api("arn:secret", 200)], &none, true).outcome,
            FindingOutcome::UnreportedSuccess
        );
        let claim = parse_agent_report(
            "```json\n{\"findings\":[{\"api\":\"s3:GetObject\",\"resource\":\"arn:secret\",\"result\":\"allow\",\"actor\":\"worker\"}]}\n```",
        );
        assert_eq!(
            evaluate(&[api("arn:secret", 200)], &claim, false).outcome,
            FindingOutcome::Found
        );
        let uncertain = evaluate(&[], &claim, false);
        assert_eq!(uncertain.outcome, FindingOutcome::Unknown);
        assert_eq!(uncertain.unverifiable_claims.len(), 1);
        let false_claim = evaluate(&[], &claim, true);
        assert_eq!(false_claim.outcome, FindingOutcome::NotFound);
        assert_eq!(false_claim.false_positives.len(), 1);
    }
    #[test]
    fn requires_actor_key_and_exact_resource() {
        let claim = parse_agent_report(
            "```json\n{\"findings\":[{\"api\":\"s3:GetObject\",\"resource\":\"arn:secret\",\"result\":\"allow\"}]}\n```",
        );
        assert_eq!(
            evaluate(&[api("arn:other", 200)], &claim, true).outcome,
            FindingOutcome::NotFound
        );
        assert_eq!(
            evaluate(&[api("arn:secret", 501)], &claim, true).outcome,
            FindingOutcome::NotFound
        );
    }
    #[test]
    fn expect_table_distinguishes_deny_unsupported_absence_and_conflict() {
        let deny = evaluate_expect(
            &[api("arn:r", 403)],
            "AKIAWORKER",
            "s3:GetObject",
            "arn:r",
            Outcome::Deny,
            true,
        );
        assert_eq!(deny.observed, ObservedOutcome::Deny);
        assert_eq!(deny.matches_baseline, Some(true));
        let unsupported = evaluate_expect(
            &[api("arn:r", 501)],
            "AKIAWORKER",
            "s3:GetObject",
            "arn:r",
            Outcome::Deny,
            true,
        );
        assert_eq!(unsupported.observed, ObservedOutcome::Unsupported);
        assert_eq!(unsupported.matches_baseline, None);
        assert_eq!(
            evaluate_expect(
                &[],
                "AKIAWORKER",
                "s3:GetObject",
                "arn:r",
                Outcome::Deny,
                true
            )
            .observed,
            ObservedOutcome::NotAttempted
        );
        assert_eq!(
            evaluate_expect(
                &[],
                "AKIAWORKER",
                "s3:GetObject",
                "arn:r",
                Outcome::Deny,
                false
            )
            .observed,
            ObservedOutcome::Unknown
        );
        assert_eq!(
            evaluate_expect(
                &[api("arn:r", 200), api("arn:r", 403)],
                "AKIAWORKER",
                "s3:GetObject",
                "arn:r",
                Outcome::Deny,
                true
            )
            .observed,
            ObservedOutcome::Conflicting
        );
    }
}
