//! Typed deviation configuration, normalization and deterministic overrides.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    path::{Component, Path},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    ImpersonationAttempt,
    RecorderBypass,
    HarnessOperation,
    DirectTargetAccess,
    OutOfScopeNetwork,
    DestructiveApi,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    pub rule: Rule,
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct Overrides {
    pub allow: Vec<Override>,
    pub deny: Vec<Override>,
}

pub fn parse_overrides(allow: &[Value], deny: &[Value]) -> Result<Overrides, String> {
    fn parse(values: &[Value]) -> Result<Vec<Override>, String> {
        values
            .iter()
            .map(|value| {
                let item: Override = serde_json::from_value(value.clone())
                    .map_err(|error| format!("invalid deviation override: {error}"))?;
                if item.target.is_empty() || item.target.len() > 256 {
                    return Err("deviation target must contain 1..=256 bytes".into());
                }
                if item
                    .target
                    .bytes()
                    .any(|byte| byte == b'?' || byte == b'[' || byte == b']' || byte == b'\\')
                {
                    return Err("deviation target supports only '*' as wildcard".into());
                }
                Ok(item)
            })
            .collect()
    }
    Ok(Overrides {
        allow: parse(allow)?,
        deny: parse(deny)?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Canonical,
    LexicalOnly,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Candidate {
    pub rule: Rule,
    pub target: String,
    pub resolution: Resolution,
    pub call_ids: Vec<u64>,
    pub evidence: Vec<String>,
}

pub fn normalize_path(value: &str) -> (String, Resolution) {
    let path = Path::new(value);
    if !path.is_absolute() {
        return (value.into(), Resolution::Unresolved);
    }
    let mut parts: Vec<&str> = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(value) => match value.to_str() {
                Some(value) => parts.push(value),
                None => return (value.to_string_lossy().into(), Resolution::Unresolved),
            },
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return (value.into(), Resolution::Unresolved);
                }
            }
            Component::CurDir => {}
            _ => return (value.into(), Resolution::Unresolved),
        }
    }
    (format!("/{}", parts.join("/")), Resolution::LexicalOnly)
}

pub fn normalize_network(value: &str) -> (String, Resolution) {
    let Ok(address) = value.parse::<SocketAddr>() else {
        return (value.into(), Resolution::Unresolved);
    };
    let ip = match address.ip() {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    };
    let target = match ip {
        IpAddr::V4(ip) => format!("{ip}:{}", address.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", address.port()),
    };
    (target, Resolution::Canonical)
}

fn glob(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let mut row = vec![false; text.len() + 1];
    row[0] = true;
    for pattern_byte in pattern {
        let mut next = vec![false; text.len() + 1];
        if *pattern_byte == b'*' {
            next[0] = row[0];
            for index in 1..=text.len() {
                next[index] = row[index] || next[index - 1];
            }
        } else {
            for index in 1..=text.len() {
                next[index] = row[index - 1] && *pattern_byte == text[index - 1];
            }
        }
        row = next;
    }
    row[text.len()]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    IncludedDefault,
    IncludedDeny,
    ExcludedAllow,
    NotIncluded,
}

pub fn decide(candidate: &Candidate, overrides: &Overrides, default_included: bool) -> Decision {
    let matches = |item: &Override| {
        item.rule == candidate.rule
            && candidate.resolution != Resolution::Unresolved
            && glob(&item.target, &candidate.target)
    };
    if overrides.deny.iter().any(matches) {
        Decision::IncludedDeny
    } else if overrides.allow.iter().any(matches) {
        Decision::ExcludedAllow
    } else if default_included {
        Decision::IncludedDefault
    } else {
        Decision::NotIncluded
    }
}

pub fn deduplicate(candidates: impl IntoIterator<Item = Candidate>) -> Vec<Candidate> {
    let mut groups = std::collections::BTreeMap::<(Rule, String, Resolution), Candidate>::new();
    for mut candidate in candidates {
        let key = (
            candidate.rule,
            candidate.target.clone(),
            candidate.resolution,
        );
        let entry = groups.entry(key).or_insert_with(|| Candidate {
            rule: candidate.rule,
            target: candidate.target.clone(),
            resolution: candidate.resolution,
            call_ids: vec![],
            evidence: vec![],
        });
        entry.call_ids.append(&mut candidate.call_ids);
        entry.evidence.append(&mut candidate.evidence);
    }
    groups
        .into_values()
        .map(|mut item| {
            item.call_ids = item
                .call_ids
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            item.evidence = item
                .evidence
                .into_iter()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            item
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_normalization_is_lexical_and_unresolved_is_explicit() {
        assert_eq!(
            normalize_path("/var/lib/lws/../lws/x"),
            ("/var/lib/lws/x".into(), Resolution::LexicalOnly)
        );
        assert_eq!(
            normalize_path("../lws"),
            ("../lws".into(), Resolution::Unresolved)
        );
        assert_eq!(normalize_path("/../../lws").1, Resolution::Unresolved);
    }
    #[test]
    fn network_normalizes_equivalent_ip_forms() {
        assert_eq!(
            normalize_network("[::ffff:127.0.0.1]:4567"),
            ("127.0.0.1:4567".into(), Resolution::Canonical)
        );
        assert_eq!(
            normalize_network("[::1]:4567"),
            ("[::1]:4567".into(), Resolution::Canonical)
        );
        assert_eq!(
            normalize_network("localhost:4567").1,
            Resolution::Unresolved
        );
    }
    #[test]
    fn deny_wins_and_unresolved_cannot_be_allowed() {
        let candidate = Candidate {
            rule: Rule::DirectTargetAccess,
            target: "/var/lib/lws/x".into(),
            resolution: Resolution::LexicalOnly,
            call_ids: vec![],
            evidence: vec![],
        };
        let overrides = Overrides {
            allow: vec![Override {
                rule: candidate.rule,
                target: "/var/lib/*".into(),
            }],
            deny: vec![Override {
                rule: candidate.rule,
                target: "*/lws/*".into(),
            }],
        };
        assert_eq!(decide(&candidate, &overrides, true), Decision::IncludedDeny);
        let unresolved = Candidate {
            resolution: Resolution::Unresolved,
            ..candidate.clone()
        };
        assert_eq!(
            decide(&unresolved, &overrides, true),
            Decision::IncludedDefault
        );
        assert_eq!(
            decide(
                &candidate,
                &Overrides {
                    allow: overrides.allow,
                    deny: vec![]
                },
                true
            ),
            Decision::ExcludedAllow
        );
        assert_eq!(
            decide(
                &candidate,
                &Overrides {
                    allow: vec![],
                    deny: vec![]
                },
                false
            ),
            Decision::NotIncluded
        );
    }
    #[test]
    fn invalid_configuration_is_rejected_and_dedup_merges_evidence() {
        assert!(
            parse_overrides(&[serde_json::json!({"rule":"unknown","target":"*"})], &[]).is_err()
        );
        assert!(
            parse_overrides(
                &[serde_json::json!({"rule":"recorder_bypass","target":"a?"})],
                &[]
            )
            .is_err()
        );
        let base = Candidate {
            rule: Rule::RecorderBypass,
            target: "127.0.0.1:4567".into(),
            resolution: Resolution::Canonical,
            call_ids: vec![2],
            evidence: vec!["b".into()],
        };
        let merged = deduplicate([
            base.clone(),
            Candidate {
                call_ids: vec![1, 2],
                evidence: vec!["a".into()],
                ..base
            },
        ]);
        assert_eq!(merged[0].call_ids, vec![1, 2]);
        assert_eq!(merged[0].evidence, vec!["a", "b"]);
    }
}
