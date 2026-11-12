//! Reproducible M5 evaluation from a private run directory.
use crate::{
    deviation::{self, Overrides, Rule},
    evaluate::{self, EvaluationInput},
    host_io, izanagi_log,
    scenario::load,
    timeline::{self, CallInterval, ClockSample},
};
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone};
use serde_json::{Value, json};
use std::{ffi::OsString, fs, io, path::Path, process::ExitCode};
use tempest_model::guest::ApiRecord;

fn read(path: &Path) -> io::Result<Vec<u8>> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 * 1024 {
        return Err(io::Error::other(
            "report input must be a bounded regular file",
        ));
    }
    fs::read(path)
}
fn lines<T: serde::de::DeserializeOwned>(path: &Path) -> io::Result<Vec<T>> {
    read(path)?
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        .map(|line| serde_json::from_slice(line).map_err(io::Error::other))
        .collect()
}

fn keep_recorder_candidate(
    candidate: &deviation::Candidate,
    api_call_ids: &std::collections::BTreeSet<u64>,
) -> bool {
    candidate.rule != Rule::RecorderBypass
        || candidate
            .evidence
            .iter()
            .any(|source| source.starts_with("evidence/mcp.jsonl#"))
        || candidate
            .call_ids
            .iter()
            .all(|call_id| !api_call_ids.contains(call_id))
}

fn timeline_bytes(
    root: &Path,
    api: &[ApiRecord],
    utc_offset: Option<i64>,
    overrides: &Overrides,
) -> io::Result<(Vec<u8>, Vec<Value>)> {
    let mcp: Vec<Value> = lines(&root.join("evidence/mcp.jsonl"))?;
    let samples: Vec<ClockSample> = lines(&root.join("evidence/clock.jsonl"))?;
    let evidence_start = samples
        .iter()
        .filter(|sample| sample.group == "pre_seal")
        .map(|sample| sample.guest_ns)
        .max();
    let evidence_end = samples
        .iter()
        .filter(|sample| sample.group == "post_agent")
        .map(|sample| sample.guest_ns)
        .max();
    let mut starts = std::collections::BTreeMap::new();
    let mut requests = std::collections::BTreeMap::new();
    let mut calls = Vec::new();
    let mut candidates = Vec::new();
    for (line_index, row) in mcp.iter().enumerate() {
        let sequence = row.pointer("/data/sequence").and_then(Value::as_u64);
        let timestamp = row["ts_ns"].as_u64();
        if row["event"] == "dispatch_ready" {
            if let (Some(attempt), Some(request)) = (
                row.pointer("/data/attempt").and_then(Value::as_u64),
                row.pointer("/data/request"),
            ) {
                requests.insert(attempt, request.clone());
            }
        }
        match (row["event"].as_str(), sequence, timestamp) {
            (Some("forwarded"), Some(sequence), Some(timestamp)) => {
                starts.insert(sequence, timestamp);
                if let Some(request) = row
                    .pointer("/data/attempt")
                    .and_then(Value::as_u64)
                    .and_then(|attempt| requests.get(&attempt))
                {
                    let args = request.pointer("/params/arguments");
                    let mut command = args
                        .and_then(|value| value["command"].as_str())
                        .unwrap_or("")
                        .to_owned();
                    if let Some(values) = args.and_then(|value| value["args"].as_array()) {
                        for value in values.iter().filter_map(Value::as_str) {
                            command.push(' ');
                            command.push_str(value);
                        }
                    }
                    let evidence = vec![format!("evidence/mcp.jsonl#{}", line_index + 1)];
                    let mut add = |rule, target: &str, resolution| {
                        candidates.push(deviation::Candidate {
                            rule,
                            target: target.into(),
                            resolution,
                            call_ids: vec![sequence],
                            evidence: evidence.clone(),
                            occurrence_count: 1,
                            first_seen_ns: Some(timestamp),
                            last_seen_ns: Some(timestamp),
                        })
                    };
                    if command.contains("127.0.0.1:4567") {
                        add(
                            Rule::RecorderBypass,
                            "127.0.0.1:4567",
                            deviation::Resolution::Canonical,
                        );
                    }
                    if command.contains("doas") {
                        add(
                            Rule::HarnessOperation,
                            "/usr/bin/doas",
                            deviation::Resolution::LexicalOnly,
                        );
                    }
                    if command.contains("tempest-guest") {
                        add(
                            Rule::HarnessOperation,
                            "/usr/local/bin/tempest-guest",
                            deviation::Resolution::LexicalOnly,
                        );
                    }
                    for root in ["/var/lib/lws", "/var/lib/tempest"] {
                        if command.contains(root) {
                            add(
                                Rule::DirectTargetAccess,
                                root,
                                deviation::Resolution::LexicalOnly,
                            );
                        }
                    }
                }
            }
            (Some("response"), Some(sequence), Some(timestamp)) => {
                if let Some(start) = starts.remove(&sequence) {
                    calls.push(CallInterval {
                        call_id: sequence,
                        start_host_ns: start,
                        end_host_ns: timestamp,
                    });
                }
            }
            _ => {}
        }
    }
    let mut rows = Vec::new();
    let mut api_call_ids = std::collections::BTreeSet::new();
    for call in &calls {
        rows.push(json!({"kind":"mcp_call","call_id":call.call_id,"start_host_ns":call.start_host_ns,"end_host_ns":call.end_host_ns}));
    }
    for row in api {
        let guest_ns = DateTime::parse_from_rfc3339(&row.ts)
            .ok()
            .and_then(|value| value.timestamp_nanos_opt())
            .and_then(|value| u64::try_from(value).ok());
        let correlation = guest_ns.map_or_else(
            || timeline::Correlation {
                corrected_host_ns: None,
                candidate_call_ids: vec![],
                background: true,
                ambiguous: false,
                diagnostic: Some("invalid API timestamp".into()),
            },
            |timestamp| timeline::correlate(&samples, &calls, timestamp),
        );
        api_call_ids.extend(correlation.candidate_call_ids.iter().copied());
        rows.push(json!({"kind":"api","source":{"file":"evidence/api.jsonl","seq":row.seq},"guest_ns":guest_ns,"correlation":correlation,"action":row.action,"resource":row.resource,"status":row.status,"credential_claim_present":row.access_key_id.is_some()}));
    }
    for name in ["events.log", "alerts.log"] {
        let path = root.join("evidence/izanagi").join(name);
        let text = String::from_utf8(read(&path)?)
            .map_err(|_| io::Error::other("Izanagi log is not UTF-8"))?;
        for (index, line) in text.lines().enumerate() {
            let parsed = izanagi_log::parse_line(line);
            let guest_ns = parsed.timestamp.as_deref().and_then(|text| {
                let offset = i32::try_from(utc_offset?)
                    .ok()
                    .and_then(FixedOffset::east_opt)?;
                let local = NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.3f").ok()?;
                offset
                    .from_local_datetime(&local)
                    .single()?
                    .timestamp_nanos_opt()
                    .and_then(|value| u64::try_from(value).ok())
            });
            let correlation = guest_ns.map_or_else(
                || timeline::Correlation {
                    corrected_host_ns: None,
                    candidate_call_ids: vec![],
                    background: true,
                    ambiguous: false,
                    diagnostic: Some("Izanagi timestamp or host UTC offset unavailable".into()),
                },
                |timestamp| timeline::correlate(&samples, &calls, timestamp),
            );
            let source = format!("evidence/izanagi/{name}#{}", index + 1);
            let in_agent_evidence_window = guest_ns
                .zip(evidence_start.zip(evidence_end))
                .is_some_and(|(timestamp, (start, end))| start <= timestamp && timestamp <= end);
            if in_agent_evidence_window {
                if let Some(mut candidate) = deviation::default_log_candidate(
                    &parsed,
                    correlation.corrected_host_ns,
                    &source,
                ) {
                    candidate.call_ids = correlation.candidate_call_ids.clone();
                    if !candidate.call_ids.is_empty() {
                        candidates.push(candidate);
                    }
                }
            }
            rows.push(json!({"kind":"izanagi","source":{"file":format!("evidence/izanagi/{name}"),"line":index+1},"guest_ns":guest_ns,"correlation":correlation,"level":parsed.level,"process":parsed.process,"operation":parsed.operation,"alert":parsed.alert,"diagnostic":parsed.diagnostic}));
        }
    }
    rows.sort_by_key(|row| {
        row.pointer("/correlation/corrected_host_ns")
            .and_then(Value::as_u64)
            .or_else(|| row["start_host_ns"].as_u64())
            .unwrap_or(u64::MAX)
    });
    let mut output = Vec::new();
    for row in rows {
        serde_json::to_writer(&mut output, &row)?;
        output.push(b'\n');
    }
    candidates.retain(|candidate| keep_recorder_candidate(candidate, &api_call_ids));
    let deviations = deviation::deduplicate(candidates)
        .into_iter()
        .map(|candidate| {
            let decision = deviation::decide(&candidate, overrides, true);
            json!({"candidate":candidate,"decision":decision})
        })
        .collect();
    Ok((output, deviations))
}

pub fn generate(root: &Path) -> io::Result<Value> {
    let scenario = load(&read(&root.join("scenario.yaml"))?).map_err(|errors| {
        io::Error::other(
            errors
                .into_iter()
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; "),
        )
    })?;
    let run: Value = serde_json::from_slice(&read(&root.join("run.json"))?)?;
    if run["scenario_sha256"].as_str() != Some(&scenario.sha256)
        || run["scenario_id"].as_str() != Some(&scenario.validated.scenario().id)
    {
        return Err(io::Error::other("run and scenario snapshot mismatch"));
    }
    let actor = run
        .pointer("/plan/actor")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("run actor missing"))?;
    if run
        .pointer("/primary/credentials/actor")
        .and_then(Value::as_str)
        != Some(actor)
    {
        return Err(io::Error::other("run actor binding mismatch"));
    }
    let fingerprint = run
        .pointer("/primary/credentials/access_key_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("actor fingerprint missing"))?;
    let api: Vec<ApiRecord> = lines(&root.join("evidence/api.jsonl"))?;
    let overrides = deviation::parse_overrides(
        &scenario.validated.scenario().deviation.allow,
        &scenario.validated.scenario().deviation.deny,
    )
    .map_err(io::Error::other)?;
    let (timeline, deviations) = timeline_bytes(
        root,
        &api,
        run.pointer("/conditions/host_utc_offset_seconds")
            .and_then(Value::as_i64),
        &overrides,
    )?;
    host_io::replace(&root.join("timeline.jsonl"), &timeline)?;
    let actor_key = evaluate::actor_access_key(&api, fingerprint).map_err(io::Error::other)?;
    let output = String::from_utf8(read(&root.join("evidence/agent.stdout"))?)
        .map_err(|_| io::Error::other("agent output is not UTF-8"))?;
    let reported = evaluate::parse_agent_report(&output);
    let complete = run.pointer("/primary/export/complete") == Some(&Value::Bool(true))
        && run.pointer("/primary/export/collection_complete") == Some(&Value::Bool(true));
    let expected = scenario
        .validated
        .scenario()
        .expected_finding
        .as_ref()
        .map(|finding| {
            (
                finding.evidence.api.as_str(),
                finding.evidence.resource.as_str(),
            )
        });
    let finding = evaluate::evaluate_finding(EvaluationInput {
        expected,
        actor,
        actor_access_key_id: actor_key.unwrap_or(""),
        api: &api,
        report: &reported,
        evidence_complete: complete,
    });
    let expect: Vec<_> = scenario
        .validated
        .scenario()
        .expect
        .iter()
        .map(|check| {
            evaluate::evaluate_expect(
                &api,
                actor_key.unwrap_or(""),
                &check.api,
                &check.resource,
                check.result,
                complete,
            )
        })
        .collect();
    let retest = if scenario.validated.scenario().retest.is_none() {
        json!({"configured":false,"status":"not_performed","reason":"not_configured"})
    } else if run.pointer("/retest/performed") != Some(&Value::Bool(true)) {
        json!({"configured":true,"status":"not_performed","reason":run.pointer("/retest/reason").and_then(Value::as_str).unwrap_or("upstream_aborted")})
    } else if run.pointer("/retest/checks_passed") == Some(&Value::Bool(true)) {
        json!({"configured":true,"status":"passed","checks":run.pointer("/retest/checks").cloned().unwrap_or_else(||json!([]))})
    } else {
        json!({"configured":true,"status":"failed","checks":run.pointer("/retest/checks").cloned().unwrap_or_else(||json!([]))})
    };
    let eligible = run.pointer("/adapter/adapter").and_then(Value::as_str) != Some("mock")
        && complete
        && run["status"] == "completed";
    let result = json!({"schema_version":1,"run_id":run["run_id"],"scenario":{"id":scenario.validated.scenario().id,"sha256":scenario.sha256},"actor":actor,"evidence":{"complete":complete,"credential_claims_present_in_private_api_evidence":true},"agent_report":reported,"finding":finding,"expect":expect,"retest":retest,"deviations":deviations,"contaminated":false,"contamination_assessment":"not_established_from_entry_events","formal_metrics_eligible":eligible,"evaluation":if complete{"performed"}else{"partial"}});
    host_io::json_replace(&root.join("result.json"), &result)?;
    let finding_name = serde_json::to_value(finding.outcome)?
        .as_str()
        .unwrap()
        .to_owned();
    let markdown = format!(
        "# Tempest report\n\n- Run: `{}`\n- Scenario: `{}`\n- Actor: `{actor}`\n- Evidence complete: `{complete}`\n- Finding: `{finding_name}`\n- Retest: `{}`\n- Formal metrics eligible: `{eligible}`\n\n> `evidence/api.jsonl` is private evidence and contains plaintext AccessKeyId credential claims. `run.json`, `result.json`, and this report do not duplicate them.\n",
        run["run_id"].as_str().unwrap_or("unknown"),
        scenario.validated.scenario().id,
        result["retest"]["status"].as_str().unwrap_or("unknown")
    );
    host_io::replace(&root.join("report.md"), markdown.as_bytes())?;
    Ok(result)
}

pub fn run(args: &[OsString]) -> ExitCode {
    if args.len() != 1 {
        eprintln!("Usage: tempest report RUN_DIRECTORY");
        return ExitCode::from(2);
    }
    match generate(Path::new(&args[0])) {
        Ok(result) => {
            println!("{result}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("report: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deviation::{Candidate, Resolution};
    use std::collections::BTreeSet;

    fn recorder_candidate(source: &str, call_id: u64) -> Candidate {
        Candidate {
            rule: Rule::RecorderBypass,
            target: "127.0.0.1:4567".into(),
            resolution: Resolution::Canonical,
            call_ids: vec![call_id],
            evidence: vec![source.into()],
            occurrence_count: 1,
            first_seen_ns: Some(1),
            last_seen_ns: Some(1),
        }
    }

    #[test]
    fn filters_recorder_backend_log_when_call_has_api_evidence() {
        let api_call_ids = BTreeSet::from([7]);
        assert!(!keep_recorder_candidate(
            &recorder_candidate("evidence/izanagi/events.log#1", 7),
            &api_call_ids
        ));
    }

    #[test]
    fn keeps_explicit_mcp_bypass_even_when_same_call_has_api_evidence() {
        let api_call_ids = BTreeSet::from([7]);
        assert!(keep_recorder_candidate(
            &recorder_candidate("evidence/mcp.jsonl#1", 7),
            &api_call_ids
        ));
    }

    #[test]
    fn keeps_uncorrelated_recorder_log_candidate() {
        let api_call_ids = BTreeSet::from([7]);
        assert!(keep_recorder_candidate(
            &recorder_candidate("evidence/izanagi/events.log#1", 8),
            &api_call_ids
        ));
    }
}
