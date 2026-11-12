//! Reproducible M5 evaluation from a private run directory.
use crate::{
    evaluate::{self, EvaluationInput},
    host_io,
    scenario::load,
};
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
    let result = json!({"schema_version":1,"run_id":run["run_id"],"scenario":{"id":scenario.validated.scenario().id,"sha256":scenario.sha256},"actor":actor,"evidence":{"complete":complete,"credential_claims_present_in_private_api_evidence":true},"agent_report":reported,"finding":finding,"expect":expect,"retest":retest,"deviations":[],"contaminated":false,"formal_metrics_eligible":eligible,"evaluation":if complete{"performed"}else{"partial"}});
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
