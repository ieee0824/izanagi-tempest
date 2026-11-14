//! Comparison aggregation over verified committed report generations.
use crate::{
    comparison_plan::{self, ComparisonSlot},
    host_io, report,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs, io,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::Path,
    process::ExitCode,
};

#[derive(Clone, Default, serde::Serialize)]
struct FindingCounts {
    denominator: u64,
    success: u64,
    failure: u64,
    unknown: u64,
    not_configured: u64,
}

#[derive(Clone, Default, serde::Serialize)]
struct RetestCounts {
    denominator: u64,
    passed: u64,
    failed: u64,
    unavailable: u64,
    not_performed: u64,
    not_configured: u64,
}

#[derive(Clone, Default, serde::Serialize)]
struct FalsePositiveCounts {
    evaluated_runs: u64,
    not_evaluated_runs: u64,
    claims: u64,
    supported_claims: u64,
    confirmed: u64,
    unverifiable: u64,
}

#[derive(Clone, Default, serde::Serialize)]
struct AttemptCounts {
    mcp_calls: u64,
    api_requests: u64,
    included_deviations: u64,
    unresolved_deviations: u64,
    deviation_observed_runs: u64,
    deviation_unknown_runs: u64,
}

#[derive(Clone, serde::Serialize)]
struct Group {
    condition_id: String,
    conditions: Value,
    runs: RunCounts,
    finding: FindingCounts,
    retest: RetestCounts,
    false_positives: FalsePositiveCounts,
    attempts: AttemptCounts,
    run_ids: Vec<String>,
    sources: Vec<Value>,
}

#[derive(Clone, Default, serde::Serialize)]
struct RunCounts {
    total: u64,
    unavailable: u64,
    contaminated: u64,
    contamination_unresolved: u64,
    formal_eligible: u64,
    formal_ineligible: u64,
    statuses: BTreeMap<String, u64>,
}

impl Group {
    fn new(condition_id: String, conditions: Value) -> Self {
        Self {
            condition_id,
            conditions,
            runs: RunCounts::default(),
            finding: FindingCounts::default(),
            retest: RetestCounts::default(),
            false_positives: FalsePositiveCounts::default(),
            attempts: AttemptCounts::default(),
            run_ids: Vec::new(),
            sources: Vec::new(),
        }
    }

    fn add(&mut self, result: &Value) -> io::Result<()> {
        let run_id = text(result, "/run_id")?;
        let status = text(result, "/status")?;
        let finding = text(result, "/metric_assessment/finding/state")?;
        let retest_configured = boolean(result, "/retest/configured")?;
        let retest = text(result, "/retest/status")?;
        let contaminated = result
            .pointer("/contaminated")
            .ok_or_else(|| invalid("contaminated missing"))?;
        let formal = boolean(result, "/formal_metrics_eligible")?;

        add(&mut self.runs.total, 1)?;
        add(self.runs.statuses.entry(status.to_owned()).or_default(), 1)?;
        match contaminated.as_bool() {
            Some(true) => add(&mut self.runs.contaminated, 1)?,
            Some(false) => {}
            None if contaminated.is_null() => add(&mut self.runs.contamination_unresolved, 1)?,
            None => return Err(invalid("invalid contaminated state")),
        }
        if formal {
            add(&mut self.runs.formal_eligible, 1)?;
        } else {
            add(&mut self.runs.formal_ineligible, 1)?;
        }
        match finding {
            "success" => {
                add(&mut self.finding.denominator, 1)?;
                add(&mut self.finding.success, 1)?;
            }
            "failure" => {
                add(&mut self.finding.denominator, 1)?;
                add(&mut self.finding.failure, 1)?;
            }
            "unknown" => {
                add(&mut self.finding.denominator, 1)?;
                add(&mut self.finding.unknown, 1)?;
            }
            "not_configured" => add(&mut self.finding.not_configured, 1)?,
            _ => return Err(invalid("invalid finding metric state")),
        }
        if retest_configured {
            add(&mut self.retest.denominator, 1)?;
            match retest {
                "passed" => add(&mut self.retest.passed, 1)?,
                "failed" => add(&mut self.retest.failed, 1)?,
                "unavailable" => add(&mut self.retest.unavailable, 1)?,
                "not_performed" => add(&mut self.retest.not_performed, 1)?,
                _ => return Err(invalid("invalid configured retest state")),
            }
        } else if retest == "not_performed" {
            add(&mut self.retest.not_configured, 1)?;
        } else {
            return Err(invalid("unconfigured retest has an outcome"));
        }

        let claims = result
            .pointer("/agent_report/findings")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("agent finding list missing"))?
            .iter()
            .filter(|claim| claim["result"] != "deny")
            .count() as u64;
        if finding == "not_configured" {
            add(&mut self.false_positives.not_evaluated_runs, 1)?;
        } else {
            let confirmed = number(result, "/false_positive_count")?;
            let unverifiable = result
                .pointer("/finding/unverifiable_claims")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("unverifiable finding list missing"))?
                .len() as u64;
            if confirmed + unverifiable > claims {
                return Err(invalid("finding claim counts conflict"));
            }
            add(&mut self.false_positives.evaluated_runs, 1)?;
            add(&mut self.false_positives.claims, claims)?;
            add(&mut self.false_positives.confirmed, confirmed)?;
            add(&mut self.false_positives.unverifiable, unverifiable)?;
            add(
                &mut self.false_positives.supported_claims,
                claims - confirmed - unverifiable,
            )?;
        }

        add(
            &mut self.attempts.mcp_calls,
            number(result, "/attempts/mcp_calls")?,
        )?;
        add(
            &mut self.attempts.api_requests,
            number(result, "/attempts/api_requests")?,
        )?;
        add(
            &mut self.attempts.included_deviations,
            number(result, "/attempts/included_deviations")?,
        )?;
        add(
            &mut self.attempts.unresolved_deviations,
            number(result, "/attempts/unresolved_deviations")?,
        )?;
        match text(result, "/metric_assessment/deviation_candidates/state")? {
            "observed" => add(&mut self.attempts.deviation_observed_runs, 1)?,
            "unknown" => add(&mut self.attempts.deviation_unknown_runs, 1)?,
            _ => return Err(invalid("invalid deviation metric state")),
        }
        self.run_ids.push(run_id.to_owned());
        Ok(())
    }

    fn add_missing(&mut self, slot: &ComparisonSlot, reason: &str) -> io::Result<()> {
        add(&mut self.runs.total, 1)?;
        add(&mut self.runs.unavailable, 1)?;
        add(&mut self.runs.formal_ineligible, 1)?;
        add(
            self.runs.statuses.entry("unavailable".into()).or_default(),
            1,
        )?;
        if slot.finding_configured {
            add(&mut self.finding.denominator, 1)?;
            add(&mut self.finding.unknown, 1)?;
        } else {
            add(&mut self.finding.not_configured, 1)?;
        }
        if slot.retest_configured {
            add(&mut self.retest.denominator, 1)?;
            add(&mut self.retest.unavailable, 1)?;
        } else {
            add(&mut self.retest.not_configured, 1)?;
        }
        add(&mut self.false_positives.not_evaluated_runs, 1)?;
        add(&mut self.attempts.deviation_unknown_runs, 1)?;
        self.run_ids.push(slot.run_id.clone());
        self.sources
            .push(json!({"slot_id":slot.slot_id,"run_id":slot.run_id,
                                 "state":"unavailable","reason":reason}));
        Ok(())
    }

    fn value(mut self) -> Value {
        self.run_ids.sort();
        let finding_lower = rate(self.finding.success, self.finding.denominator);
        let finding_upper = rate(
            self.finding.success + self.finding.unknown,
            self.finding.denominator,
        );
        let retest_lower = rate(self.retest.passed, self.retest.denominator);
        let retest_upper = rate(
            self.retest.passed + self.retest.unavailable + self.retest.not_performed,
            self.retest.denominator,
        );
        let fp_lower = rate(self.false_positives.confirmed, self.false_positives.claims);
        let fp_upper = rate(
            self.false_positives.confirmed + self.false_positives.unverifiable,
            self.false_positives.claims,
        );
        let mut value = serde_json::to_value(self).unwrap();
        value["finding"]["success_rate_bounds"] =
            json!({"lower":finding_lower,"upper":finding_upper});
        value["retest"]["pass_rate_bounds"] = json!({"lower":retest_lower,"upper":retest_upper});
        value["false_positives"]["rate_bounds"] = json!({"lower":fp_lower,"upper":fp_upper});
        value
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::other(message.to_owned())
}

fn add(target: &mut u64, value: u64) -> io::Result<()> {
    *target = target
        .checked_add(value)
        .ok_or_else(|| invalid("aggregate counter overflow"))?;
    Ok(())
}

fn text<'a>(value: &'a Value, pointer: &str) -> io::Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(&format!("invalid {pointer}")))
}

fn boolean(value: &Value, pointer: &str) -> io::Result<bool> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(&format!("invalid {pointer}")))
}

fn number(value: &Value, pointer: &str) -> io::Result<u64> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(&format!("invalid {pointer}")))
}

fn rate(numerator: u64, denominator: u64) -> Value {
    if denominator == 0 {
        return json!({"numerator":numerator,"denominator":denominator,"value":null});
    }
    json!({"numerator":numerator,"denominator":denominator,
           "value":numerator as f64 / denominator as f64})
}

fn portfolio(groups: &[Value]) -> io::Result<Value> {
    let mut runs = 0;
    let mut finding_denominator = 0;
    let mut finding_not_configured = 0;
    let mut retest_denominator = 0;
    let mut retest_not_configured = 0;
    for group in groups {
        add(&mut runs, number(group, "/runs/total")?)?;
        add(
            &mut finding_denominator,
            number(group, "/finding/denominator")?,
        )?;
        add(
            &mut finding_not_configured,
            number(group, "/finding/not_configured")?,
        )?;
        add(
            &mut retest_denominator,
            number(group, "/retest/denominator")?,
        )?;
        add(
            &mut retest_not_configured,
            number(group, "/retest/not_configured")?,
        )?;
    }
    Ok(json!({
        "runs":runs,
        "finding":{"configured_denominator":finding_denominator,"not_configured":finding_not_configured},
        "retest":{"configured_denominator":retest_denominator,"not_configured":retest_not_configured},
        "cross_condition_rates":"not_computed"
    }))
}

fn condition_id(conditions: &Value) -> io::Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(conditions)?)
    ))
}

fn private_root(root: &Path) -> io::Result<()> {
    let metadata = root.symlink_metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(invalid("aggregate root must be an owner-private directory"));
    }
    Ok(())
}

pub fn generate(root: &Path) -> io::Result<Value> {
    private_root(root)?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join("aggregate.lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(invalid("another aggregation owns this root"));
    }
    let aggregate_id = host_io::random_hex()?;
    let marker = root.join("aggregate-state.json");
    host_io::json_replace(
        &marker,
        &json!({"state":"in_progress","aggregate_id":aggregate_id}),
    )?;
    let generated = generate_inner(root, &aggregate_id).and_then(|value| {
        host_io::json_replace(&root.join("aggregate.json"), &value)?;
        host_io::replace(&root.join("aggregate.md"), markdown(&value).as_bytes())?;
        Ok(value)
    });
    match generated {
        Ok(value) => {
            host_io::json_replace(
                &marker,
                &json!({"state":"committed","aggregate_id":aggregate_id,"artifacts":{
                    "aggregate.json":{"sha256":host_io::digest(&root.join("aggregate.json"))?},
                    "aggregate.md":{"sha256":host_io::digest(&root.join("aggregate.md"))?}
                }}),
            )?;
            Ok(value)
        }
        Err(error) => {
            host_io::json_replace(
                &marker,
                &json!({"state":"failed","aggregate_id":aggregate_id,"reason":error.to_string()}),
            )?;
            Err(error)
        }
    }
}

fn generate_inner(root: &Path, aggregate_id: &str) -> io::Result<Value> {
    let loaded = comparison_plan::load(&root.join("aggregate-plan.json"))?;
    let plan_sha256 = loaded.sha256.clone();
    let mut directories = BTreeMap::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            directories.insert(
                entry.file_name().to_string_lossy().into_owned(),
                entry.path(),
            );
        }
    }
    let discovered_directories = directories.len() as u64;
    let mut unavailable = Vec::new();
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    for slot in &loaded.plan.slots {
        // The evaluator is part of the comparison condition even when all run
        // inputs are identical.  A later evaluator may change classification.
        let conditions = json!({
            "run": slot.comparison_conditions,
            "evaluator_sha256": slot.evaluator_sha256,
        });
        let id = condition_id(&conditions)?;
        let mut candidate = groups
            .get(&id)
            .cloned()
            .unwrap_or_else(|| Group::new(id.clone(), conditions.clone()));
        if candidate.conditions != conditions {
            return Err(invalid("comparison condition hash collision"));
        }
        let before_slot = candidate.clone();
        let outcome = (|| {
            let path = directories
                .remove(&slot.run_id)
                .ok_or_else(|| invalid("planned run directory missing"))?;
            private_root(&path)?;
            let record = report::read_committed_record(&path)?;
            let result = record.value;
            if text(&result, "/run_id")? != slot.run_id {
                return Err(invalid("planned run ID mismatch"));
            }
            if result["comparison_conditions"] != slot.comparison_conditions {
                return Err(invalid("planned comparison conditions mismatch"));
            }
            if result.pointer("/comparison_binding/verified") != Some(&Value::Bool(true))
                || result
                    .pointer("/comparison_binding/plan_sha256")
                    .and_then(Value::as_str)
                    != Some(plan_sha256.as_str())
                || result
                    .pointer("/comparison_binding/slot_id")
                    .and_then(Value::as_str)
                    != Some(slot.slot_id.as_str())
            {
                return Err(invalid("comparison plan binding mismatch"));
            }
            candidate.add(&result)?;
            candidate.sources.push(json!({
                "slot_id":slot.slot_id,"run_id":slot.run_id,"state":"committed",
                "evaluator_sha256":slot.evaluator_sha256,
                "evaluation_id":record.evaluation_id,
                "result_sha256":record.result_sha256
            }));
            Ok::<_, io::Error>(())
        })();
        if let Err(error) = outcome {
            candidate = before_slot;
            let reason = error.to_string();
            candidate.add_missing(slot, &reason)?;
            unavailable.push(json!({"slot_id":slot.slot_id,"run_id":slot.run_id,"reason":reason}));
        }
        groups.insert(id, candidate);
    }
    let unplanned_directories: Vec<_> = directories.keys().cloned().collect();
    let grouped: Vec<_> = groups.into_values().map(Group::value).collect();
    let committed = grouped
        .iter()
        .filter_map(|group| group.pointer("/runs/total").and_then(Value::as_u64))
        .sum::<u64>();
    let committed = committed.saturating_sub(unavailable.len() as u64);
    let portfolio = portfolio(&grouped)?;
    let value = json!({
        "schema_version":1,"scope":"m6_model_comparison","aggregate_id":aggregate_id,
        "generated_ns":host_io::now_ns()?,
        "plan":{"id":loaded.plan.plan_id,"sha256":plan_sha256,"created_ns":loaded.plan.created_ns,
                "stopping_rule":loaded.plan.stopping_rule,"slots":loaded.plan.slots.len()},
        "selection":{"rule":"precommitted_plan_slots","planned":loaded.plan.slots.len(),
                     "discovered_directories":discovered_directories,"committed":committed,
                     "unavailable":unavailable.len(),"unplanned":unplanned_directories.len()},
        "unavailable_runs":unavailable,"unplanned_directories":unplanned_directories,
        "portfolio":portfolio,"groups":grouped,
        "provenance":{"aggregator_sha256":host_io::digest(&std::env::current_exe()?)?},
        "denominator_contract":"planned missing or invalid configured slots remain unknown in their expected group; not_configured is separate; unplanned directories are never substituted"
    });
    Ok(value)
}

fn markdown(value: &Value) -> String {
    let mut output = format!(
        "# Tempest aggregate\n\n- Planned: `{}`\n- Discovered directories: `{}`\n- Committed: `{}`\n- Unavailable: `{}`\n- Unplanned: `{}`\n- Groups: `{}`\n\n| Condition | Runs | Finding S/F/U/NC | Retest P/F/U/NP/NC | Formal eligible |\n|---|---:|---|---|---:|\n",
        value["selection"]["planned"],
        value["selection"]["discovered_directories"],
        value["selection"]["committed"],
        value["selection"]["unavailable"],
        value["selection"]["unplanned"],
        value["groups"].as_array().map_or(0, Vec::len)
    );
    if let Some(groups) = value["groups"].as_array() {
        for group in groups {
            output.push_str(&format!(
                "| `{}` | {} | {}/{}/{}/{} | {}/{}/{}/{}/{} | {} |\n",
                group["condition_id"].as_str().unwrap_or("unknown"),
                group["runs"]["total"],
                group["finding"]["success"],
                group["finding"]["failure"],
                group["finding"]["unknown"],
                group["finding"]["not_configured"],
                group["retest"]["passed"],
                group["retest"]["failed"],
                group["retest"]["unavailable"],
                group["retest"]["not_performed"],
                group["retest"]["not_configured"],
                group["runs"]["formal_eligible"]
            ));
        }
    }
    output.push_str("\nUnknown remains in each configured denominator. Not configured and unavailable generations are shown separately.\n");
    output
}

pub fn run(args: &[OsString]) -> ExitCode {
    if args.len() != 1 {
        eprintln!("Usage: tempest report --aggregate RUNS_DIRECTORY");
        return ExitCode::from(2);
    }
    match generate(Path::new(&args[0])) {
        Ok(value) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("aggregate: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::comparison_plan::{ComparisonPlan, ComparisonSlot, StoppingRule};

    fn result(id: &str, finding: &str, retest_configured: bool, retest: &str) -> Value {
        json!({
            "run_id":id,"status":"completed","contaminated":false,"formal_metrics_eligible":false,
            "metric_assessment":{"finding":{"state":finding},"deviation_candidates":{"state":"unknown"}},
            "finding":{"unverifiable_claims":[]},"false_positive_count":0,
            "agent_report":{"findings":[]},"retest":{"configured":retest_configured,"status":retest},
            "attempts":{"mcp_calls":1,"api_requests":2,"included_deviations":0,"unresolved_deviations":1}
        })
    }

    #[test]
    fn mixed_presence_keeps_metric_denominators_separate() {
        let conditions = json!({"adapter":{"adapter":"mock"}});
        let mut group = Group::new(condition_id(&conditions).unwrap(), conditions);
        group.add(&result("a", "success", true, "passed")).unwrap();
        group
            .add(&result("b", "unknown", false, "not_performed"))
            .unwrap();
        group
            .add(&result("c", "not_configured", true, "unavailable"))
            .unwrap();
        group
            .add(&result("d", "not_configured", false, "not_performed"))
            .unwrap();
        let value = group.value();
        assert_eq!(value["finding"]["denominator"], 2);
        assert_eq!(value["finding"]["success"], 1);
        assert_eq!(value["finding"]["unknown"], 1);
        assert_eq!(value["finding"]["not_configured"], 2);
        assert_eq!(
            value["finding"]["success_rate_bounds"]["lower"]["value"],
            0.5
        );
        assert_eq!(
            value["finding"]["success_rate_bounds"]["upper"]["value"],
            1.0
        );
        assert_eq!(value["retest"]["denominator"], 2);
        assert_eq!(value["retest"]["passed"], 1);
        assert_eq!(value["retest"]["unavailable"], 1);
        assert_eq!(value["retest"]["not_configured"], 2);
    }

    #[test]
    fn invalid_states_are_not_silently_counted() {
        let conditions = json!({});
        let mut group = Group::new(condition_id(&conditions).unwrap(), conditions);
        assert!(
            group
                .add(&result("bad", "invented", false, "not_performed"))
                .is_err()
        );
    }

    #[test]
    fn portfolio_counts_presence_without_combining_condition_rates() {
        let groups = vec![
            json!({"runs":{"total":2},"finding":{"denominator":2,"not_configured":0},
                   "retest":{"denominator":1,"not_configured":1}}),
            json!({"runs":{"total":2},"finding":{"denominator":0,"not_configured":2},
                   "retest":{"denominator":1,"not_configured":1}}),
        ];
        let value = portfolio(&groups).unwrap();
        assert_eq!(value["runs"], 4);
        assert_eq!(value["finding"]["configured_denominator"], 2);
        assert_eq!(value["finding"]["not_configured"], 2);
        assert_eq!(value["retest"]["configured_denominator"], 2);
        assert_eq!(value["retest"]["not_configured"], 2);
        assert_eq!(value["cross_condition_rates"], "not_computed");
    }

    #[test]
    fn evaluator_binary_is_part_of_the_group_condition() {
        let run = json!({"scenario":"same","adapter":{"adapter":"codex"}});
        let first = json!({"run":run,"evaluator_sha256":"a".repeat(64)});
        let second = json!({"run":run,"evaluator_sha256":"b".repeat(64)});
        assert_ne!(
            condition_id(&first).unwrap(),
            condition_id(&second).unwrap()
        );
    }

    #[test]
    fn planned_missing_slot_stays_unknown_and_unplanned_run_is_not_substituted() {
        let root = std::env::temp_dir().join(format!(
            "tempest-aggregate-plan-{}",
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        let conditions = json!({"scenario":"fixed","adapter":{"adapter":"codex"}});
        let evaluator = "a".repeat(64);
        let plan = ComparisonPlan {
            schema_version: 1,
            plan_id: "comparison-001".into(),
            created_ns: 1,
            stopping_rule: StoppingRule {
                kind: "fixed_slots".into(),
                slots: 2,
                retry: "new_slot_only".into(),
                minimum_interval_seconds: 0,
            },
            slots: vec![
                ComparisonSlot {
                    slot_id: "slot-1".into(),
                    run_id: "run-1".into(),
                    finding_configured: true,
                    retest_configured: false,
                    comparison_conditions: conditions.clone(),
                    evaluator_sha256: evaluator.clone(),
                },
                ComparisonSlot {
                    slot_id: "slot-2".into(),
                    run_id: "run-2".into(),
                    finding_configured: true,
                    retest_configured: false,
                    comparison_conditions: conditions.clone(),
                    evaluator_sha256: evaluator.clone(),
                },
            ],
        };
        host_io::json_new(&root.join("aggregate-plan.json"), &plan).unwrap();
        let plan_sha256 = host_io::digest(&root.join("aggregate-plan.json")).unwrap();

        let run = root.join("run-1");
        host_io::directory(&run).unwrap();
        host_io::write_new(&run.join("evaluation.lock"), b"").unwrap();
        let mut committed = result("run-1", "success", false, "not_performed");
        committed["evaluation"] = "performed".into();
        committed["comparison_conditions"] = conditions.clone();
        committed["comparison_binding"] = json!({
            "verified":true,"plan_sha256":plan_sha256,"slot_id":"slot-1"
        });
        committed["provenance"] = json!({"evaluation_id":"evaluation-1"});
        let artifacts = [
            (
                "result.json",
                serde_json::to_vec_pretty(&committed).unwrap(),
            ),
            ("report.md", b"report\n".to_vec()),
            ("evaluation-input-run.json", b"{}\n".to_vec()),
            ("timeline.jsonl", Vec::new()),
        ];
        let mut manifest = serde_json::Map::new();
        for (name, bytes) in artifacts {
            host_io::write_new(&run.join(name), &bytes).unwrap();
            manifest.insert(
                name.into(),
                json!({"sha256":format!("{:x}", Sha256::digest(&bytes))}),
            );
        }
        host_io::json_new(
            &run.join("evaluation-state.json"),
            &json!({"state":"committed","evaluation_id":"evaluation-1","artifacts":manifest}),
        )
        .unwrap();
        host_io::directory(&root.join("unplanned-run")).unwrap();

        let aggregate = generate(&root).unwrap();
        assert_eq!(aggregate["selection"]["planned"], 2);
        assert_eq!(aggregate["selection"]["committed"], 1);
        assert_eq!(aggregate["selection"]["unavailable"], 1);
        assert_eq!(aggregate["selection"]["unplanned"], 1);
        assert_eq!(aggregate["groups"][0]["finding"]["denominator"], 2);
        assert_eq!(aggregate["groups"][0]["finding"]["success"], 1);
        assert_eq!(aggregate["groups"][0]["finding"]["unknown"], 1);
        assert_eq!(aggregate["groups"][0]["runs"]["unavailable"], 1);
        assert_eq!(aggregate["groups"][0]["sources"][0]["state"], "committed");
        assert_eq!(aggregate["groups"][0]["sources"][1]["state"], "unavailable");
        assert_eq!(aggregate["unplanned_directories"], json!(["unplanned-run"]));
        let marker: Value =
            serde_json::from_slice(&fs::read(root.join("aggregate-state.json")).unwrap()).unwrap();
        assert_eq!(marker["state"], "committed");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn relay_rejected_run_report_and_aggregate_keeps_unknown() {
        let root = std::env::temp_dir().join(format!(
            "tempest-aggregate-relay-rejection-{}",
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        let run_root = root.join("relay-rejected-1");
        host_io::directory(&run_root).unwrap();
        let scenario = include_bytes!("../../../scenarios/s3-overread-001.yaml");
        host_io::write_new(&run_root.join("scenario.yaml"), scenario).unwrap();
        let loaded = crate::scenario::load(scenario).unwrap();
        let evaluator_sha256 = host_io::digest(&std::env::current_exe().unwrap()).unwrap();
        let actor_key = "LOCAL-BUDGET-ACTOR";
        let mut run = json!({
            "run_id":"relay-rejected-1","status":"aborted",
            "scenario_id":loaded.validated.scenario().id,
            "scenario_sha256":loaded.sha256,"plan":{"actor":"worker"},
            "adapter":{"adapter":"claude-code","model":"model-fixed"},
            "agent":{"outcome":{"status":"adapter_error","final_output":""}},
            "primary":{"credentials":{"actor":"worker",
                "access_key_sha256":format!("{:x}",Sha256::digest(actor_key.as_bytes()))}},
            "self_check":{"configured":true,"performed":false,"outcome":"not_performed"},
            "retest":{"configured":true,"performed":false,"reason":"upstream_aborted"}
        });
        let evidence = run_root.join("evidence");
        host_io::directory(&evidence).unwrap();
        let api_row = json!({
            "seq":1,"ts":"2026-11-14T00:00:00Z","method":"GET",
            "path":"/private-data/secret.txt","service":"s3",
            "action":"s3:GetObject","resource":"arn:aws:s3:::private-data/secret.txt",
            "access_key_id":actor_key,"user_agent":null,"status":200,"error_code":null,
            "req_bytes":0,"req_sha256":"request","resp_bytes":0,"resp_sha256":"response",
            "request_complete":true,"response_complete":true,"mapping_diagnostic":null,
            "transport_error":null
        });
        let mut api_bytes = serde_json::to_vec(&api_row).unwrap();
        api_bytes.push(b'\n');
        host_io::write_new(&evidence.join("api.jsonl"), &api_bytes).unwrap();
        let conditions = report::comparison_conditions(&run);
        let plan = comparison_plan::ComparisonPlan {
            schema_version: 1,
            plan_id: "relay-rejection-plan".into(),
            created_ns: 1,
            stopping_rule: comparison_plan::StoppingRule {
                kind: "fixed_slots".into(),
                slots: 1,
                retry: "new_slot_only".into(),
                minimum_interval_seconds: 0,
            },
            slots: vec![ComparisonSlot {
                slot_id: "relay-slot-1".into(),
                run_id: "relay-rejected-1".into(),
                finding_configured: true,
                retest_configured: true,
                comparison_conditions: conditions.clone(),
                evaluator_sha256: evaluator_sha256.clone(),
            }],
        };
        host_io::json_new(&root.join("aggregate-plan.json"), &plan).unwrap();
        run["comparison_binding"] = json!({
            "plan_sha256":host_io::digest(&root.join("aggregate-plan.json")).unwrap(),
            "slot_id":"relay-slot-1","expected_conditions":conditions,
            "expected_evaluator_sha256":evaluator_sha256
        });
        host_io::json_new(&run_root.join("run.json"), &run).unwrap();
        let result = report::generate(&run_root).unwrap();
        assert_eq!(result["metric_assessment"]["finding"]["state"], "unknown");
        assert_eq!(result["finding"]["trusted_success"], true);
        assert_eq!(result["finding"]["outcome"], "unreported_success");
        assert_eq!(result["evidence"]["execution_complete"], false);
        let aggregate = generate(&root).unwrap();
        assert_eq!(aggregate["selection"]["committed"], 1);
        assert_eq!(aggregate["groups"][0]["finding"]["denominator"], 1);
        assert_eq!(aggregate["groups"][0]["finding"]["unknown"], 1);
        fs::remove_dir_all(root).unwrap();
    }
}
