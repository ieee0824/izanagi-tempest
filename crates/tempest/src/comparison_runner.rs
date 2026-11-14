use crate::{comparison_plan, host_io, run_cli};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, HashMap},
    ffi::{OsStr, OsString},
    fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    thread,
    time::Duration,
};

const USAGE: &str = "Usage: tempest compare PLAN SCENARIO --agent-executable FILE --model-auth-file FILE --izanagi FILE --image FILE --image-inputs FILE [--mailbox-bridge FILE] [--python FILE] [--runs DIR] [--actor NAME] [--max-evidence-bytes BYTES]";

struct Options {
    plan: PathBuf,
    scenario: PathBuf,
    executable: PathBuf,
    auth_file: PathBuf,
    izanagi: PathBuf,
    image: PathBuf,
    inputs: PathBuf,
    bridge: PathBuf,
    python: PathBuf,
    runs: PathBuf,
    actor: Option<OsString>,
    evidence_bytes: Option<OsString>,
}

fn options(args: &[OsString]) -> io::Result<Options> {
    if args.len() < 2 || (args.len() - 2) % 2 != 0 {
        return Err(io::Error::other("invalid arguments"));
    }
    let mut values = HashMap::new();
    for pair in args[2..].chunks_exact(2) {
        let flag = pair[0]
            .to_str()
            .ok_or_else(|| io::Error::other("invalid option"))?;
        if !matches!(
            flag,
            "--agent-executable"
                | "--model-auth-file"
                | "--izanagi"
                | "--image"
                | "--image-inputs"
                | "--mailbox-bridge"
                | "--python"
                | "--runs"
                | "--actor"
                | "--max-evidence-bytes"
        ) || values.insert(flag, pair[1].clone()).is_some()
        {
            return Err(io::Error::other("unknown or duplicate option"));
        }
    }
    let required = |name| {
        values
            .get(name)
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::other(format!("required option missing: {name}")))
    };
    Ok(Options {
        plan: args[0].clone().into(),
        scenario: args[1].clone().into(),
        executable: required("--agent-executable")?,
        auth_file: required("--model-auth-file")?,
        izanagi: required("--izanagi")?,
        image: required("--image")?,
        inputs: required("--image-inputs")?,
        bridge: values
            .get("--mailbox-bridge")
            .map(PathBuf::from)
            .unwrap_or_else(|| "image/host_bridge.py".into()),
        python: values
            .get("--python")
            .map(PathBuf::from)
            .unwrap_or_else(|| "python3".into()),
        runs: values
            .get("--runs")
            .map(PathBuf::from)
            .unwrap_or_else(|| "runs".into()),
        actor: values.get("--actor").cloned(),
        evidence_bytes: values.get("--max-evidence-bytes").cloned(),
    })
}

fn text<'a>(value: &'a Value, pointer: &str) -> io::Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::other(format!("comparison slot missing {pointer}")))
}

fn committed(root: &Path) -> io::Result<(Value, Value)> {
    let marker: Value = serde_json::from_slice(&fs::read(root.join("evaluation-state.json"))?)?;
    if marker["state"] != "committed" {
        return Err(io::Error::other("evaluation is not committed"));
    }
    let run = serde_json::from_slice(&fs::read(root.join("run.json"))?)?;
    let result = serde_json::from_slice(&fs::read(root.join("result.json"))?)?;
    Ok((run, result))
}

fn push_pair(args: &mut Vec<OsString>, flag: &str, value: &OsStr) {
    args.extend([OsString::from(flag), value.to_owned()]);
}

fn validate_models(models: &[String]) -> io::Result<()> {
    if models.len() % 2 != 0
        || models.iter().collect::<BTreeSet<_>>().len() != 2
        || models.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(io::Error::other(
            "comparison plan must alternate exactly two models equally",
        ));
    }
    Ok(())
}

fn prepare_runs(options: &Options, loaded: &comparison_plan::LoadedPlan) -> io::Result<PathBuf> {
    if options.runs.exists() {
        let metadata = options.runs.symlink_metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::other(
                "comparison runs directory is not owner-private",
            ));
        }
    } else {
        host_io::directory(&options.runs)?;
    }
    for slot in &loaded.plan.slots {
        if options.runs.join(&slot.run_id).symlink_metadata().is_ok() {
            return Err(io::Error::other(format!(
                "comparison run already exists: {}",
                slot.run_id
            )));
        }
    }
    let snapshot = options
        .runs
        .join(format!("comparison-plan-{}.json", loaded.sha256));
    host_io::write_new(&snapshot, &fs::read(&options.plan)?)?;
    if comparison_plan::load(&snapshot)?.sha256 != loaded.sha256 {
        return Err(io::Error::other("comparison plan snapshot mismatch"));
    }
    Ok(snapshot)
}

fn binding_matches(result: &Value, loaded: &comparison_plan::LoadedPlan, slot_id: &str) -> bool {
    result.pointer("/comparison_binding/verified") == Some(&Value::Bool(true))
        && result
            .pointer("/comparison_binding/plan_sha256")
            .and_then(Value::as_str)
            == Some(loaded.sha256.as_str())
        && result
            .pointer("/comparison_binding/slot_id")
            .and_then(Value::as_str)
            == Some(slot_id)
}

fn execute(options: Options) -> io::Result<Value> {
    let loaded = comparison_plan::load(&options.plan)?;
    let models: Vec<_> = loaded
        .plan
        .slots
        .iter()
        .map(|slot| {
            if text(&slot.comparison_conditions, "/adapter/adapter")? != "claude-code" {
                return Err(io::Error::other(
                    "comparison runner only accepts claude-code slots",
                ));
            }
            Ok(text(&slot.comparison_conditions, "/adapter/model")?.to_owned())
        })
        .collect::<io::Result<_>>()?;
    validate_models(&models)?;
    let snapshot = prepare_runs(&options, &loaded)?;
    let interval_seconds = loaded.plan.stopping_rule.minimum_interval_seconds;
    let interval_text = interval_seconds.to_string();
    let interval = Duration::from_secs(interval_seconds);
    let mut completed = Vec::new();
    let journal_path = options.runs.join("comparison-execution.json");
    let started_ns = host_io::now_ns()?;
    let mut journal = json!({"schema_version":1,"plan_id":loaded.plan.plan_id,
        "plan_sha256":loaded.sha256,"plan_snapshot":snapshot.file_name(),
        "state":"running","started_ns":started_ns,"finished_ns":Value::Null,
        "interval_definition":"minimum_seconds_from_previous_slot_finish_to_next_slot_start",
        "resume":"forbidden_new_plan_and_runs_root_required","events":[]});
    host_io::json_new(&journal_path, &journal)?;
    for (index, (slot, model)) in loaded.plan.slots.iter().zip(models).enumerate() {
        let snapshot_matches =
            comparison_plan::load(&snapshot).is_ok_and(|value| value.sha256 == loaded.sha256);
        let source_matches =
            comparison_plan::load(&options.plan).is_ok_and(|value| value.sha256 == loaded.sha256);
        if !snapshot_matches || !source_matches {
            journal["state"] = "stopped".into();
            journal["failure"] = if !snapshot_matches {
                "plan_snapshot_unreadable_or_changed"
            } else {
                "source_plan_unreadable_or_changed"
            }
            .into();
            journal["finished_ns"] = host_io::now_ns()?.into();
            host_io::json_replace(&journal_path, &journal)?;
            return Err(io::Error::other("comparison plan snapshot changed"));
        }
        let slot_started_ns = host_io::now_ns()?;
        journal["events"].as_array_mut().unwrap().push(
            json!({"slot_id":slot.slot_id,"run_id":slot.run_id,"model":model,
                "state":"started","started_ns":slot_started_ns}),
        );
        host_io::json_replace(&journal_path, &journal)?;
        let mut args = vec![options.scenario.clone().into_os_string()];
        for (flag, value) in [
            ("--agent", OsStr::new("claude-code")),
            ("--agent-executable", options.executable.as_os_str()),
            ("--model", OsStr::new(&model)),
            ("--model-auth-file", options.auth_file.as_os_str()),
            ("--izanagi", options.izanagi.as_os_str()),
            ("--image", options.image.as_os_str()),
            ("--image-inputs", options.inputs.as_os_str()),
            ("--mailbox-bridge", options.bridge.as_os_str()),
            ("--python", options.python.as_os_str()),
            ("--runs", options.runs.as_os_str()),
            ("--run-id", OsStr::new(&slot.run_id)),
            ("--repeat-interval-seconds", OsStr::new(&interval_text)),
            ("--comparison-plan", snapshot.as_os_str()),
            ("--comparison-slot", OsStr::new(&slot.slot_id)),
        ] {
            push_pair(&mut args, flag, value);
        }
        if let Some(actor) = &options.actor {
            push_pair(&mut args, "--actor", actor);
        }
        if let Some(limit) = &options.evidence_bytes {
            push_pair(&mut args, "--max-evidence-bytes", limit);
        }
        let status = run_cli::run(&args);
        let run_root = options.runs.join(&slot.run_id);
        let committed = committed(&run_root);
        let (run, result) = match committed {
            Ok(value) => value,
            Err(error) => {
                journal["state"] = "stopped".into();
                journal["failure"] = "slot_not_committed".into();
                journal["finished_ns"] = host_io::now_ns()?.into();
                host_io::json_replace(&journal_path, &journal)?;
                return Err(io::Error::other(format!(
                    "slot {} did not commit; comparison stopped: {error}",
                    slot.slot_id
                )));
            }
        };
        if run["started_ns"]
            .as_u64()
            .is_none_or(|value| value < slot_started_ns)
        {
            journal["state"] = "stopped".into();
            journal["failure"] = "slot_started_before_invocation".into();
            journal["finished_ns"] = host_io::now_ns()?.into();
            host_io::json_replace(&journal_path, &journal)?;
            return Err(io::Error::other(format!(
                "slot {} invocation timestamp failed; comparison stopped",
                slot.slot_id
            )));
        }
        if !binding_matches(&result, &loaded, &slot.slot_id) {
            journal["state"] = "stopped".into();
            journal["failure"] = "slot_comparison_binding_failed".into();
            journal["finished_ns"] = host_io::now_ns()?.into();
            host_io::json_replace(&journal_path, &journal)?;
            return Err(io::Error::other(format!(
                "slot {} comparison binding failed; comparison stopped",
                slot.slot_id
            )));
        }
        let slot_finished_ns = host_io::now_ns()?;
        completed.push(json!({"slot_id":slot.slot_id,"run_id":slot.run_id,
            "model":model,"started_ns":slot_started_ns,"finished_ns":slot_finished_ns,
            "command_success":status == ExitCode::SUCCESS}));
        journal["events"].as_array_mut().unwrap().push(
            json!({"slot_id":slot.slot_id,"run_id":slot.run_id,"model":model,
                "state":"committed","started_ns":slot_started_ns,"finished_ns":slot_finished_ns,
                "command_success":status == ExitCode::SUCCESS}),
        );
        host_io::json_replace(&journal_path, &journal)?;
        if run["cancellation"].is_object() {
            journal["state"] = "stopped".into();
            journal["failure"] = "slot_cancelled".into();
            journal["finished_ns"] = host_io::now_ns()?.into();
            host_io::json_replace(&journal_path, &journal)?;
            return Err(io::Error::other(format!(
                "slot {} was cancelled; unstarted slots remain unused",
                slot.slot_id
            )));
        }
        if index + 1 < loaded.plan.slots.len() && !interval.is_zero() {
            thread::sleep(interval);
        }
    }
    journal["state"] = "completed".into();
    journal["finished_ns"] = host_io::now_ns()?.into();
    host_io::json_replace(&journal_path, &journal)?;
    Ok(json!({"schema_version":1,"plan_id":loaded.plan.plan_id,
        "plan_sha256":loaded.sha256,"order":"precommitted_slot_order",
        "minimum_interval_seconds":interval_seconds,"completed":completed}))
}

pub fn run(args: &[OsString]) -> ExitCode {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match options(args).and_then(execute) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("comparison failed: {error}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (PathBuf, Options, comparison_plan::LoadedPlan) {
        let root = std::env::temp_dir().join(format!(
            "tempest-comparison-runner-{}",
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        let runs = root.join("runs");
        host_io::directory(&runs).unwrap();
        let plan = root.join("plan.json");
        host_io::json_new(
            &plan,
            &json!({"schema_version":1,"plan_id":"p","created_ns":1,
                "stopping_rule":{"kind":"fixed_slots","slots":2,
                    "retry":"new_slot_only","minimum_interval_seconds":0},
                "slots":[
                    {"slot_id":"a","run_id":"a","finding_configured":true,
                        "retest_configured":true,"comparison_conditions":{
                            "adapter":{"adapter":"claude-code","model":"a"}},
                        "evaluator_sha256":"a".repeat(64)},
                    {"slot_id":"b","run_id":"b","finding_configured":true,
                        "retest_configured":true,"comparison_conditions":{
                            "adapter":{"adapter":"claude-code","model":"b"}},
                        "evaluator_sha256":"a".repeat(64)}]}),
        )
        .unwrap();
        let loaded = comparison_plan::load(&plan).unwrap();
        let options = Options {
            plan,
            scenario: "scenario".into(),
            executable: "agent".into(),
            auth_file: "auth".into(),
            izanagi: "izanagi".into(),
            image: "image".into(),
            inputs: "inputs".into(),
            bridge: "bridge".into(),
            python: "python".into(),
            runs,
            actor: None,
            evidence_bytes: None,
        };
        (root, options, loaded)
    }

    #[test]
    fn required_condition_text_is_fail_closed() {
        let conditions = json!({"adapter":{"adapter":"claude-code","model":"a"}});
        assert_eq!(text(&conditions, "/adapter/model").unwrap(), "a");
        assert!(text(&conditions, "/adapter/missing").is_err());
    }

    #[test]
    fn comparison_models_must_alternate() {
        assert!(validate_models(&["a".into(), "b".into()]).is_ok());
        assert!(validate_models(&["a".into(), "b".into(), "a".into()]).is_err());
        assert!(validate_models(&["a".into(), "a".into(), "b".into()]).is_err());
        assert!(validate_models(&["a".into(), "b".into(), "c".into()]).is_err());
    }

    #[test]
    fn existing_run_is_rejected_before_snapshot_or_execution() {
        let (root, options, loaded) = fixture();
        host_io::directory(&options.runs.join("a")).unwrap();
        assert!(prepare_runs(&options, &loaded).is_err());
        assert_eq!(fs::read_dir(&options.runs).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn plan_snapshot_and_binding_are_pinned_to_initial_hash() {
        let (root, options, loaded) = fixture();
        let snapshot = prepare_runs(&options, &loaded).unwrap();
        let mut changed: Value = serde_json::from_slice(&fs::read(&options.plan).unwrap()).unwrap();
        changed["plan_id"] = "changed".into();
        host_io::replace(&options.plan, &serde_json::to_vec(&changed).unwrap()).unwrap();
        assert_eq!(
            comparison_plan::load(&snapshot).unwrap().sha256,
            loaded.sha256
        );
        assert_ne!(
            comparison_plan::load(&options.plan).unwrap().sha256,
            loaded.sha256
        );
        assert!(binding_matches(
            &json!({"comparison_binding":{"verified":true,
                "plan_sha256":loaded.sha256,"slot_id":"a"}}),
            &loaded,
            "a"
        ));
        assert!(!binding_matches(
            &json!({"comparison_binding":{"verified":true,
                "plan_sha256":"b".repeat(64),"slot_id":"a"}}),
            &loaded,
            "a"
        ));
        fs::remove_dir_all(root).unwrap();
    }
}
