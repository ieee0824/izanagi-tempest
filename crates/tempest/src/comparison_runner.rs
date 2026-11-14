use crate::{comparison_plan, run_cli};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, HashMap},
    ffi::{OsStr, OsString},
    fs, io,
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
    if models.iter().collect::<BTreeSet<_>>().len() != 2
        || models.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(io::Error::other(
            "comparison plan must alternate exactly two models",
        ));
    }
    Ok(())
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
    let interval_seconds = loaded.plan.stopping_rule.minimum_interval_seconds;
    let interval_text = interval_seconds.to_string();
    let interval = Duration::from_secs(interval_seconds);
    let mut completed = Vec::new();
    for (index, (slot, model)) in loaded.plan.slots.iter().zip(models).enumerate() {
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
            ("--comparison-plan", options.plan.as_os_str()),
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
        let (run, result) = committed(&options.runs.join(&slot.run_id)).map_err(|error| {
            io::Error::other(format!(
                "slot {} did not commit; comparison stopped: {error}",
                slot.slot_id
            ))
        })?;
        if result.pointer("/comparison_binding/verified") != Some(&Value::Bool(true)) {
            return Err(io::Error::other(format!(
                "slot {} comparison binding failed; comparison stopped",
                slot.slot_id
            )));
        }
        completed.push(json!({"slot_id":slot.slot_id,"run_id":slot.run_id,
            "model":model,"command_success":status == ExitCode::SUCCESS}));
        if run["cancellation"].is_object() {
            return Err(io::Error::other(format!(
                "slot {} was cancelled; unstarted slots remain unused",
                slot.slot_id
            )));
        }
        if index + 1 < loaded.plan.slots.len() && !interval.is_zero() {
            thread::sleep(interval);
        }
    }
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

    #[test]
    fn required_condition_text_is_fail_closed() {
        let conditions = json!({"adapter":{"adapter":"claude-code","model":"a"}});
        assert_eq!(text(&conditions, "/adapter/model").unwrap(), "a");
        assert!(text(&conditions, "/adapter/missing").is_err());
    }

    #[test]
    fn comparison_models_must_alternate() {
        assert!(validate_models(&["a".into(), "b".into(), "a".into()]).is_ok());
        assert!(validate_models(&["a".into(), "a".into(), "b".into()]).is_err());
        assert!(validate_models(&["a".into(), "b".into(), "c".into()]).is_err());
    }
}
