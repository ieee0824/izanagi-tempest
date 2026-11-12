use crate::{
    adapter::{AgentAdapter, McpCommand, MockAdapter},
    admission::CloseReason,
    host_io,
    plan::{ExecutionPlan, Stage},
    relay::RelayConfig,
    report as evaluation_report,
    scenario::load,
    seed_controller::SeedController,
    supervisor::{Supervisor, SupervisorConfig},
    vm::{Vm, VmInputs},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{ExitCode, Stdio},
    time::{Duration, Instant},
};
use tempest_model::{
    Diagnostic,
    guest::{AccessKeys, ProbeOutcome, ProbeResult},
    scenario::Outcome,
};

const USAGE: &str = "Usage: tempest run SCENARIO --agent mock --mock-script FILE --izanagi FILE --image FILE --image-inputs FILE [--mailbox-bridge FILE] [--python FILE] [--runs DIR] [--run-id ID] [--actor NAME] [--max-evidence-bytes BYTES]";
async fn version(executable: &Path) -> io::Result<String> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        host_io::command(executable)
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| io::Error::other("version deadline"))??;
    if !output.status.success() || output.stdout.len() > 4096 {
        return Err(io::Error::other("version command failed"));
    }
    Ok(String::from_utf8(output.stdout)
        .map_err(|_| io::Error::other("invalid version output"))?
        .trim()
        .to_owned())
}
struct Options {
    scenario: PathBuf,
    script: PathBuf,
    izanagi: PathBuf,
    image: PathBuf,
    inputs: PathBuf,
    bridge: PathBuf,
    python: PathBuf,
    runs: PathBuf,
    id: String,
    actor: Option<String>,
    maximum_evidence_file_bytes: u64,
}
fn options(args: &[OsString]) -> io::Result<Options> {
    if args.is_empty() || args.len() % 2 == 0 {
        return Err(io::Error::other("invalid arguments"));
    }
    let mut values = HashMap::new();
    for pair in args[1..].chunks_exact(2) {
        let flag = pair[0]
            .to_str()
            .ok_or_else(|| io::Error::other("invalid option"))?;
        if !matches!(
            flag,
            "--agent"
                | "--mock-script"
                | "--izanagi"
                | "--image"
                | "--image-inputs"
                | "--mailbox-bridge"
                | "--python"
                | "--runs"
                | "--run-id"
                | "--actor"
                | "--max-evidence-bytes"
        ) || values.insert(flag, &pair[1]).is_some()
        {
            return Err(io::Error::other("unknown or duplicate option"));
        }
    }
    if values
        .get("--agent")
        .is_none_or(|v| v.as_os_str() != "mock")
    {
        return Err(io::Error::other("only the mock adapter is implemented"));
    }
    let required = |key| {
        values
            .get(key)
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::other("required option missing"))
    };
    let optional = |key, default: &str| {
        values
            .get(key)
            .map(PathBuf::from)
            .unwrap_or_else(|| default.into())
    };
    let text = |key| {
        values
            .get(key)
            .map(|v| {
                v.to_str()
                    .map(str::to_owned)
                    .ok_or_else(|| io::Error::other("invalid text option"))
            })
            .transpose()
    };
    Ok(Options {
        scenario: args[0].clone().into(),
        script: required("--mock-script")?,
        izanagi: required("--izanagi")?,
        image: required("--image")?,
        inputs: required("--image-inputs")?,
        bridge: optional("--mailbox-bridge", "image/host_bridge.py"),
        python: optional("--python", "python3"),
        runs: optional("--runs", "runs"),
        id: text("--run-id")?.unwrap_or(host_io::random_hex()?),
        actor: text("--actor")?,
        maximum_evidence_file_bytes: match text("--max-evidence-bytes")? {
            None => 64 * 1024 * 1024,
            Some(value) => value
                .parse::<u64>()
                .ok()
                .filter(|v| *v <= 1024 * 1024 * 1024)
                .ok_or_else(|| io::Error::other("invalid evidence limit"))?,
        },
    })
}
fn not_performed(configured: bool, reason: &str) -> Value {
    json!({"configured":configured,"performed":false,"outcome":"not_performed","reason":reason})
}
fn seed_error(_: io::Error) -> Diagnostic {
    Diagnostic::new("runtime.seed", "seed response unavailable; discard VM")
}
fn diagnostic(error: Diagnostic) -> io::Error {
    io::Error::other(error.to_string())
}
fn probe_matches(value: &ProbeResult, expected: Outcome) -> bool {
    value.complete
        && value.credential_known
        && matches!(
            (value.outcome, expected),
            (ProbeOutcome::Allow, Outcome::Allow) | (ProbeOutcome::Deny, Outcome::Deny)
        )
}
async fn seed(vm: &mut Vm, controller: &mut SeedController, stage: Stage) -> io::Result<()> {
    controller
        .seed(stage, |setup| async move {
            let result = vm
                .call("seed", json!({"setup":setup}))
                .await
                .map_err(seed_error)?;
            if result["admin_key_rotated"] != true
                || result["new_key_verified"] != true
                || result["old_key_rejected"] != true
            {
                return Err(Diagnostic::new(
                    "runtime.seed",
                    "management key rotation not verified",
                ));
            }
            serde_json::from_value::<AccessKeys>(result["access_keys"].clone())
                .map_err(|_| Diagnostic::new("runtime.seed", "invalid seed response"))
        })
        .await
        .map_err(diagnostic)
}
async fn verify_image(vm: &mut Vm, inputs: &Value) -> io::Result<Value> {
    let value = vm.inspect_image().await?;
    for field in [
        "izanagi_commit",
        "lws_commit",
        "input_sha256",
        "derivation_sha256",
        "tempest_guest_source_tree_sha256",
    ] {
        if value[field] != inputs[field] {
            return Err(io::Error::other("guest image provenance mismatch"));
        }
    }
    if vm.daemon_identity.as_ref().unwrap()["exe_sha256"] != inputs["input_sha256"]["agent"] {
        return Err(io::Error::other("guest daemon binary mismatch"));
    }
    Ok(value)
}
#[allow(clippy::too_many_arguments)]
async fn primary(
    vm: &mut Vm,
    plan: &ExecutionPlan,
    controller: &mut SeedController,
    adapter: &MockAdapter,
    budget: &tempest_model::scenario::Budget,
    report: &mut Value,
    root: &Path,
    inputs: &Value,
) -> io::Result<()> {
    report["primary"]["vm_binding"] = vm.binding_metadata();
    report["primary"]["image"] = verify_image(vm, inputs).await?;
    seed(vm, controller, Stage::Primary).await?;
    report["primary"]["credentials"] = serde_json::to_value(
        controller
            .binding_metadata(Stage::Primary)
            .map_err(diagnostic)?,
    )?;
    report["primary"]["registry_sha256"] = serde_json::to_value(
        controller
            .registry_metadata(Stage::Primary)
            .map_err(diagnostic)?,
    )?;
    report["primary"]["daemon_identity"] = vm.daemon_identity.clone().unwrap();
    if let Some(check) = plan.self_check() {
        let probe = controller
            .probe(Stage::Primary, check)
            .map_err(diagnostic)?;
        let result: ProbeResult =
            serde_json::from_value(vm.call("probe", json!({"probe":probe})).await?)?;
        report["self_check"] = json!({"configured":true,"performed":true,"result":result,"established":probe_matches(&result,Outcome::Allow)});
        if !probe_matches(&result, Outcome::Allow) {
            return Err(io::Error::other("scenario self-check not established"));
        }
    }
    let evidence = root.join("evidence");
    let mut clock = crate::proxy_cli::private_new(&evidence.join("clock.jsonl"))?;
    vm.clock("pre_seal", &mut clock).await?;
    vm.call("seal", json!({})).await?;
    let agent_cwd = root.join("agent-cwd");
    host_io::directory(&agent_cwd)?;
    // Darwin socket paths are bounded by sockaddr_un; keep this private owner
    // endpoint short and outside every guest share.
    let socket_base = if cfg!(target_os = "macos") {
        "/private/tmp"
    } else {
        "/tmp"
    };
    let socket_root = PathBuf::from(socket_base).join(format!("ts-{}", host_io::random_hex()?));
    host_io::directory(&socket_root)?;
    let socket = socket_root.join("s");
    let owner = Supervisor::start(SupervisorConfig {
        executable: vm.izanagi_path().to_owned(),
        args: vec!["mcp".into()],
        cwd: vm.workspace.clone(),
        socket: socket.clone(),
        log: evidence.join("mcp.jsonl"),
        stderr: evidence.join("mcp.stderr"),
        secret_file: Some(vm.hmac.clone()),
        owner_file: Some(evidence.join("mcp-owner.json")),
        relay: RelayConfig {
            max_calls: budget.max_calls,
            timeout: budget.timeout.0,
            ..RelayConfig::default()
        },
    })?;
    let prompt = controller.agent_prompt().map_err(diagnostic)?;
    report["agent"] = json!({"configured":true,"performed":true,"started_ns":host_io::now_ns()?,"description":adapter.describe()});
    let endpoint = McpCommand {
        executable: root.join("bin/tempest"),
        socket,
        owner_file: evidence.join("agent-owner.json"),
    };
    let outcome = tokio::time::timeout(
        budget.timeout.0,
        adapter.run(&prompt, &endpoint, &agent_cwd),
    )
    .await;
    let reason = match &outcome {
        Err(_) => CloseReason::Timeout,
        Ok(Err(_)) => CloseReason::Cancelled,
        Ok(Ok(_)) => CloseReason::AgentFinished,
    };
    report["agent"]["ended_ns"] = host_io::now_ns()?.into();
    report["agent"]["close_requested"] = serde_json::to_value(reason)?;
    let drained = owner.finish(reason).await;
    let _ = fs::remove_dir(&socket_root);
    let drained = drained?;
    report["primary"]["mcp"] = serde_json::to_value(&drained)?;
    let mut adapter_failed = false;
    match outcome {
        Ok(Ok(outcome)) => {
            host_io::write_new(
                &evidence.join("agent.stdout"),
                outcome.final_output.as_bytes(),
            )?;
            report["agent"]["outcome"] = serde_json::to_value(&outcome)?;
        }
        Err(_) => {
            report["agent"]["outcome"] = json!({"status":"timeout","final_output":""});
            host_io::write_new(&evidence.join("agent.stdout"), b"")?;
        }
        Ok(Err(_)) => {
            report["agent"]["outcome"] = json!({"status":"adapter_error","final_output":""});
            host_io::write_new(&evidence.join("agent.stdout"), b"")?;
            adapter_failed = true;
        }
    }
    if !drained.verified_rpc_drain() {
        vm.discard_only();
        return Err(io::Error::other(
            "MCP state uncertain; normal export forbidden",
        ));
    }
    vm.clock("post_agent", &mut clock).await?;
    let exported = vm.export(&evidence).await?;
    report["primary"]["export"] = exported;
    if report["primary"]["export"]["complete"] != true {
        return Err(io::Error::other("recorder evidence incomplete"));
    }
    if report["primary"]["export"]["collection_complete"] != true {
        return Err(io::Error::other("evidence collection incomplete"));
    }
    if adapter_failed {
        return Err(io::Error::other("agent adapter failed; evidence retained"));
    }
    Ok(())
}
async fn retest(
    vm: &mut Vm,
    plan: &ExecutionPlan,
    controller: &mut SeedController,
    report: &mut Value,
    inputs: &Value,
) -> io::Result<()> {
    let retest = plan.retest().unwrap();
    let image_qcow_sha256 = report["conditions"]["image_sha256"].clone();
    report["retest"] = json!({"configured":true,"performed":true,"checks":[],"repair_intent":retest.repair_intent(),"image_qcow_sha256":image_qcow_sha256});
    report["retest"]["vm_binding"] = vm.binding_metadata();
    if report["retest"]["vm_binding"]["session_fingerprint"]
        == report["primary"]["vm_binding"]["session_fingerprint"]
        || vm.daemon_identity.as_ref().unwrap()["invocation_id"]
            == report["primary"]["daemon_identity"]["invocation_id"]
    {
        vm.discard_only();
        return Err(io::Error::other("retest VM not fresh"));
    }
    report["retest"]["image"] = verify_image(vm, inputs).await?;
    seed(vm, controller, Stage::Retest).await?;
    report["retest"]["credentials"] = serde_json::to_value(
        controller
            .binding_metadata(Stage::Retest)
            .map_err(diagnostic)?,
    )?;
    report["retest"]["registry_sha256"] = serde_json::to_value(
        controller
            .registry_metadata(Stage::Retest)
            .map_err(diagnostic)?,
    )?;
    report["retest"]["daemon_identity"] = vm.daemon_identity.clone().unwrap();
    let mut matched = true;
    for check in retest.checks() {
        let probe = controller.probe(Stage::Retest, check).map_err(diagnostic)?;
        let result: ProbeResult =
            serde_json::from_value(vm.call("probe", json!({"probe":probe})).await?)?;
        let matches = probe_matches(&result, check.result);
        matched &= matches;
        report["retest"]["checks"]
            .as_array_mut()
            .unwrap()
            .push(json!({"check":check,"result":result,"matches":matches}));
    }
    report["retest"]["checks_passed"] = matched.into();
    Ok(())
}

async fn cancelled(
    receiver: &mut tokio::sync::watch::Receiver<Option<&'static str>>,
) -> &'static str {
    match receiver.wait_for(Option::is_some).await {
        Ok(value) => value.unwrap(),
        Err(_) => "owner_lost",
    }
}
async fn execute(
    options: Options,
    mut cancel: tokio::sync::watch::Receiver<Option<&'static str>>,
) -> io::Result<(PathBuf, bool)> {
    let raw = fs::read(&options.scenario)?;
    let loaded = load(&raw).map_err(|_| {
        io::Error::other("scenario validation failed; use tempest validate for diagnostics")
    })?;
    let plan =
        ExecutionPlan::resolve(&loaded.validated, options.actor.as_deref()).map_err(diagnostic)?;
    let script = fs::read(&options.script)?;
    if script.len() > 8 * 1024 * 1024 {
        return Err(io::Error::other("mock script too large"));
    }
    let adapter: MockAdapter = serde_json::from_slice(&script)?;
    let image = options.image.canonicalize()?;
    let izanagi = options.izanagi.canonicalize()?;
    let inputs: Value = serde_json::from_slice(&fs::read(&options.inputs)?)?;
    let bridge = options.bridge.canonicalize()?;
    let transport = bridge.parent().unwrap().join("transport.py");
    if !options.runs.exists() {
        host_io::directory(&options.runs)?;
    }
    let runs = options.runs.canonicalize()?;
    let mut controller = SeedController::create(&runs, &options.id, plan.clone())?;
    let root = runs.join(&options.id);
    host_io::json_new(
        &root.join("controller-owner.json"),
        &json!({"pid":std::process::id(),"status":"active","started_ns":host_io::now_ns()?,"executable_sha256":host_io::digest(&std::env::current_exe()?)?}),
    )?;
    host_io::directory(&root.join("bin"))?;
    host_io::private_copy(&std::env::current_exe()?, &root.join("bin/tempest"))?;
    host_io::private_copy(&izanagi, &root.join("bin/izanagi"))?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(root.join("bin/tempest"), fs::Permissions::from_mode(0o500))?;
    fs::set_permissions(root.join("bin/izanagi"), fs::Permissions::from_mode(0o500))?;
    let izanagi = root.join("bin/izanagi");
    host_io::write_new(&root.join("scenario.yaml"), &raw)?;
    host_io::write_new(&root.join("mock-script.json"), &script)?;
    host_io::json_new(&root.join("image-inputs.json"), &inputs)?;
    let companion = root.join("companion");
    host_io::directory(&companion)?;
    host_io::private_copy(&bridge, &companion.join("host_bridge.py"))?;
    host_io::private_copy(&transport, &companion.join("transport.py"))?;
    let budget = &loaded.validated.scenario().budget;
    let mut report = json!({"schema_version":1,"scope":"m5_evaluation","purpose":"collection_and_evaluation","iteration":1,"adapter":adapter.describe(),"status":"preparing","run_id":options.id,"scenario_id":loaded.validated.scenario().id,"scenario_sha256":loaded.sha256,"plan":plan.summary(),"started_ns":host_io::now_ns()?,"conditions":{"image_sha256":host_io::digest(&image)?,"izanagi_sha256":host_io::digest(&izanagi)?,"tempest_sha256":host_io::digest(&root.join("bin/tempest"))?,"mock_script_sha256":host_io::digest(&root.join("mock-script.json"))?,"companion_sha256":host_io::digest(&companion.join("host_bridge.py"))?,"codec_sha256":host_io::digest(&companion.join("transport.py"))?,"restrict_network":true,"snapshot":true,"share_read_only":true,"host_os":std::env::consts::OS,"host_arch":std::env::consts::ARCH,"max_export_file_bytes":options.maximum_evidence_file_bytes,"budget":{"max_calls":budget.max_calls,"timeout_ms":budget.timeout.0.as_millis()}},"primary":{},"agent":not_performed(true,"upstream_aborted"),"self_check":not_performed(plan.self_check().is_some(),if plan.self_check().is_some(){"upstream_aborted"}else{"not_configured"}),"finding":not_performed(plan.self_check().is_some(),if plan.self_check().is_some(){"evaluation_pending"}else{"not_configured"}),"retest":not_performed(plan.retest().is_some(),if plan.retest().is_some(){"upstream_aborted"}else{"not_configured"}),"evaluation":"not_performed"});
    report["conditions"]["izanagi_version"] = version(&izanagi).await?.into();
    report["conditions"]["tempest_version"] = env!("CARGO_PKG_VERSION").into();
    report["conditions"]["host_utc_offset_seconds"] = host_io::utc_offset_seconds()?.into();
    host_io::json_replace(&root.join("run.json"), &report)?;
    let bridge_script = companion.join("host_bridge.py");
    let boot = tokio::select! {
        biased;
        _=cancelled(&mut cancel)=>Err(io::Error::other("run cancelled during boot")),
        result=Vm::boot(
        &root,
        VmInputs {
            izanagi: &izanagi,
            image: &image,
            python: &options.python,
            companion: &bridge_script,
            maximum_evidence_file_bytes:options.maximum_evidence_file_bytes,
        },
        )=>result,
    };
    let mut primary_vm = match boot {
        Ok(vm) => vm,
        Err(error) => {
            report["failure"] = error.to_string().into();
            if let Some(reason) = *cancel.borrow() {
                report["cancellation"] = json!({"reason":reason,"observed_ns":host_io::now_ns()?});
            }
            let mut success = false;
            finalize(&root, &mut report, &mut success)?;
            return Ok((root, false));
        }
    };
    report["status"] = "running".into();
    report["primary"]["image_qcow_sha256"] = report["conditions"]["image_sha256"].clone();
    host_io::json_replace(&root.join("run.json"), &report)?;
    let primary_result = tokio::select! {
        biased;
        _=cancelled(&mut cancel)=>Err(io::Error::other("run cancelled")),
        result=primary(
        &mut primary_vm,
        &plan,
        &mut controller,
        &adapter,
        &loaded.validated.scenario().budget,
        &mut report,
        &root,
        &inputs,
        )=>result,
    };
    if cancel.borrow().is_some() {
        primary_vm.discard_only();
    }
    let cleanup = primary_vm.shutdown().await;
    let mut success = primary_result.is_ok() && cleanup.as_ref().is_ok_and(cleanup_verified);
    if primary_result.is_ok() && !success {
        report["failure"] = "VM cleanup unverified".into();
    }
    report["primary"]["cleanup"] = match cleanup {
        Ok(value) => value,
        Err(_) => json!({"failed":true}),
    };
    if let Err(error) = primary_result {
        report["failure"] = error.to_string().into();
    }
    if let Some(reason) = *cancel.borrow() {
        success = false;
        report["cancellation"] = json!({"reason":reason,"observed_ns":host_io::now_ns()?});
    }
    host_io::json_replace(&root.join("run.json"), &report)?;
    if success && plan.retest().is_some() {
        let directory = root.join("retest");
        host_io::directory(&directory)?;
        let boot = tokio::select! {
            biased;
            _=cancelled(&mut cancel)=>Err(io::Error::other("run cancelled during retest boot")),
            result=Vm::boot(
            &directory,
            VmInputs {
                izanagi: &izanagi,
                image: &image,
                python: &options.python,
                companion: &bridge_script,
                maximum_evidence_file_bytes:options.maximum_evidence_file_bytes,
            },
            )=>result,
        };
        match boot {
            Ok(mut vm) => {
                let result = tokio::select! {
                    biased;
                    _=cancelled(&mut cancel)=>Err(io::Error::other("run cancelled during retest")),
                    result=retest(&mut vm,&plan,&mut controller,&mut report,&inputs)=>result,
                };
                if cancel.borrow().is_some() {
                    vm.discard_only();
                }
                let cleanup = vm.shutdown().await;
                success = result.is_ok() && cleanup.as_ref().is_ok_and(cleanup_verified);
                report["retest"]["cleanup"] = match cleanup {
                    Ok(value) => value,
                    Err(_) => json!({"failed":true}),
                };
                if let Err(error) = result {
                    report["failure"] = error.to_string().into();
                }
            }
            Err(error) => {
                success = false;
                report["failure"] = error.to_string().into();
            }
        }
    }
    if let Some(reason) = *cancel.borrow() {
        success = false;
        report["cancellation"] = json!({"reason":reason,"observed_ns":host_io::now_ns()?});
    }
    finalize(&root, &mut report, &mut success)?;
    Ok((root, success))
}
fn cleanup_verified(value: &Value) -> bool {
    value["management_stopped"] == true
        && value["companion_stopped"] == true
        && value["down_succeeded"] == true
        && value["up_exited_successfully"] == true
        && value["forced_group_stop"] == false
        && value["missing_logs"].as_array().is_some_and(Vec::is_empty)
}
fn collect_artifacts(root: &Path, directory: &Path, paths: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| io::Error::other("artifact escaped run directory"))?
            .to_str()
            .ok_or_else(|| io::Error::other("non-UTF-8 artifact path"))?
            .to_owned();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect_artifacts(root, &path, paths)?;
        } else if kind.is_file() {
            paths.push(relative);
        } else {
            paths.push(format!("!non_regular:{relative}"));
        }
    }
    Ok(())
}
fn allowed_artifact(path: &str) -> bool {
    let (retest, path) = path
        .strip_prefix("retest/")
        .map_or((false, path), |path| (true, path));
    let vm = matches!(
        path,
        "companion.stderr"
            | "down.stderr"
            | "down.stdout"
            | "izanagi.toml"
            | "management.stderr"
            | "recovery-down.stderr"
            | "recovery-down.stdout"
            | "up.stderr"
            | "up.stdout"
            | "vm-launch.json"
            | "vm-owner.json"
            | "evidence/clock.jsonl"
            | "evidence/control.jsonl"
            | "evidence/izanagi/alerts.log"
            | "evidence/izanagi/events.log"
    );
    if retest {
        return vm;
    }
    vm || matches!(
        path,
        "artifact-inventory.json"
            | "bin/izanagi"
            | "bin/tempest"
            | "companion/host_bridge.py"
            | "companion/transport.py"
            | "controller-owner.json"
            | "evidence/agent.stdout"
            | "evidence/agent-owner.json"
            | "evidence/api.jsonl"
            | "evidence/capture.pcap"
            | "evidence/collection.json"
            | "evidence/export-index.json"
            | "evidence/manifest.json"
            | "evidence/mcp.jsonl"
            | "evidence/mcp-owner.json"
            | "evidence/mcp.stderr"
            | "image-inputs.json"
            | "mock-script.json"
            | "primary-seed-attempt.json"
            | "retest-seed-attempt.json"
            | "recovery-down.stderr"
            | "recovery-down.stdout"
            | "recovery.json"
            | "report.md"
            | "evaluation-state.json"
            | "evaluation.lock"
            | "evaluation-input-run.json"
            | "result.json"
            | "run.json"
            | "scenario.yaml"
            | "timeline.jsonl"
    )
}
fn finalize(root: &Path, report: &mut Value, success: &mut bool) -> io::Result<()> {
    report["status"] = if *success { "completed" } else { "aborted" }.into();
    report["execution_status"] = report["status"].clone();
    report["finished_ns"] = host_io::now_ns()?.into();
    host_io::json_replace(&root.join("run.json"), report)?;
    if *success {
        match evaluation_report::generate(root) {
            Ok(result) => {
                report["evaluation"] = result["evaluation"].clone();
                if result["finding"].is_object() {
                    let configured = result["finding"]["outcome"] != "not_configured";
                    report["finding"] = json!({"configured":configured,"performed":configured,"outcome":result["finding"]["outcome"]});
                }
                report["result"] = json!({"path":"result.json","formal_metrics_eligible":result["formal_metrics_eligible"]});
                if result["evaluation"] != "performed" {
                    *success = false;
                    report["finalization"] = "incomplete".into();
                } else {
                    report["finalization"] = "completed".into();
                }
            }
            Err(error) => {
                *success = false;
                report["finalization"] = "incomplete".into();
                report["evaluation"] = "unavailable".into();
                report["evaluation_failure"] = error.to_string().into();
            }
        }
        host_io::json_replace(&root.join("run.json"), report)?;
    }
    let mut paths = Vec::new();
    collect_artifacts(root, root, &mut paths)?;
    paths.push("artifact-inventory.json".to_owned());
    paths.sort();
    paths.dedup();
    let unexpected: Vec<_> = paths
        .iter()
        .filter(|path| !allowed_artifact(path))
        .cloned()
        .collect();
    if !unexpected.is_empty() {
        *success = false;
        report["status"] = "aborted".into();
        report["artifact_failure"] = "unexpected_artifacts".into();
    }
    report["artifacts"] = json!({"allowlist_checked":true,"unexpected":unexpected});
    host_io::json_replace(&root.join("run.json"), report)?;
    host_io::json_new(
        &root.join("artifact-inventory.json"),
        &json!({"complete":unexpected.is_empty(),"files":paths,"unexpected":unexpected}),
    )?;
    if root.join("controller-owner.json").exists() {
        let mut owner: Value =
            serde_json::from_slice(&fs::read(root.join("controller-owner.json"))?)?;
        owner["status"] = "finished".into();
        owner["finished_ns"] = host_io::now_ns()?.into();
        host_io::json_replace(&root.join("controller-owner.json"), &owner)?;
    }
    Ok(())
}
fn pid_alive(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid as i32, 0) };
    result == 0 || io::Error::last_os_error().kind() == io::ErrorKind::PermissionDenied
}
fn remove_transients(root: &Path, directory: &Path, removed: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| io::Error::other("recovery path escaped run directory"))?
            .to_str()
            .ok_or_else(|| io::Error::other("non-UTF-8 recovery path"))?
            .to_owned();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            if name == "__pycache__" || relative.ends_with("sandbox/.tempest-control") {
                fs::remove_dir_all(&path)?;
                removed.push(relative);
            } else {
                remove_transients(root, &path, removed)?;
            }
        } else if kind.is_file()
            && (relative == "transport-hmac"
                || relative == "retest/transport-hmac"
                || name.to_string_lossy().ends_with(".partial"))
        {
            fs::remove_file(&path)?;
            removed.push(relative);
        }
    }
    Ok(())
}
fn process_group_alive(group: u32) -> bool {
    let result = unsafe { libc::kill(-(group as i32), 0) };
    result == 0 || io::Error::last_os_error().kind() == io::ErrorKind::PermissionDenied
}
async fn verify_owned_group_gone(owner_file: &Path) -> io::Result<Option<u32>> {
    if !owner_file.is_file() {
        return Ok(None);
    }
    let owner: Value = serde_json::from_slice(&fs::read(owner_file)?)?;
    if owner["state"] != "running" {
        return Err(io::Error::other("owned process launch outcome is unknown"));
    }
    let group = owner["process_group"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 1)
        .ok_or_else(|| io::Error::other("invalid owned process group"))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    while process_group_alive(group) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if process_group_alive(group) {
        return Err(io::Error::other("owned process group is still alive"));
    }
    Ok(Some(group))
}
async fn recover_vm_stage(root: &Path, stage: &Path, name: &str) -> io::Result<Value> {
    let launch_path = stage.join("vm-launch.json");
    let owner_path = stage.join("vm-owner.json");
    if !launch_path.is_file() {
        if owner_path.exists() {
            return Err(io::Error::other("VM owner exists without launch intent"));
        }
        return Ok(json!({"stage":name,"present":false,"down_succeeded":true}));
    }
    let launch: Value = serde_json::from_slice(&fs::read(&launch_path)?)?;
    if !owner_path.is_file() {
        return Err(io::Error::other("VM launch outcome is unknown"));
    }
    if !matches!(launch["state"].as_str(), Some("spawned" | "running")) {
        return Err(io::Error::other("VM launch intent is unresolved"));
    }
    let owner: Value = serde_json::from_slice(&fs::read(&owner_path)?)?;
    let supervisor_pid = owner["supervisor_pid"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .ok_or_else(|| io::Error::other("invalid VM owner"))?;
    if launch["supervisor_pid"].as_u64() != Some(supervisor_pid.into())
        || launch["boot_nonce"] != owner["boot_nonce"]
    {
        return Err(io::Error::other("VM launch and owner records disagree"));
    }
    if !process_group_alive(supervisor_pid) {
        return Ok(
            json!({"stage":name,"present":true,"supervisor_pid":supervisor_pid,"down_succeeded":true,"already_stopped":true}),
        );
    }
    let expected = owner["session_fingerprint"]
        .as_str()
        .ok_or_else(|| io::Error::other("live VM has no session fingerprint"))?;
    let workspace = stage.join("sandbox").canonicalize()?;
    let instance = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("HOME required"))?
        .join(".izanagi/instances")
        .join(format!(
            "{:x}",
            Sha256::digest(workspace.as_os_str().as_encoded_bytes())
        ));
    if host_io::digest(&instance.join("session.json"))? != expected {
        return Err(io::Error::other("live VM session identity changed"));
    }
    let handle = crate::proxy_cli::secret_reference(&stage.join("transport-hmac"))?;
    let mut command = host_io::command(&root.join("bin/izanagi"));
    crate::proxy_cli::inherit_secret(&mut command, handle);
    let child = command
        .arg("--config")
        .arg(stage.join("izanagi.toml"))
        .arg("down")
        .current_dir(&workspace)
        .stdout(Stdio::from(crate::proxy_cli::private_new(
            &stage.join("recovery-down.stdout"),
        )?))
        .stderr(Stdio::from(crate::proxy_cli::private_new(
            &stage.join("recovery-down.stderr"),
        )?))
        .kill_on_drop(true)
        .spawn()?;
    let down_succeeded = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .is_ok_and(|result| result.is_ok_and(|output| output.status.success()));
    let deadline = Instant::now() + Duration::from_secs(30);
    while process_group_alive(supervisor_pid) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !down_succeeded || process_group_alive(supervisor_pid) {
        return Err(io::Error::other("owned VM shutdown could not be verified"));
    }
    Ok(
        json!({"stage":name,"present":true,"supervisor_pid":supervisor_pid,"down_succeeded":true,"already_stopped":false}),
    )
}
async fn recover_run(root: &Path) -> io::Result<Value> {
    let root = root.canonicalize()?;
    let metadata = root.symlink_metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::other("run directory is not private and owned"));
    }
    let owner_path = root.join("controller-owner.json");
    let owner: Value = serde_json::from_slice(&fs::read(&owner_path)?)?;
    if owner["status"] != "active" {
        return Err(io::Error::other("run is already finalized"));
    }
    let controller_pid = owner["pid"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .ok_or_else(|| io::Error::other("invalid controller owner"))?;
    if pid_alive(controller_pid) {
        return Err(io::Error::other("controller owner is still alive"));
    }
    let primary = recover_vm_stage(&root, &root, "primary").await?;
    let retest_directory = root.join("retest");
    let retest = if retest_directory.is_dir() {
        recover_vm_stage(&root, &retest_directory, "retest").await?
    } else {
        json!({"stage":"retest","present":false,"down_succeeded":true})
    };
    let mut verified_process_groups = Vec::new();
    for owner_file in [
        root.join("evidence/agent-owner.json"),
        root.join("evidence/mcp-owner.json"),
    ] {
        if let Some(group) = verify_owned_group_gone(&owner_file).await? {
            verified_process_groups.push(group);
        }
    }
    let mut removed = Vec::new();
    remove_transients(&root, &root, &mut removed)?;
    removed.sort();
    let recovery = json!({"status":"recovered","controller_pid":controller_pid,"stages":[primary,retest],"verified_process_groups_gone":verified_process_groups,"removed":removed,"finished_ns":host_io::now_ns()?});
    host_io::json_new(&root.join("recovery.json"), &recovery)?;
    let mut report: Value = serde_json::from_slice(&fs::read(root.join("run.json"))?)?;
    report["failure"] = "controller terminated; explicit recovery completed".into();
    report["recovery"] = recovery.clone();
    let mut success = false;
    finalize(&root, &mut report, &mut success)?;
    Ok(recovery)
}
pub fn recover(args: &[OsString]) -> ExitCode {
    const RECOVER_USAGE: &str = "Usage: tempest recover RUN_DIRECTORY";
    if args.len() != 1 {
        eprintln!("{RECOVER_USAGE}");
        return ExitCode::from(2);
    }
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(_) => return ExitCode::FAILURE,
    };
    let result = runtime.block_on(recover_run(Path::new(&args[0])));
    runtime.shutdown_background();
    match result {
        Ok(value) => {
            println!("{value}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("recovery failed: {error}");
            ExitCode::FAILURE
        }
    }
}
pub fn run(args: &[OsString]) -> ExitCode {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let options = match options(args) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(value) => value,
        Err(_) => return ExitCode::FAILURE,
    };
    let result = runtime.block_on(async {
        let (sender, receiver) = tokio::sync::watch::channel(None);
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let signal = tokio::spawn(async move {
            let reason =
                tokio::select! {_=tokio::signal::ctrl_c()=>"sigint",_=term.recv()=>"sigterm"};
            let _ = sender.send(Some(reason));
        });
        let result = execute(options, receiver).await;
        signal.abort();
        result
    });
    runtime.shutdown_background();
    match result {
        Ok((path, success)) => {
            let metadata: Value = fs::read(path.join("run.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or(Value::Null);
            println!(
                "{}",
                json!({"run_directory":path,"status":metadata["status"],"scope":"m5_evaluation","evaluation":metadata["evaluation"],"finalization":metadata["finalization"]})
            );
            if success {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("run failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    #[test]
    fn evaluation_failure_preserves_completed_execution() {
        let root = std::env::temp_dir().join(format!(
            "tempest-finalize-evaluation-{}",
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        host_io::write_new(&root.join("scenario.yaml"), b"invalid scenario").unwrap();
        let mut report = json!({"evaluation":"not_performed"});
        let mut success = true;
        finalize(&root, &mut report, &mut success).unwrap();
        assert!(!success);
        assert_eq!(report["status"], "completed");
        assert_eq!(report["execution_status"], "completed");
        assert_eq!(report["evaluation"], "unavailable");
        assert_eq!(report["finalization"], "incomplete");
        assert!(report["evaluation_failure"].is_string());
        assert_eq!(report["artifacts"]["unexpected"], json!([]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn artifact_allowlist_rejects_runtime_material_and_non_regular_entries() {
        let root = std::env::temp_dir().join(format!(
            "tempest-artifacts-{}-{}",
            std::process::id(),
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        host_io::write_new(&root.join("scenario.yaml"), b"id: fixture").unwrap();
        host_io::write_new(&root.join("transport-hmac"), b"not-a-real-key").unwrap();
        let mut report = json!({});
        let mut success = false;
        finalize(&root, &mut report, &mut success).unwrap();
        assert!(!success);
        assert_eq!(report["artifact_failure"], "unexpected_artifacts");
        assert!(
            report["artifacts"]["unexpected"]
                .as_array()
                .unwrap()
                .iter()
                .any(|path| path == "transport-hmac")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn recovery_rejects_unknown_launch_and_detects_leaderless_group() {
        let root = std::env::temp_dir().join(format!(
            "tempest-recovery-{}-{}",
            std::process::id(),
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        let owner = root.join("owner.json");
        host_io::json_new(&owner, &json!({"state":"launching"})).unwrap();
        assert!(verify_owned_group_gone(&owner).await.is_err());
        host_io::json_new(
            &root.join("vm-launch.json"),
            &json!({"state":"spawned","supervisor_pid":999999,"boot_nonce":"fixture"}),
        )
        .unwrap();
        assert!(recover_vm_stage(&root, &root, "primary").await.is_err());

        let mut leader = std::process::Command::new("/bin/sh");
        leader
            .args(["-c", "sleep 30 &"])
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut leader = leader.spawn().unwrap();
        let group = leader.id();
        assert!(leader.wait().unwrap().success());
        assert!(process_group_alive(group));
        host_io::json_replace(
            &root.join("vm-launch.json"),
            &json!({"state":"running","supervisor_pid":group,"boot_nonce":"fixture"}),
        )
        .unwrap();
        host_io::json_new(
            &root.join("vm-owner.json"),
            &json!({"supervisor_pid":group,"boot_nonce":"fixture","session_fingerprint":"missing"}),
        )
        .unwrap();
        host_io::directory(&root.join("sandbox")).unwrap();
        assert!(recover_vm_stage(&root, &root, "primary").await.is_err());
        unsafe {
            libc::kill(-(group as i32), libc::SIGKILL);
        }
        fs::remove_dir_all(root).unwrap();
    }
}
