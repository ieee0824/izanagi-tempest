use crate::{
    adapter::{AgentAdapter, CliAdapter, McpCommand, MockAdapter},
    admission::CloseReason,
    capability_runner::{
        CapabilityAgent, CapabilityDiscoveryConfig, ProductionLaunchConfig, discover_for_launch,
    },
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
    collections::{BTreeMap, HashMap},
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

const USAGE: &str = "Usage: tempest run SCENARIO (--agent mock --mock-script FILE | --agent claude-code --agent-executable FILE --model EXACT_MODEL_ID --model-auth-file FILE) --izanagi FILE --image FILE --image-inputs FILE [--mailbox-bridge FILE] [--python FILE] [--runs DIR] [--run-id ID] [--repeat N] [--repeat-interval-seconds N] [--actor NAME] [--max-evidence-bytes BYTES] [--comparison-plan FILE --comparison-slot ID]";
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
#[derive(Clone)]
enum AgentSelection {
    Mock {
        script: PathBuf,
    },
    ClaudeCode {
        executable: PathBuf,
        model: String,
        auth_file: PathBuf,
    },
}

#[derive(Clone)]
struct Options {
    scenario: PathBuf,
    agent: AgentSelection,
    izanagi: PathBuf,
    image: PathBuf,
    inputs: PathBuf,
    bridge: PathBuf,
    python: PathBuf,
    runs: PathBuf,
    id: String,
    repeat: usize,
    repeat_interval_seconds: u64,
    actor: Option<String>,
    comparison_plan: Option<PathBuf>,
    comparison_slot: Option<String>,
    maximum_evidence_file_bytes: u64,
    iteration: usize,
}

enum AgentSetup {
    Mock(MockAdapter),
    ClaudeCode {
        executable: PathBuf,
        model: String,
        auth_file: PathBuf,
    },
}

enum RuntimeAdapter {
    Mock(MockAdapter),
    Native(Box<CliAdapter>),
}

impl AgentAdapter for RuntimeAdapter {
    fn describe(&self) -> Value {
        match self {
            Self::Mock(adapter) => adapter.describe(),
            Self::Native(adapter) => adapter.describe(),
        }
    }

    async fn run<'a>(
        &'a self,
        prompt: &'a str,
        endpoint: &'a McpCommand,
        cwd: &'a Path,
    ) -> io::Result<crate::adapter::AgentOutcome> {
        match self {
            Self::Mock(adapter) => adapter.run(prompt, endpoint, cwd).await,
            Self::Native(adapter) => adapter.run(prompt, endpoint, cwd).await,
        }
    }
}

impl RuntimeAdapter {
    fn mcp_bridge(&self, mock_bridge: &Path) -> PathBuf {
        match self {
            Self::Mock(_) => mock_bridge.to_owned(),
            Self::Native(adapter) => adapter.mcp_bridge_path().to_owned(),
        }
    }
}

struct NativeRuntimeDirectory(PathBuf);

impl Drop for NativeRuntimeDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn native_runtime_directory(root: &Path) -> io::Result<(NativeRuntimeDirectory, PathBuf)> {
    let parent = root.join(".native-runtime");
    host_io::directory(&parent)?;
    let output = parent.join("discovery");
    if output.exists() {
        return Err(io::Error::other("native discovery output already exists"));
    }
    Ok((NativeRuntimeDirectory(parent), output))
}

fn preserve_native_acceptance(runtime_root: &Path, evidence: &Path) -> io::Result<()> {
    let destination = evidence.join("native-acceptance");
    host_io::directory(&destination)?;
    host_io::directory(&destination.join("evidence"))?;
    for (source, target) in [
        (
            "acceptance-proof/launcher-profile.json",
            "launcher-profile.json",
        ),
        (
            "acceptance-proof/capability-proof.json",
            "capability-proof.json",
        ),
        ("harness/request-policy.json", "request-policy.json"),
        (
            "harness/model-relay-audit.jsonl",
            "acceptance-relay-audit.jsonl",
        ),
        ("harness/acceptance-mcp.jsonl", "acceptance-mcp.jsonl"),
    ] {
        host_io::private_copy(&runtime_root.join(source), &destination.join(target))?;
    }
    for check in [
        "allowed_mcp_succeeded",
        "control_socket_unavailable",
        "hmac_unavailable",
        "host_canary_read_denied",
        "host_canary_write_denied",
        "host_tools_rejected",
        "mcp_child_env_sanitized",
        "provider_request_policy",
        "tool_catalog_exact",
    ] {
        let name = format!("{check}.json");
        host_io::private_copy(
            &runtime_root.join("acceptance-proof/evidence").join(&name),
            &destination.join("evidence").join(name),
        )?;
    }
    Ok(())
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
                | "--agent-executable"
                | "--model"
                | "--model-auth-file"
                | "--izanagi"
                | "--image"
                | "--image-inputs"
                | "--mailbox-bridge"
                | "--python"
                | "--runs"
                | "--run-id"
                | "--repeat"
                | "--repeat-interval-seconds"
                | "--actor"
                | "--max-evidence-bytes"
                | "--comparison-plan"
                | "--comparison-slot"
        ) || values.insert(flag, &pair[1]).is_some()
        {
            return Err(io::Error::other("unknown or duplicate option"));
        }
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
    let comparison_plan = values.get("--comparison-plan").map(PathBuf::from);
    let comparison_slot = text("--comparison-slot")?;
    if comparison_plan.is_some() != comparison_slot.is_some() {
        return Err(io::Error::other(
            "comparison plan and slot must be provided together",
        ));
    }
    let agent = match values.get("--agent").and_then(|value| value.to_str()) {
        Some("mock") => {
            if values.contains_key("--agent-executable")
                || values.contains_key("--model")
                || values.contains_key("--model-auth-file")
            {
                return Err(io::Error::other("mock and native agent options conflict"));
            }
            AgentSelection::Mock {
                script: required("--mock-script")?,
            }
        }
        Some("claude-code") => {
            if values.contains_key("--mock-script") {
                return Err(io::Error::other("mock and native agent options conflict"));
            }
            AgentSelection::ClaudeCode {
                executable: required("--agent-executable")?,
                model: text("--model")?
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| io::Error::other("required model missing"))?,
                auth_file: required("--model-auth-file")?,
            }
        }
        _ => return Err(io::Error::other("unsupported or missing agent")),
    };
    Ok(Options {
        scenario: args[0].clone().into(),
        agent,
        izanagi: required("--izanagi")?,
        image: required("--image")?,
        inputs: required("--image-inputs")?,
        bridge: optional("--mailbox-bridge", "image/host_bridge.py"),
        python: optional("--python", "python3"),
        runs: optional("--runs", "runs"),
        id: text("--run-id")?.unwrap_or(host_io::random_hex()?),
        repeat: match text("--repeat")? {
            None => 1,
            Some(value) => value
                .parse::<usize>()
                .ok()
                .filter(|value| (1..=100).contains(value))
                .ok_or_else(|| io::Error::other("invalid repeat count"))?,
        },
        repeat_interval_seconds: match text("--repeat-interval-seconds")? {
            None => 0,
            Some(value) => value
                .parse::<u64>()
                .ok()
                .filter(|value| *value <= 3600)
                .ok_or_else(|| io::Error::other("invalid repeat interval"))?,
        },
        actor: text("--actor")?,
        comparison_plan,
        comparison_slot,
        iteration: 1,
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
fn model_relay_summary(path: &Path, maximum_requests: u64) -> io::Result<(Value, bool)> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > 1024 * 1024
    {
        return Err(io::Error::other("unsafe model relay audit"));
    }
    let mut admitted = HashMap::<String, u64>::new();
    let mut completed = HashMap::<String, u64>::new();
    let mut delivery_states = BTreeMap::<String, u64>::new();
    let mut reasons = BTreeMap::<String, u64>::new();
    let mut upstream_statuses = BTreeMap::<String, u64>::new();
    let mut only_complete_pairs = true;
    let mut rows = 0_u64;
    for line in fs::read_to_string(path)?.lines() {
        rows += 1;
        let row: Value = serde_json::from_str(line)?;
        let sha256 = row["request_sha256"]
            .as_str()
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(|| io::Error::other("invalid model relay audit request binding"))?;
        let delivery_state = row["delivery_state"]
            .as_str()
            .ok_or_else(|| io::Error::other("invalid model relay delivery state"))?;
        *delivery_states
            .entry(delivery_state.to_owned())
            .or_default() += 1;
        let reason = row["reason"].as_str().unwrap_or("none");
        *reasons.entry(reason.to_owned()).or_default() += 1;
        let upstream_status = row["upstream_status"]
            .as_u64()
            .map_or_else(|| "none".to_owned(), |status| status.to_string());
        *upstream_statuses.entry(upstream_status).or_default() += 1;
        match delivery_state {
            "not_sent" if row["reason"] == "admission_verified" => {
                *admitted.entry(sha256.to_owned()).or_default() += 1;
            }
            "response_complete" if row["forwarded"] == true => {
                *completed.entry(sha256.to_owned()).or_default() += 1;
            }
            _ => only_complete_pairs = false,
        }
    }
    let requests = admitted.values().sum::<u64>();
    let delivery_verified = only_complete_pairs
        && rows == requests.saturating_mul(2)
        && requests != 0
        && requests <= maximum_requests
        && admitted == completed;
    if rows == 0 || rows > maximum_requests.saturating_mul(3) || requests > maximum_requests {
        return Err(io::Error::other("model relay audit sequence out of bounds"));
    }
    Ok((
        json!({"rows":rows,"requests":requests,"responses_complete":completed.values().sum::<u64>(),
        "maximum_requests":maximum_requests,"delivery_verified":delivery_verified,
        "delivery_states":delivery_states,"reasons":reasons,"upstream_statuses":upstream_statuses}),
        delivery_verified,
    ))
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
    setup: AgentSetup,
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
    let mut native_runtime = None;
    let mut production_request_budget = None;
    let mut production_relay = None;
    let mut native_authorized_ns = None;
    let adapter = match setup {
        AgentSetup::Mock(adapter) => RuntimeAdapter::Mock(adapter),
        AgentSetup::ClaudeCode {
            executable,
            model,
            auth_file,
        } => {
            let (runtime_directory, runtime_root) = native_runtime_directory(root)?;
            native_runtime = Some(runtime_directory);
            let launch = discover_for_launch(
                CapabilityDiscoveryConfig {
                    agent: CapabilityAgent::ClaudeCode,
                    executable: executable.canonicalize()?,
                    model,
                    output: runtime_root.clone(),
                },
                ProductionLaunchConfig {
                    auth_file: auth_file.canonicalize()?,
                    audit_file: evidence.join("model-relay-audit.jsonl"),
                    owner_file: evidence.join("model-relay-owner.json"),
                    launch_harness_root: evidence.clone(),
                },
            )
            .await?;
            let discovery = &launch.discovery;
            let request_policy: Value = serde_json::from_slice(&fs::read(
                runtime_root.join("harness/request-policy.json"),
            )?)?;
            let launcher_profile_sha256 =
                host_io::digest(&runtime_root.join("acceptance-proof/launcher-profile.json"))?;
            let capability_proof_sha256 =
                host_io::digest(&runtime_root.join("acceptance-proof/capability-proof.json"))?;
            let request_policy_sha256 =
                host_io::digest(&runtime_root.join("harness/request-policy.json"))?;
            report["primary"]["native_acceptance"] = json!({
                "agent":"claude-code",
                "model":discovery.model,
                "cli_version":discovery.cli_version,
                "executable_sha256":discovery.executable_sha256,
                "strict_tempest_only":discovery.strict_tempest_only,
                "acceptance_relay_verified":discovery.acceptance_relay_verified,
                "launch_permit_verified":discovery.launch_permit_verified,
                "launcher_profile_sha256":launcher_profile_sha256,
                "capability_proof_sha256":capability_proof_sha256,
                "request_policy_sha256":request_policy_sha256,
                "acceptance_request_count":request_policy["acceptance_requests"],
                "production_request_budget":request_policy["maximum_requests"],
                "preserved_evidence_root":"evidence/native-acceptance",
                "runtime_capability_material_retained":false,
            });
            report["adapter"] = launch.adapter.describe();
            report["adapter"]["launcher_profile_sha256"] = launcher_profile_sha256.into();
            report["adapter"]["request_policy_sha256"] = request_policy_sha256.into();
            report["adapter"]["production_request_budget"] =
                request_policy["maximum_requests"].clone();
            preserve_native_acceptance(&runtime_root, &evidence)?;
            native_authorized_ns = Some(host_io::now_ns()?);
            production_request_budget = request_policy["maximum_requests"].as_u64();
            production_relay = Some(launch.relay);
            RuntimeAdapter::Native(Box::new(launch.adapter))
        }
    };
    let mut clock = crate::proxy_cli::private_new(&evidence.join("clock.jsonl"))?;
    vm.clock("pre_seal", &mut clock).await?;
    let seal_started_ns = host_io::now_ns()?;
    vm.call("seal", json!({})).await?;
    let seal_finished_ns = host_io::now_ns()?;
    report["primary"]["seal"] = json!({"started_ns":seal_started_ns,
        "finished_ns":seal_finished_ns,"duration_ns":seal_finished_ns-seal_started_ns});
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
    let agent_started_ns = host_io::now_ns()?;
    report["agent"] = json!({"configured":true,"performed":true,"started_ns":agent_started_ns,"description":adapter.describe()});
    if let Some(authorized_ns) = native_authorized_ns {
        report["primary"]["native_launch_timing"] = json!({
            "authorized_ns":authorized_ns,"agent_run_invoked_ns":agent_started_ns,
            "authorization_to_run_ns":agent_started_ns.saturating_sub(authorized_ns),
            "permit_deadline_ns":60_000_000_000_u64,
        });
    }
    let endpoint = McpCommand {
        executable: adapter.mcp_bridge(&root.join("bin/tempest")),
        socket,
        owner_file: evidence.join("agent-owner.json"),
        raw_stdout: evidence.join("agent.events.jsonl"),
        raw_stderr: evidence.join("agent.stderr"),
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
    let relay_stopped = match production_relay.take() {
        Some(relay) => match relay.shutdown().await {
            Ok(()) => true,
            Err(error) => {
                adapter_failed = true;
                report["primary"]["model_relay_shutdown"] = json!({
                    "verified":false,"failure":error.to_string(),
                });
                false
            }
        },
        None => true,
    };
    let model_relay_audit = evidence.join("model-relay-audit.jsonl");
    if model_relay_audit.is_file() && relay_stopped {
        match production_request_budget
            .ok_or_else(|| io::Error::other("model relay budget binding missing"))
            .and_then(|budget| model_relay_summary(&model_relay_audit, budget))
        {
            Ok((summary, delivery_verified)) => {
                report["primary"]["model_relay_audit"] = json!({
                    "path":"evidence/model-relay-audit.jsonl",
                    "sha256":host_io::digest(&model_relay_audit)?,
                    "summary":summary,
                });
                if !delivery_verified {
                    adapter_failed = true;
                }
            }
            Err(error) => {
                adapter_failed = true;
                report["primary"]["model_relay_audit"] = json!({
                    "path":"evidence/model-relay-audit.jsonl",
                    "sha256":host_io::digest(&model_relay_audit)?,
                    "delivery_verified":false,
                    "failure":error.to_string(),
                });
            }
        }
    } else if production_request_budget.is_some() {
        adapter_failed = true;
        report["primary"]["model_relay_audit"] = json!({"delivery_verified":false,
            "failure":if relay_stopped{"model relay audit missing"}else{"model relay shutdown unverified; audit snapshot forbidden"}});
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
    drop(native_runtime);
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
fn iteration_options(options: &Options, iteration: usize) -> Options {
    let mut value = options.clone();
    value.repeat = 1;
    if options.repeat > 1 {
        value.id = format!("{}-{iteration:03}", options.id);
        value.comparison_slot = options
            .comparison_slot
            .as_ref()
            .map(|slot| format!("{slot}-{iteration:03}"));
    }
    value.iteration = iteration;
    value
}
async fn execute(
    options: Options,
    mut cancel: tokio::sync::watch::Receiver<Option<&'static str>>,
) -> io::Result<(PathBuf, bool)> {
    if cancel.borrow().is_some() {
        return Err(io::Error::other("run cancelled before reservation"));
    }
    let raw = fs::read(&options.scenario)?;
    let loaded = load(&raw).map_err(|_| {
        io::Error::other("scenario validation failed; use tempest validate for diagnostics")
    })?;
    let plan =
        ExecutionPlan::resolve(&loaded.validated, options.actor.as_deref()).map_err(diagnostic)?;
    let (setup, script, planned_adapter) = match &options.agent {
        AgentSelection::Mock { script } => {
            let bytes = fs::read(script)?;
            if bytes.len() > 8 * 1024 * 1024 {
                return Err(io::Error::other("mock script too large"));
            }
            let adapter: MockAdapter = serde_json::from_slice(&bytes)?;
            let description = adapter.describe();
            (AgentSetup::Mock(adapter), Some(bytes), description)
        }
        AgentSelection::ClaudeCode {
            executable,
            model,
            auth_file,
        } => (
            AgentSetup::ClaudeCode {
                executable: executable.clone(),
                model: model.clone(),
                auth_file: auth_file.clone(),
            },
            None,
            json!({"adapter":"claude-code","model":model,"authorization":"acceptance_pending"}),
        ),
    };
    let evaluator_sha256 = host_io::digest(&std::env::current_exe()?)?;
    let comparison_binding = if let (Some(path), Some(slot_id)) = (
        options.comparison_plan.as_deref(),
        options.comparison_slot.as_deref(),
    ) {
        let comparison = crate::comparison_plan::load(path)?;
        if comparison.plan.stopping_rule.minimum_interval_seconds != options.repeat_interval_seconds
        {
            return Err(io::Error::other("comparison plan interval mismatch"));
        }
        let slot = comparison.slot(slot_id, &options.id, &evaluator_sha256)?;
        if slot.finding_configured != plan.self_check().is_some()
            || slot.retest_configured != plan.retest().is_some()
        {
            return Err(io::Error::other("comparison slot presence mismatch"));
        }
        json!({
            "plan_id":comparison.plan.plan_id.clone(),
            "plan_sha256":comparison.sha256.clone(),
            "slot_id":slot.slot_id.clone(),
            "expected_evaluator_sha256":slot.evaluator_sha256.clone(),
            "expected_conditions":slot.comparison_conditions.clone()
        })
    } else {
        Value::Null
    };
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
    if let Some(script) = &script {
        host_io::write_new(&root.join("mock-script.json"), script)?;
    }
    host_io::json_new(&root.join("image-inputs.json"), &inputs)?;
    let companion = root.join("companion");
    host_io::directory(&companion)?;
    host_io::private_copy(&bridge, &companion.join("host_bridge.py"))?;
    host_io::private_copy(&transport, &companion.join("transport.py"))?;
    let budget = &loaded.validated.scenario().budget;
    let mock_script_sha256 = script
        .as_ref()
        .map(|_| host_io::digest(&root.join("mock-script.json")))
        .transpose()?;
    let mut report = json!({"schema_version":1,"scope":"m5_evaluation","purpose":"collection_and_evaluation","iteration":options.iteration,"adapter":planned_adapter,"comparison_binding":comparison_binding,"status":"preparing","run_id":options.id,"scenario_id":loaded.validated.scenario().id,"scenario_sha256":loaded.sha256,"plan":plan.summary(),"started_ns":host_io::now_ns()?,"conditions":{"image_sha256":host_io::digest(&image)?,"izanagi_sha256":host_io::digest(&root.join("bin/izanagi"))?,"tempest_sha256":host_io::digest(&root.join("bin/tempest"))?,"mock_script_sha256":mock_script_sha256,"companion_sha256":host_io::digest(&companion.join("host_bridge.py"))?,"codec_sha256":host_io::digest(&companion.join("transport.py"))?,"restrict_network":true,"snapshot":true,"share_read_only":true,"host_os":std::env::consts::OS,"host_arch":std::env::consts::ARCH,"repeat_interval_seconds":options.repeat_interval_seconds,"max_export_file_bytes":options.maximum_evidence_file_bytes,"budget":{"max_calls":budget.max_calls,"timeout_ms":budget.timeout.0.as_millis()}},"primary":{},"agent":not_performed(true,"upstream_aborted"),"self_check":not_performed(plan.self_check().is_some(),if plan.self_check().is_some(){"upstream_aborted"}else{"not_configured"}),"finding":not_performed(plan.self_check().is_some(),if plan.self_check().is_some(){"evaluation_pending"}else{"not_configured"}),"retest":not_performed(plan.retest().is_some(),if plan.retest().is_some(){"upstream_aborted"}else{"not_configured"}),"evaluation":"not_performed"});
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
        setup,
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
    if let Some(path) = path.strip_prefix("evidence/native-acceptance/") {
        return matches!(
            path,
            "launcher-profile.json"
                | "capability-proof.json"
                | "request-policy.json"
                | "acceptance-relay-audit.jsonl"
                | "acceptance-mcp.jsonl"
                | "evidence/allowed_mcp_succeeded.json"
                | "evidence/control_socket_unavailable.json"
                | "evidence/hmac_unavailable.json"
                | "evidence/host_canary_read_denied.json"
                | "evidence/host_canary_write_denied.json"
                | "evidence/host_tools_rejected.json"
                | "evidence/mcp_child_env_sanitized.json"
                | "evidence/provider_request_policy.json"
                | "evidence/tool_catalog_exact.json"
        );
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
            | "evidence/agent.events.jsonl"
            | "evidence/agent.stderr"
            | "evidence/agent-owner.json"
            | "evidence/api.jsonl"
            | "evidence/capture.pcap"
            | "evidence/collection.json"
            | "evidence/export-index.json"
            | "evidence/manifest.json"
            | "evidence/mcp.jsonl"
            | "evidence/mcp-owner.json"
            | "evidence/mcp.stderr"
            | "evidence/model-relay-audit.jsonl"
            | "evidence/model-relay-owner.json"
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
    {
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
            if name == "__pycache__"
                || relative == ".native-runtime"
                || relative.ends_with("sandbox/.tempest-control")
            {
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
    if !matches!(
        owner["state"].as_str(),
        Some("running" | "stop_requested" | "stopped")
    ) {
        return Err(io::Error::other("owned process launch outcome is unknown"));
    }
    let group = owner["process_group"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 1)
        .ok_or_else(|| io::Error::other("invalid owned process group"))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while process_group_alive(group) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if process_group_alive(group) {
        return Err(io::Error::other(
            "owned process group is still alive; no signal sent",
        ));
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
        root.join("evidence/model-relay-owner.json"),
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
        let (sender, mut receiver) = tokio::sync::watch::channel(None);
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let signal = tokio::spawn(async move {
            let reason =
                tokio::select! {_=tokio::signal::ctrl_c()=>"sigint",_=term.recv()=>"sigterm"};
            let _ = sender.send(Some(reason));
        });
        let mut results = Vec::with_capacity(options.repeat);
        let mut stop_reason = None;
        for iteration in 1..=options.repeat {
            if let Some(reason) = *receiver.borrow() {
                stop_reason = Some(format!("cancelled:{reason}"));
                break;
            }
            match execute(iteration_options(&options, iteration), receiver.clone()).await {
                Ok(result) => results.push(result),
                Err(error) => {
                    stop_reason = Some(format!("infrastructure:{error}"));
                    break;
                }
            }
            if let Some(reason) = *receiver.borrow() {
                stop_reason = Some(format!("cancelled:{reason}"));
                break;
            }
            if iteration < options.repeat && options.repeat_interval_seconds > 0 {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(options.repeat_interval_seconds)) => {}
                    reason = cancelled(&mut receiver) => {
                        stop_reason = Some(format!("cancelled:{reason}"));
                        break;
                    }
                }
            }
        }
        signal.abort();
        Ok::<_, io::Error>((results, stop_reason))
    });
    runtime.shutdown_background();
    match result {
        Ok((results, stop_reason)) => {
            let runs = results
                .iter()
                .map(|(path, success)| {
                    let metadata: Value = fs::read(path.join("run.json"))
                        .ok()
                        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                        .unwrap_or(Value::Null);
                    json!({"run_directory":path,"status":metadata["status"],"evaluation":metadata["evaluation"],"finalization":metadata["finalization"],"success":success})
                })
                .collect::<Vec<_>>();
            if runs.len() == 1 && stop_reason.is_none() {
                println!(
                    "{}",
                    json!({"run_directory":runs[0]["run_directory"],"status":runs[0]["status"],"scope":"m5_evaluation","evaluation":runs[0]["evaluation"],"finalization":runs[0]["finalization"]})
                );
            } else {
                println!(
                    "{}",
                    json!({"scope":"m5_evaluation","runs":runs,"stopped":stop_reason})
                );
            }
            if stop_reason.is_none() && results.iter().all(|(_, success)| *success) {
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

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn run_options_separate_mock_and_native_authority() {
        let base = [
            "scenario.yaml",
            "--izanagi",
            "/bin/izanagi",
            "--image",
            "/tmp/image.qcow2",
            "--image-inputs",
            "/tmp/image-inputs.json",
        ];
        let mut native = base.to_vec();
        native.extend([
            "--agent",
            "claude-code",
            "--agent-executable",
            "/opt/claude",
            "--model",
            "claude-sonnet-5-5",
            "--model-auth-file",
            "/tmp/anthropic-key",
        ]);
        let parsed = options(&arguments(&native)).unwrap();
        assert!(matches!(
            parsed.agent,
            AgentSelection::ClaudeCode { ref model, .. } if model == "claude-sonnet-5-5"
        ));

        let mut mixed = native;
        mixed.extend(["--mock-script", "/tmp/mock.json"]);
        assert!(options(&arguments(&mixed)).is_err());

        let mut incomplete = base.to_vec();
        incomplete.extend(["--agent", "claude-code", "--model", "claude-sonnet-5-5"]);
        assert!(options(&arguments(&incomplete)).is_err());
    }

    #[test]
    fn native_run_passes_an_uncreated_child_to_capability_discovery() {
        let root = std::env::temp_dir().join(format!(
            "tempest-native-runtime-path-{}",
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        let (guard, output) = native_runtime_directory(&root).unwrap();
        assert_eq!(output, root.join(".native-runtime/discovery"));
        assert!(!output.exists());
        drop(guard);
        assert!(!root.join(".native-runtime").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_acceptance_keeps_reviewable_evidence_but_drops_runtime_capabilities() {
        let root = std::env::temp_dir().join(format!(
            "tempest-native-preserved-evidence-{}",
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        let (guard, output) = native_runtime_directory(&root).unwrap();
        host_io::directory(&output).unwrap();
        for directory in ["acceptance-proof", "acceptance-proof/evidence", "harness"] {
            host_io::directory(&output.join(directory)).unwrap();
        }
        for path in [
            "acceptance-proof/launcher-profile.json",
            "acceptance-proof/capability-proof.json",
            "harness/request-policy.json",
            "harness/model-relay-audit.jsonl",
            "harness/acceptance-mcp.jsonl",
        ] {
            host_io::write_new(&output.join(path), b"fixture").unwrap();
        }
        for check in [
            "allowed_mcp_succeeded",
            "control_socket_unavailable",
            "hmac_unavailable",
            "host_canary_read_denied",
            "host_canary_write_denied",
            "host_tools_rejected",
            "mcp_child_env_sanitized",
            "provider_request_policy",
            "tool_catalog_exact",
        ] {
            host_io::write_new(
                &output
                    .join("acceptance-proof/evidence")
                    .join(format!("{check}.json")),
                b"fixture",
            )
            .unwrap();
        }
        let evidence = root.join("evidence");
        host_io::directory(&evidence).unwrap();
        preserve_native_acceptance(&output, &evidence).unwrap();
        drop(guard);
        assert!(!root.join(".native-runtime").exists());
        assert!(
            evidence
                .join("native-acceptance/capability-proof.json")
                .is_file()
        );
        let mut paths = Vec::new();
        collect_artifacts(&root, &evidence, &mut paths).unwrap();
        assert!(paths.iter().all(|path| allowed_artifact(path)));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn production_relay_audit_requires_paired_completed_deliveries() {
        let root = std::env::temp_dir().join(format!(
            "tempest-production-relay-audit-{}",
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        let path = root.join("audit.jsonl");
        let sha = "a".repeat(64);
        let admitted = json!({"request_sha256":sha,"delivery_state":"not_sent",
            "reason":"admission_verified","forwarded":false});
        let completed = json!({"request_sha256":"a".repeat(64),
            "delivery_state":"response_complete","reason":null,"forwarded":true});
        host_io::write_new(&path, format!("{}\n{}\n", admitted, completed).as_bytes()).unwrap();
        let (summary, verified) = model_relay_summary(&path, 20).unwrap();
        assert!(verified);
        assert_eq!(summary["requests"], 1);
        fs::write(
            &path,
            format!(
                "{}\n",
                json!({"request_sha256":"a".repeat(64),
                "delivery_state":"request_outcome_unknown","reason":"upstream transport failed",
                "forwarded":false})
            ),
        )
        .unwrap();
        let (summary, verified) = model_relay_summary(&path, 20).unwrap();
        assert!(!verified);
        assert_eq!(summary["delivery_states"]["request_outcome_unknown"], 1);
        assert_eq!(summary["reasons"]["upstream transport failed"], 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn repeat_expands_run_and_comparison_slot_ids_deterministically() {
        let options = Options {
            scenario: "scenario".into(),
            agent: AgentSelection::Mock {
                script: "script".into(),
            },
            izanagi: "izanagi".into(),
            image: "image".into(),
            inputs: "inputs".into(),
            bridge: "bridge".into(),
            python: "python".into(),
            runs: "runs".into(),
            id: "batch".into(),
            actor: None,
            comparison_plan: Some("plan".into()),
            comparison_slot: Some("slot".into()),
            maximum_evidence_file_bytes: 1,
            repeat: 3,
            repeat_interval_seconds: 0,
            iteration: 1,
        };
        let values = (1..=options.repeat)
            .map(|iteration| iteration_options(&options, iteration))
            .collect::<Vec<_>>();
        assert_eq!(values[0].id, "batch-001");
        assert_eq!(values[2].id, "batch-003");
        assert_eq!(values[1].comparison_slot.as_deref(), Some("slot-002"));
        assert_eq!(values[2].iteration, 3);
        assert!(values.iter().all(|value| value.repeat == 1));
    }

    #[tokio::test]
    async fn preexisting_cancellation_has_no_run_reservation_side_effect() {
        let root = std::env::temp_dir().join(format!(
            "tempest-repeat-cancel-{}",
            host_io::random_hex().unwrap()
        ));
        let options = Options {
            scenario: root.join("missing-scenario"),
            agent: AgentSelection::Mock {
                script: root.join("missing-script"),
            },
            izanagi: root.join("missing-izanagi"),
            image: root.join("missing-image"),
            inputs: root.join("missing-inputs"),
            bridge: root.join("missing-bridge"),
            python: root.join("missing-python"),
            runs: root.join("runs"),
            id: "batch-002".into(),
            actor: None,
            comparison_plan: None,
            comparison_slot: None,
            maximum_evidence_file_bytes: 1,
            repeat: 1,
            repeat_interval_seconds: 0,
            iteration: 2,
        };
        let (sender, receiver) = tokio::sync::watch::channel(None);
        sender.send(Some("sigint")).unwrap();
        assert!(execute(options, receiver).await.is_err());
        assert!(!root.exists());
    }

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
        assert_eq!(report["execution_status"], "aborted");
        assert_eq!(report["evaluation"], "unavailable");
        assert!(root.join("evaluation-state.json").is_file());
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
        let mut owned = std::process::Command::new("/bin/sleep");
        owned
            .arg("30")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut owned = owned.spawn().unwrap();
        let owned_group = owned.id();
        let reaper = tokio::task::spawn_blocking(move || owned.wait());
        host_io::json_replace(
            &owner,
            &json!({"state":"running","process_group":owned_group}),
        )
        .unwrap();
        assert!(verify_owned_group_gone(&owner).await.is_err());
        assert!(process_group_alive(owned_group));
        unsafe {
            libc::kill(-(owned_group as i32), libc::SIGKILL);
        }
        let _ = reaper.await.unwrap().unwrap();
        assert!(!process_group_alive(owned_group));
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
