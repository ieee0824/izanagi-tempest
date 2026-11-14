//! Trusted native launcher probe. Discovery is the first pass; acceptance is
//! issued only after a second, relay-gated pass validates the frozen contract.
use crate::{
    adapter::{
        CapabilityProbeCliConfig, CliAdapter, CliAdapterConfig, CliKind, McpCommand,
        claude_argument_template, claude_environment_rules, codex_argument_template,
        codex_environment_rules, run_capability_probe_cli,
    },
    admission::CloseReason,
    capability_probe_provider::{ProbeAgent, ProbeIdentity, ProbeProvider},
    capability_proof::{ProbeChallenge, authorize_staged_launch},
    host_io, model_api_relay,
    relay::RelayConfig,
    supervisor::{Supervisor, SupervisorConfig},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::net::UnixListener;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityAgent {
    Codex,
    ClaudeCode,
}

pub struct CapabilityDiscoveryConfig {
    pub agent: CapabilityAgent,
    pub executable: PathBuf,
    pub model: String,
    pub output: PathBuf,
}

pub struct CapabilityDiscovery {
    pub agent: CapabilityAgent,
    pub cli_version: String,
    pub model: String,
    pub executable_sha256: String,
    pub catalogs: Vec<Vec<Value>>,
    pub tool_outputs: Vec<Vec<Value>>,
    pub request_fields: Vec<Vec<String>>,
    pub strict_tempest_only: bool,
    pub codex_framework_exception_verified: bool,
    pub acceptance_relay_verified: bool,
    pub launch_permit_verified: bool,
}

pub(crate) struct AuthorizedNativeLaunch {
    pub(crate) discovery: CapabilityDiscovery,
    pub(crate) adapter: CliAdapter,
    pub(crate) relay: model_api_relay::ProductionRelay,
}

pub(crate) struct ProductionLaunchConfig {
    pub(crate) auth_file: PathBuf,
    pub(crate) audit_file: PathBuf,
    pub(crate) owner_file: PathBuf,
    pub(crate) launch_harness_root: PathBuf,
    pub(crate) upstream: String,
}

fn production_auth_header(agent: CapabilityAgent) -> &'static str {
    match agent {
        CapabilityAgent::Codex => "authorization",
        CapabilityAgent::ClaudeCode => "x-api-key",
    }
}

fn expected_mcp_policy_rejections(agent: CapabilityAgent) -> u64 {
    match agent {
        CapabilityAgent::Codex => 5,
        // Claude Code probes the non-standard `server/discover` method once.
        // The Tempest MCP allowlist rejects it before Izanagi sees it.
        CapabilityAgent::ClaudeCode => 1,
    }
}

struct CapabilitySocketDirectory {
    path: PathBuf,
    remove_on_drop: bool,
}

impl Drop for CapabilitySocketDirectory {
    fn drop(&mut self) {
        if self.remove_on_drop {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn capability_socket_directory(root: &Path) -> io::Result<CapabilitySocketDirectory> {
    if cfg!(target_os = "macos") {
        let path = PathBuf::from("/private/tmp").join(format!("tc-{}", host_io::random_hex()?));
        host_io::directory(&path)?;
        Ok(CapabilitySocketDirectory {
            path,
            remove_on_drop: true,
        })
    } else {
        Ok(CapabilitySocketDirectory {
            path: root.join("socket"),
            remove_on_drop: false,
        })
    }
}

fn strict_tempest_catalog(agent: CapabilityAgent, catalog: &[Value]) -> bool {
    let names = catalog
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    match agent {
        CapabilityAgent::Codex => false,
        CapabilityAgent::ClaudeCode => {
            names
                == [
                    "mcp__tempest__sandbox_exec",
                    "mcp__tempest__sandbox_shell",
                    "mcp__tempest__sandbox_status",
                ]
        }
    }
}

fn codex_framework_exception_catalog(catalog: &[Value]) -> bool {
    let names = catalog
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    if names
        != [
            "list_mcp_resources",
            "list_mcp_resource_templates",
            "read_mcp_resource",
            "request_user_input",
            "mcp__tempest",
        ]
        || catalog
            .get(4)
            .is_none_or(|tool| tool["type"] != "namespace")
    {
        return false;
    }
    let framework_bytes = match serde_json::to_vec(&catalog[..4]) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    format!("{:x}", Sha256::digest(framework_bytes))
        == "38be71810fa4b995fd7ad3b1be26e60ceb184cdfa66ec4ab3802ef470dc3d51f"
}

fn validate_catalog(agent: CapabilityAgent, catalogs: &[Vec<Value>]) -> io::Result<()> {
    let Some(expected) = catalogs.first() else {
        return Err(io::Error::other("capability discovery catalog missing"));
    };
    if expected.is_empty() || catalogs.iter().any(|catalog| catalog != expected) {
        return Err(io::Error::other("capability discovery catalog changed"));
    }
    let names = expected
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect::<Vec<_>>();
    let valid = match agent {
        CapabilityAgent::Codex => codex_framework_exception_catalog(expected),
        CapabilityAgent::ClaudeCode => {
            names
                == [
                    "mcp__tempest__sandbox_exec",
                    "mcp__tempest__sandbox_shell",
                    "mcp__tempest__sandbox_status",
                ]
        }
    };
    if !valid {
        return Err(io::Error::other(
            "capability discovery exposed an unexpected tool catalog",
        ));
    }
    Ok(())
}

fn validate_tool_outputs(
    agent: CapabilityAgent,
    outputs: &[Vec<Value>],
    probe_id: &str,
    host_canary_value: &str,
) -> io::Result<()> {
    let final_outputs = outputs
        .last()
        .ok_or_else(|| io::Error::other("capability discovery tool outputs missing"))?;
    let output_count = match agent {
        CapabilityAgent::Codex => 13,
        CapabilityAgent::ClaudeCode => 7,
    };
    let expected_ids = (0..output_count)
        .map(|index| format!("call_{index}"))
        .collect::<Vec<_>>();
    let mut by_id = std::collections::BTreeMap::new();
    for output in final_outputs {
        let id = match agent {
            CapabilityAgent::Codex => output["call_id"].as_str(),
            CapabilityAgent::ClaudeCode => output["tool_use_id"].as_str(),
        }
        .ok_or_else(|| io::Error::other("capability discovery tool output ID missing"))?;
        if !expected_ids.iter().any(|expected| expected == id)
            || by_id.insert(id.to_owned(), output).is_some()
        {
            return Err(io::Error::other(
                "capability discovery tool output ID mismatch",
            ));
        }
    }
    if by_id.len() != expected_ids.len() {
        return Err(io::Error::other(
            "capability discovery tool outputs incomplete",
        ));
    }
    let rejected_names = match agent {
        CapabilityAgent::Codex => [
            "exec_command",
            "apply_patch",
            "view_image",
            "exec_command",
            "exec_command",
        ],
        CapabilityAgent::ClaudeCode => ["Bash", "Write", "Read", "Read", "Read"],
    };
    for (index, name) in rejected_names.iter().enumerate() {
        let output = by_id[&format!("call_{index}")];
        let valid = match agent {
            CapabilityAgent::Codex => {
                output["type"] == "function_call_output"
                    && output["output"] == format!("unsupported call: {name}")
            }
            CapabilityAgent::ClaudeCode => {
                output["type"] == "tool_result"
                    && output["is_error"] == true
                    && output["content"].as_str().is_some_and(|value| {
                        value.starts_with(&format!(
                            "<tool_use_error>Error: No such tool available: {name}."
                        ))
                    })
            }
        };
        if !valid {
            return Err(io::Error::other(
                "capability discovery host tool rejection not established",
            ));
        }
    }
    if agent == CapabilityAgent::Codex {
        let exact = |index: usize, expected: &str| {
            let output = by_id[&format!("call_{index}")];
            output["type"] == "function_call_output"
                && output["call_id"] == format!("call_{index}")
                && output["output"] == expected
                && output.get("is_error").is_none()
                && output.get("isError").is_none()
        };
        let tempest_list_rejected = by_id["call_6"]["output"]
            .as_str()
            .is_some_and(|value| {
                value
                    == "resources/list failed: resources/list failed for `tempest`: Mcp error: -32601: MCP method not allowed"
            });
        let tempest_templates_rejected = by_id["call_8"]["output"]
            .as_str()
            .is_some_and(|value| {
                value
                    == "resources/templates/list failed: resources/templates/list failed for `tempest`: Mcp error: -32601: MCP method not allowed"
            });
        let tempest_read_rejected = by_id["call_9"]["output"].as_str().is_some_and(|value| {
            value.starts_with("resources/read failed: resources/read failed for `tempest` (")
                && value.ends_with("Mcp error: -32601: MCP method not allowed")
        });
        if !exact(5, "{\"resources\":[]}")
            || !tempest_list_rejected
            || !exact(7, "{\"resourceTemplates\":[]}")
            || !tempest_templates_rejected
            || !tempest_read_rejected
            || !exact(10, "unknown MCP server 'other'")
            || !exact(11, "request_user_input is unavailable in Default mode")
            || (5..=11).any(|index| {
                serde_json::to_string(by_id[&format!("call_{index}")])
                    .is_ok_and(|value| value.contains(host_canary_value))
            })
        {
            return Err(io::Error::other(
                "Codex fixed framework tool exception was not established",
            ));
        }
    }
    let bypass_index = match agent {
        CapabilityAgent::Codex => 9,
        CapabilityAgent::ClaudeCode => 5,
    };
    let bypass = by_id[&format!("call_{bypass_index}")];
    let bypass_rejected = match agent {
        CapabilityAgent::Codex => true,
        CapabilityAgent::ClaudeCode => {
            bypass["type"] == "tool_result"
                && bypass["tool_use_id"] == "call_5"
                && bypass["is_error"] == true
                && bypass["content"]
                    == "<tool_use_error>Error: No such tool available: mcp__other__read</tool_use_error>"
        }
    };
    if !bypass_rejected || serde_json::to_string(bypass)?.contains(host_canary_value) {
        return Err(io::Error::other(
            "capability discovery MCP bypass rejection not established",
        ));
    }
    let allowed_index = match agent {
        CapabilityAgent::Codex => 12,
        CapabilityAgent::ClaudeCode => 6,
    };
    let allowed = by_id[&format!("call_{allowed_index}")];
    let allowed_text = match agent {
        CapabilityAgent::Codex
            if allowed["type"] == "function_call_output"
                && allowed["call_id"] == format!("call_{allowed_index}")
                && allowed.get("is_error").is_none()
                && allowed.get("isError").is_none() =>
        {
            allowed["output"]
                .as_array()
                .and_then(|items| items.last())
                .filter(|item| item["type"] == "input_text")
                .and_then(|item| item["text"].as_str())
        }
        CapabilityAgent::ClaudeCode
            if allowed["type"] == "tool_result"
                && allowed["tool_use_id"] == format!("call_{allowed_index}")
                && allowed.get("is_error").is_none() =>
        {
            allowed["content"]
                .as_array()
                .and_then(|items| items.first())
                .filter(|item| item["type"] == "text")
                .and_then(|item| item["text"].as_str())
        }
        _ => None,
    };
    let allowed_value = allowed_text
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .filter(|value| value.as_object().is_some_and(|object| object.len() == 2));
    if !allowed_value.is_some_and(|value| value["probe_id"] == probe_id && value["running"] == true)
    {
        return Err(io::Error::other(
            "capability discovery allowed MCP call not established",
        ));
    }
    Ok(())
}

fn codex_framework_response_ns(
    requests: &[crate::capability_probe_provider::ProbeRequest],
) -> io::Result<u64> {
    let started = requests
        .get(11)
        .map(|request| request.observed_ns)
        .filter(|value| *value > 0)
        .ok_or_else(|| io::Error::other("Codex request_user_input start observation missing"))?;
    let finished = requests
        .get(12)
        .map(|request| request.observed_ns)
        .filter(|value| *value >= started)
        .ok_or_else(|| {
            io::Error::other("Codex request_user_input completion observation missing")
        })?;
    let elapsed = finished - started;
    if elapsed > 5_000_000_000 {
        return Err(io::Error::other(
            "Codex request_user_input did not reject within five seconds",
        ));
    }
    Ok(elapsed)
}

pub fn run(args: &[OsString]) -> std::process::ExitCode {
    const USAGE: &str = "Usage: tempest capability-discover --agent codex|claude-code --executable FILE --model EXACT_MODEL_ID --output DIR";
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{USAGE}");
        return std::process::ExitCode::SUCCESS;
    }
    if args.len() != 8 {
        eprintln!("{USAGE}");
        return std::process::ExitCode::from(2);
    }
    let mut agent = None;
    let mut executable = None;
    let mut model = None;
    let mut output = None;
    for pair in args.chunks_exact(2) {
        match pair[0].to_str() {
            Some("--agent") if agent.is_none() => {
                agent = match pair[1].to_str() {
                    Some("codex") => Some(CapabilityAgent::Codex),
                    Some("claude-code") => Some(CapabilityAgent::ClaudeCode),
                    _ => None,
                };
            }
            Some("--executable") if executable.is_none() => {
                executable = Some(PathBuf::from(&pair[1]));
            }
            Some("--model") if model.is_none() => {
                model = pair[1]
                    .to_str()
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned);
            }
            Some("--output") if output.is_none() => output = Some(PathBuf::from(&pair[1])),
            _ => {
                eprintln!("{USAGE}");
                return std::process::ExitCode::from(2);
            }
        }
    }
    let (Some(agent), Some(executable), Some(model), Some(output)) =
        (agent, executable, model, output)
    else {
        eprintln!("{USAGE}");
        return std::process::ExitCode::from(2);
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("capability discovery: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match runtime.block_on(discover(CapabilityDiscoveryConfig {
        agent,
        executable,
        model,
        output,
    })) {
        Ok(discovery) => {
            println!(
                "{}",
                serde_json::json!({"agent":match discovery.agent {CapabilityAgent::Codex=>"codex",
                    CapabilityAgent::ClaudeCode=>"claude-code"},
                    "cli_version":discovery.cli_version,
                    "model":discovery.model,
                    "executable_sha256":discovery.executable_sha256,
                    "requests":discovery.catalogs.len(),
                    "strict_tempest_only":discovery.strict_tempest_only,
                    "codex_framework_exception_verified":discovery.codex_framework_exception_verified,
                    "acceptance_relay_verified":discovery.acceptance_relay_verified,
                    "launch_permit_verified":discovery.launch_permit_verified,
                    "tool_output_rounds":discovery.tool_outputs.iter().filter(|values| !values.is_empty()).count(),
                    "request_shapes":discovery.request_fields})
            );
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("capability discovery: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn version(executable: &Path) -> io::Result<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        host_io::command(executable)
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| io::Error::other("capability probe version deadline"))??;
    if !output.status.success() || output.stdout.is_empty() || output.stdout.len() > 4096 {
        return Err(io::Error::other("capability probe version command failed"));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| io::Error::other("capability probe version is not UTF-8"))
}

fn private_file(path: &Path, value: &[u8]) -> io::Result<()> {
    host_io::write_new(path, value)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn collect_value_types(value: &Value, values: &mut BTreeSet<String>) -> io::Result<()> {
    match value {
        Value::Object(object) => {
            if let Some(kind) = object.get("type") {
                values.insert(
                    kind.as_str()
                        .ok_or_else(|| io::Error::other("provider request type is not text"))?
                        .to_owned(),
                );
            }
            for (name, child) in object {
                if name != "tools" {
                    collect_value_types(child, values)?;
                }
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_value_types(child, values)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn frozen_request_policy(
    requests: &[crate::capability_probe_provider::ProbeRequest],
    provider_prefix: &str,
) -> io::Result<Value> {
    let first = requests
        .first()
        .ok_or_else(|| io::Error::other("provider requests missing"))?;
    let tools = first.tools.clone();
    if tools.is_empty() || requests.iter().any(|request| request.tools != tools) {
        return Err(io::Error::other("provider tool catalog was not stable"));
    }
    let mut paths = BTreeSet::new();
    let mut models = BTreeSet::new();
    let mut fields = BTreeSet::new();
    let mut value_types = BTreeSet::new();
    let mut required_request_values = BTreeMap::new();
    for request in requests {
        let path = request
            .path
            .strip_prefix(provider_prefix)
            .filter(|path| path.starts_with('/'))
            .ok_or_else(|| io::Error::other("provider request path escaped its capability"))?;
        paths.insert(path.to_owned());
        let object = request
            .body
            .as_object()
            .ok_or_else(|| io::Error::other("provider request is not an object"))?;
        models.insert(
            object
                .get("model")
                .and_then(Value::as_str)
                .ok_or_else(|| io::Error::other("provider request model missing"))?
                .to_owned(),
        );
        fields.extend(object.keys().cloned());
        let mut without_tools = request.body.clone();
        without_tools.as_object_mut().unwrap().remove("tools");
        collect_value_types(&without_tools, &mut value_types)?;
    }
    for name in [
        "include",
        "parallel_tool_calls",
        "reasoning",
        "store",
        "stream",
        "tool_choice",
    ] {
        if let Some(expected) = first.body.get(name) {
            if requests
                .iter()
                .any(|request| request.body.get(name) != Some(expected))
            {
                return Err(io::Error::other(format!(
                    "security-sensitive request value changed: {name}"
                )));
            }
            required_request_values.insert(name.to_owned(), expected.clone());
        }
    }
    let dynamic_request_values = [
        ("client_metadata", "codex_client_metadata_v1"),
        ("prompt_cache_key", "uuid"),
    ]
    .into_iter()
    .filter(|(name, _)| first.body.get(*name).is_some())
    .map(|(name, validator)| (name.to_owned(), validator.to_owned()))
    .collect::<BTreeMap<_, _>>();
    Ok(serde_json::json!({
        "schema_version":1,
        "paths":paths,
        "models":models,
        "top_level_fields":fields,
        "required_request_values":required_request_values,
        "dynamic_request_values":dynamic_request_values,
        "request_value_types":value_types,
        "request_headers":{"content-type":"application/json"},
        "acceptance_requests":requests.len(),
        "tools":tools,
    }))
}

fn approved_observation(policy: &Value) -> io::Result<Value> {
    let mut observation = policy.clone();
    let object = observation
        .as_object_mut()
        .ok_or_else(|| io::Error::other("reviewed request policy is not an object"))?;
    object
        .remove("maximum_requests")
        .ok_or_else(|| io::Error::other("reviewed production request budget missing"))?;
    object
        .remove("mcp_catalog_source")
        .ok_or_else(|| io::Error::other("reviewed MCP catalog source missing"))?;
    Ok(observation)
}

fn acceptance_policy(policy: &Value) -> io::Result<Value> {
    let mut acceptance = policy.clone();
    let requests = acceptance
        .get("acceptance_requests")
        .and_then(Value::as_u64)
        .ok_or_else(|| io::Error::other("reviewed acceptance request count missing"))?;
    acceptance["maximum_requests"] = requests.into();
    Ok(acceptance)
}

fn approved_request_policy(
    agent: CapabilityAgent,
    cli_version: &str,
    model: &str,
) -> io::Result<Value> {
    let bytes: &[u8] = match (agent, cli_version, model) {
        (CapabilityAgent::Codex, "codex-cli 0.169.0", "gpt-6.1") => {
            include_bytes!("../policies/codex-0.169.0-gpt-6.1-openai-responses.json")
        }
        (CapabilityAgent::ClaudeCode, "2.1.323 (Claude Code)", "claude-haiku-5-5") => {
            include_bytes!(
                "../policies/claude-code-2.1.323-claude-haiku-5-5-anthropic-messages.json"
            )
        }
        (CapabilityAgent::ClaudeCode, "2.1.323 (Claude Code)", "claude-sonnet-5-5") => {
            include_bytes!(
                "../policies/claude-code-2.1.323-claude-sonnet-5-5-anthropic-messages.json"
            )
        }
        _ => {
            return Err(io::Error::other(
                "no reviewed model request policy for this CLI version and exact model ID",
            ));
        }
    };
    crate::capability_proof::parse_unique_value(bytes)
}

pub(crate) fn reviewed_request_policy(
    agent: CapabilityAgent,
    version: &str,
    model: &str,
) -> io::Result<Value> {
    approved_request_policy(agent, version, model)
}

fn validate_relay_audit(
    path: &Path,
    expected_requests: usize,
    expected_rejections: usize,
    expected_hello_path: &str,
) -> io::Result<()> {
    let text = fs::read_to_string(path)?;
    let rows = text
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).map_err(io::Error::other))
        .collect::<io::Result<Vec<_>>>()?;
    let admitted = rows
        .iter()
        .filter(|row| row["forwarded"] == false && row["reason"] == "admission_verified")
        .count();
    let forwarded = rows
        .iter()
        .filter(|row| row["forwarded"] == true && row["reason"].is_null())
        .count();
    let rejected_health_probes = rows
        .iter()
        .filter(|row| {
            row["forwarded"] == false
                && row["reason"] == "reviewed preflight rejected"
                && row["method"] == "HEAD"
                && row["path"] == expected_hello_path
                && row["model"].is_null()
                && row["tools"].as_array().is_some_and(Vec::is_empty)
                && row["upstream_status"].is_null()
        })
        .count();
    if rows.len() != expected_requests * 2 + rejected_health_probes + expected_rejections
        || admitted != expected_requests
        || forwarded != expected_requests
        || rejected_health_probes > 1
    {
        return Err(io::Error::other(
            "acceptance relay audit contains a rejection or incomplete request",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct ExpectedRelayRejection {
    request_sha256: String,
    reason: String,
}

async fn submit_relay_rejection(
    endpoint: &str,
    path: &str,
    body: &Value,
    expected_reason: &str,
) -> io::Result<ExpectedRelayRejection> {
    let bytes = serde_json::to_vec(body)?;
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .map_err(io::Error::other)?
        .post(format!("{endpoint}{path}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(bytes.clone())
        .send()
        .await
        .map_err(io::Error::other)?;
    if response.status().is_success() {
        return Err(io::Error::other("relay negative probe was accepted"));
    }
    let response_bytes = response.bytes().await.map_err(io::Error::other)?;
    let value: Value = serde_json::from_slice(&response_bytes).map_err(io::Error::other)?;
    if value["reason"] != expected_reason || value["error"] != "request_rejected" {
        return Err(io::Error::other(
            "relay negative probe returned an unexpected rejection",
        ));
    }
    Ok(ExpectedRelayRejection {
        request_sha256: format!("{:x}", Sha256::digest(&bytes)),
        reason: expected_reason.to_owned(),
    })
}

fn mutate_first_request_type(value: &mut Value) -> bool {
    match value {
        Value::Object(object) => {
            if let Some(kind) = object.get_mut("type")
                && kind.is_string()
            {
                *kind = "tempest_forbidden_type".into();
                return true;
            }
            object
                .iter_mut()
                .filter(|(name, _)| name.as_str() != "tools")
                .any(|(_, child)| mutate_first_request_type(child))
        }
        Value::Array(array) => array.iter_mut().any(mutate_first_request_type),
        _ => false,
    }
}

async fn prove_relay_rejections(
    endpoint: &str,
    path: &str,
    baseline: &Value,
) -> io::Result<Vec<ExpectedRelayRejection>> {
    let mut cases = Vec::new();

    let mut catalog = baseline.clone();
    let description = catalog["tools"][0]["description"]
        .as_str()
        .ok_or_else(|| io::Error::other("baseline tool description missing"))?;
    catalog["tools"][0]["description"] = format!("{description} changed").into();
    cases.push(submit_relay_rejection(endpoint, path, &catalog, "tool catalog mismatch").await?);

    let mut extra_field = baseline.clone();
    extra_field
        .as_object_mut()
        .ok_or_else(|| io::Error::other("baseline request is not an object"))?
        .insert("tempest_extra".into(), true.into());
    cases.push(
        submit_relay_rejection(
            endpoint,
            path,
            &extra_field,
            "unknown top-level request field",
        )
        .await?,
    );

    let mut value_type = baseline.clone();
    if !mutate_first_request_type(&mut value_type) {
        return Err(io::Error::other("baseline request type missing"));
    }
    cases.push(
        submit_relay_rejection(
            endpoint,
            path,
            &value_type,
            "request value type is not allowed: tempest_forbidden_type",
        )
        .await?,
    );

    let mut model = baseline.clone();
    model["model"] = "tempest-forbidden-model".into();
    cases.push(
        submit_relay_rejection(endpoint, path, &model, "request model is not allowed").await?,
    );
    cases.push(
        submit_relay_rejection(
            endpoint,
            "/tempest-forbidden-path",
            baseline,
            "request path is not allowed",
        )
        .await?,
    );
    Ok(cases)
}

fn validate_relay_rejections(path: &Path, expected: &[ExpectedRelayRejection]) -> io::Result<()> {
    let rows = fs::read_to_string(path)?
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).map_err(io::Error::other))
        .collect::<io::Result<Vec<_>>>()?;
    for rejection in expected {
        let matches = rows
            .iter()
            .filter(|row| {
                row["forwarded"] == false
                    && row["request_sha256"] == rejection.request_sha256
                    && row["reason"] == rejection.reason
                    && row["upstream_status"].is_null()
            })
            .count();
        if matches != 1 {
            return Err(io::Error::other(
                "relay negative probe audit binding mismatch",
            ));
        }
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn stage_authorized_code(root: &Path, source: &Path) -> io::Result<PathBuf> {
    let destination = root.join("authorized-code");
    for directory in [
        "authorized-code",
        "authorized-code/jail",
        "authorized-code/jail/bin",
        "authorized-code/host",
    ] {
        host_io::directory(&root.join(directory))?;
    }
    let runner = std::env::current_exe()?.canonicalize()?;
    for (from, to) in [
        (source, destination.join("jail/bin/agent")),
        (&runner, destination.join("jail/bin/tempest")),
        (&runner, destination.join("host/model-api-relay")),
    ] {
        host_io::private_copy(from, &to)?;
        fs::set_permissions(&to, fs::Permissions::from_mode(0o500))?;
    }
    Ok(destination)
}

struct ProofInputs<'a> {
    root: &'a Path,
    prepared: &'a PreparedProof,
    request_count: usize,
    negative_count: usize,
    canary_sha256: &'a str,
    started_ns: u64,
    finished_ns: u64,
    control_started_ns: u64,
    control_finished_ns: u64,
    framework_response_ns: Option<u64>,
    framework_mcp_policy_rejections: Option<u64>,
}

struct PreparedProof {
    agent: CapabilityAgent,
    proof_root: PathBuf,
    profile_sha256: String,
    runner_sha256: String,
    policy_sha256: String,
    catalog_sha256: String,
    acceptance_request_count: u64,
    production_request_budget: u64,
}

fn reviewed_system_configuration(agent: CapabilityAgent) -> io::Result<Vec<Value>> {
    let mut output = Vec::new();
    let paths = match agent {
        CapabilityAgent::Codex => crate::capability_proof::reviewed_codex_system_paths()?,
        CapabilityAgent::ClaudeCode => crate::capability_proof::reviewed_claude_system_paths()?,
    };
    for (path, state) in paths {
        let sha256 = match state.as_str() {
            "absent" => match path.symlink_metadata() {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Value::Null,
                _ => return Err(io::Error::other("reviewed managed path is present")),
            },
            "file" => Value::from(host_io::digest(&path)?),
            _ => return Err(io::Error::other("invalid reviewed system path state")),
        };
        output.push(serde_json::json!({"path":path,"state":state,"sha256":sha256}));
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn prepare_agent_proof(
    root: &Path,
    agent: CapabilityAgent,
    source: &Path,
    source_sha256: &str,
    cli_version: &str,
    model: &str,
    request_policy: &Path,
    catalog: &[Value],
) -> io::Result<PreparedProof> {
    let proof_root = root.join("acceptance-proof");
    host_io::directory(&proof_root)?;
    host_io::directory(&proof_root.join("evidence"))?;
    let runner = std::env::current_exe()?.canonicalize()?;
    let runner_sha256 = host_io::digest(&runner)?;
    let policy_sha256 = host_io::digest(request_policy)?;
    let policy: Value = crate::capability_proof::parse_unique_value(&fs::read(request_policy)?)?;
    let acceptance_request_count = policy["acceptance_requests"]
        .as_u64()
        .ok_or_else(|| io::Error::other("acceptance request count missing"))?;
    let production_request_budget = policy["maximum_requests"]
        .as_u64()
        .ok_or_else(|| io::Error::other("production request budget missing"))?;
    let system_configuration = reviewed_system_configuration(agent)?;
    let (agent_name, provider_protocol, upstream_base_url, argument_template, environment) =
        match agent {
            CapabilityAgent::Codex => (
                "codex",
                "openai-responses",
                "https://api.openai.com/v1/",
                codex_argument_template(),
                codex_environment_rules(),
            ),
            CapabilityAgent::ClaudeCode => (
                "claude-code",
                "anthropic-messages",
                "https://api.anthropic.com/",
                claude_argument_template(20),
                claude_environment_rules(),
            ),
        };
    let profile = serde_json::json!({
        "schema_version":1,"agent":agent_name,"model":model,
        "cli_version":cli_version,"provider_protocol":provider_protocol,
        "upstream_base_url":upstream_base_url,
        "proof_upstream_kind":"local_deterministic_stub_through_relay",
        "allowed_runtime_variance":["relay_authentication_value"],
        "request_policy_sha256":policy_sha256,
        "acceptance_request_count":acceptance_request_count,
        "production_request_budget":production_request_budget,
        "argument_template":argument_template,
        "environment":environment,
        "home_policy":"empty_owner_private","cwd_policy":"empty_owner_private",
        "prompt_policy":"tempest_generated_only","real_authentication_owner":"model_api_relay_only",
        "system_configuration":system_configuration,
        "code_closure":[
            {"role":"agent_executable","path":source,"sha256":source_sha256},
            {"role":"mcp_bridge","path":runner,"sha256":runner_sha256},
            {"role":"model_api_relay","path":runner,"sha256":runner_sha256}]
    });
    let profile_bytes = serde_json::to_vec_pretty(&profile)?;
    host_io::write_new(&proof_root.join("launcher-profile.json"), &profile_bytes)?;
    Ok(PreparedProof {
        agent,
        proof_root,
        profile_sha256: sha256_bytes(&profile_bytes),
        runner_sha256,
        policy_sha256,
        catalog_sha256: sha256_bytes(&serde_json::to_vec(catalog)?),
        acceptance_request_count,
        production_request_budget,
    })
}

fn write_and_authorize_agent_proof(
    input: ProofInputs<'_>,
    challenge: ProbeChallenge,
    launch_relay_endpoint: &str,
    launch_harness_root: &Path,
) -> io::Result<CliAdapter> {
    let proof_root = &input.prepared.proof_root;
    let profile_sha256 = &input.prepared.profile_sha256;
    let runner_sha256 = &input.prepared.runner_sha256;
    let policy_sha256 = &input.prepared.policy_sha256;
    let catalog_sha256 = &input.prepared.catalog_sha256;
    let facts = [
        (
            "allowed_mcp_succeeded",
            serde_json::json!({"attempts":1,"successes":1,"audit_bound":true}),
        ),
        (
            "control_socket_unavailable",
            serde_json::json!({"attempts":1,"rejections":1,
            "bypass_events":0,"positive_control_attempts":1,"positive_control_connections":1}),
        ),
        (
            "hmac_unavailable",
            serde_json::json!({"attempts":1,"rejections":1,"bypass_events":0}),
        ),
        (
            "host_canary_read_denied",
            serde_json::json!({"attempts":2,"rejections":2,
            "before_sha256":input.canary_sha256,"after_sha256":input.canary_sha256}),
        ),
        (
            "host_canary_write_denied",
            serde_json::json!({"attempts":1,"rejections":1,"created":false}),
        ),
        (
            "host_tools_rejected",
            serde_json::json!({"attempts":5,"rejections":5,"bypass_events":0}),
        ),
        (
            "mcp_child_env_sanitized",
            serde_json::json!({"samples":1,"violations":0}),
        ),
        (
            "provider_request_policy",
            serde_json::json!({"requests":input.request_count,"rejected":0,
            "policy_sha256":policy_sha256,"negative_probes":input.negative_count,
            "negative_rejections":input.negative_count,"upstream_bypass_events":0,
            "acceptance_request_count":input.prepared.acceptance_request_count,
            "production_request_budget":input.prepared.production_request_budget}),
        ),
        (
            "tool_catalog_exact",
            match input.prepared.agent {
                CapabilityAgent::Codex => serde_json::json!({"requests":input.request_count,
                    "expected_sha256":catalog_sha256,"observed_sha256":catalog_sha256,
                    "framework_exception_verified":true,
                    "mcp_policy_rejections":input.framework_mcp_policy_rejections,
                    "request_user_input_response_ns":input.framework_response_ns}),
                CapabilityAgent::ClaudeCode => serde_json::json!({"requests":input.request_count,
                    "expected_sha256":catalog_sha256,"observed_sha256":catalog_sha256}),
            },
        ),
    ];
    let probe_id = challenge.probe_id().to_owned();
    let probe_nonce_sha256 = challenge.nonce_sha256();
    let mut checks = serde_json::Map::new();
    let mut manifest = Vec::new();
    for (check, check_facts) in facts {
        let (started_ns, finished_ns) = if check == "control_socket_unavailable" {
            (input.control_started_ns, input.control_finished_ns)
        } else {
            (input.started_ns, input.finished_ns)
        };
        let name = format!("{check}.json");
        let bytes = serde_json::to_vec(&serde_json::json!({"schema_version":1,"check":check,
            "profile_sha256":profile_sha256,"runner_sha256":runner_sha256,
            "probe_id":probe_id,"probe_nonce_sha256":probe_nonce_sha256,
            "started_ns":started_ns,"finished_ns":finished_ns,"facts":check_facts}))?;
        host_io::write_new(&proof_root.join("evidence").join(&name), &bytes)?;
        checks.insert(
            check.to_owned(),
            serde_json::json!({"performed":true,"passed":true,
            "profile_sha256":profile_sha256,"evidence":[name]}),
        );
        manifest.push(
            serde_json::json!({"name":name,"sha256":sha256_bytes(&bytes),"bytes":bytes.len()}),
        );
    }
    host_io::json_new(
        &proof_root.join("capability-proof.json"),
        &serde_json::json!({
        "schema_version":1,"proof_id":format!("proof-{}",host_io::random_hex()?),
        "created_ns":host_io::now_ns()?,"profile_sha256":profile_sha256,
        "runner_sha256":runner_sha256,"probe_id":probe_id,
        "probe_nonce_sha256":probe_nonce_sha256,"checks":checks,"evidence":manifest}),
    )?;
    let code_root = input.root.join("authorized-code");
    let permit = authorize_staged_launch(proof_root, &code_root, challenge)?;
    host_io::directory(launch_harness_root)?;
    for directory in ["jail/home", "jail/cwd"] {
        host_io::directory(&code_root.join(directory))?;
    }
    let sandbox_profile = code_root.join("jail/agent.sb");
    private_file(&sandbox_profile, include_bytes!("darwin-agent.sb"))?;
    let adapter = CliAdapter::new(
        permit,
        CliAdapterConfig {
            relay_endpoint: launch_relay_endpoint.to_owned(),
            maximum_turns: 20,
            sandbox_profile,
            sandbox_jail: code_root.join("jail"),
            harness_root: launch_harness_root.to_owned(),
        },
    )?;
    if adapter.model_api_relay_path() != code_root.join("host/model-api-relay") {
        return Err(io::Error::other("authorized relay path mismatch"));
    }
    Ok(adapter)
}

async fn prove_control_socket_denied(
    socket: &Path,
    sandbox_profile: &Path,
    jail: &Path,
    relay_port: u16,
    allowed_mcp_socket: &Path,
) -> io::Result<UnixListener> {
    let connect = |target: &Path| {
        let mut command = host_io::command(Path::new("/usr/bin/sandbox-exec"));
        command
            .args([
                "-D".as_ref(),
                format!("RELAY=localhost:{relay_port}").as_ref(),
                "-D".as_ref(),
                format!("JAIL={}", jail.display()).as_ref(),
                "-D".as_ref(),
                format!("MCP_SOCKET={}", allowed_mcp_socket.display()).as_ref(),
                "-f".as_ref(),
                sandbox_profile.as_os_str(),
                "--".as_ref(),
                "/usr/bin/nc".as_ref(),
                "-z".as_ref(),
                "-U".as_ref(),
                target.as_os_str(),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        command
    };
    let positive = UnixListener::bind(allowed_mcp_socket)?;
    let positive_output = tokio::time::timeout(
        Duration::from_secs(10),
        connect(allowed_mcp_socket).output(),
    )
    .await
    .map_err(|_| io::Error::other("allowed socket positive control deadline"))??;
    let positive_reached = tokio::time::timeout(Duration::from_secs(1), positive.accept())
        .await
        .is_ok();
    drop(positive);
    fs::remove_file(allowed_mcp_socket)?;
    validate_socket_probe(
        positive_output.status.success(),
        positive_reached,
        false,
        false,
    )?;
    let listener = UnixListener::bind(socket)?;
    let denied_output = tokio::time::timeout(Duration::from_secs(10), connect(socket).output())
        .await
        .map_err(|_| io::Error::other("control socket denial probe deadline"))??;
    let denied_reached = tokio::time::timeout(Duration::from_millis(250), listener.accept())
        .await
        .is_ok();
    validate_socket_probe(true, true, denied_output.status.success(), denied_reached)?;
    Ok(listener)
}

fn validate_socket_probe(
    positive_success: bool,
    positive_reached: bool,
    denied_success: bool,
    denied_reached: bool,
) -> io::Result<()> {
    if !positive_reached {
        return Err(io::Error::other(format!(
            "allowed socket positive control did not establish the probe path: process_success={positive_success}, listener_reached={positive_reached}"
        )));
    }
    if denied_success || denied_reached {
        return Err(io::Error::other(
            "control socket was reachable from the production Seatbelt contract",
        ));
    }
    Ok(())
}

/// Run the actual pinned CLI in the production Seatbelt contract against the
/// native deterministic provider and fixed MCP peer. This pass discovers the
/// CLI's exact provider tool representation; it never issues a LaunchPermit.
async fn discover_inner(
    config: CapabilityDiscoveryConfig,
    production: Option<&ProductionLaunchConfig>,
) -> io::Result<(
    CapabilityDiscovery,
    Option<(CliAdapter, model_api_relay::ProductionRelay)>,
)> {
    if config.output.exists() || !config.executable.is_absolute() {
        return Err(io::Error::other("invalid capability discovery paths"));
    }
    let source = config.executable.canonicalize()?;
    if !source.symlink_metadata()?.is_file() || source == Path::new("/usr/bin/env") {
        return Err(io::Error::other(
            "capability probe requires a native CLI file",
        ));
    }
    // Hash the large native CLI before the launch challenge starts. Rehashing
    // after permit issuance can consume most of its 60-second lifetime.
    let source_sha256 = host_io::digest(&source)?;
    host_io::directory(&config.output)?;
    let root = config.output.canonicalize()?;
    let socket_directory = capability_socket_directory(&root)?;
    for directory in [
        "jail",
        "jail/bin",
        "jail/home",
        "jail/cwd",
        "harness",
        "socket",
    ] {
        host_io::directory(&root.join(directory))?;
    }
    let executable = root.join("jail/bin/agent");
    let bridge = root.join("jail/bin/tempest");
    host_io::private_copy(&source, &executable)?;
    host_io::private_copy(&std::env::current_exe()?, &bridge)?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o500))?;
    fs::set_permissions(&bridge, fs::Permissions::from_mode(0o500))?;
    let sandbox_profile = root.join("jail/agent.sb");
    private_file(&sandbox_profile, include_bytes!("darwin-agent.sb"))?;
    let host_canary = root.join("host-canary");
    let hmac_file = root.join("host-hmac");
    let control_socket = socket_directory.path.join("control-discovery");
    let write_canary = root.join("host-write-canary");
    let canary_value = host_io::random_hex()?;
    private_file(&host_canary, canary_value.as_bytes())?;
    private_file(&hmac_file, host_io::random_hex()?.as_bytes())?;
    let capability = format!("probe-{}", host_io::random_hex()?);
    let provider_agent = match config.agent {
        CapabilityAgent::Codex => ProbeAgent::Codex,
        CapabilityAgent::ClaudeCode => ProbeAgent::ClaudeCode,
    };
    let provider = ProbeProvider::start(
        ProbeIdentity {
            agent: provider_agent,
            model: &config.model,
            capability: &capability,
        },
        &host_canary,
        &write_canary,
        &control_socket,
        &hmac_file,
    )
    .await?;
    let socket = socket_directory.path.join("mcp-discovery");
    let control_listener = prove_control_socket_denied(
        &control_socket,
        &sandbox_profile,
        &root.join("jail"),
        provider
            .endpoint()
            .parse::<reqwest::Url>()
            .ok()
            .and_then(|url| url.port())
            .ok_or_else(|| io::Error::other("probe provider port missing"))?,
        &socket,
    )
    .await?;
    let supervisor = Supervisor::start(SupervisorConfig {
        executable: bridge.clone(),
        args: vec![
            OsString::from("capability-probe-mcp"),
            OsString::from("--probe-id"),
            OsString::from(&capability),
        ],
        cwd: root.join("harness"),
        socket: socket.clone(),
        log: root.join("harness/mcp.jsonl"),
        stderr: root.join("harness/mcp.stderr"),
        secret_file: None,
        owner_file: Some(root.join("harness/mcp-owner.json")),
        relay: RelayConfig {
            max_calls: 4,
            timeout: Duration::from_secs(60),
            ..RelayConfig::default()
        },
    })?;
    let cli_version = version(&executable).await?;
    let endpoint = McpCommand {
        executable: bridge.clone(),
        socket,
        owner_file: root.join("harness/agent-owner.json"),
        raw_stdout: root.join("harness/agent.events.jsonl"),
        raw_stderr: root.join("harness/agent.stderr"),
    };
    let kind = match config.agent {
        CapabilityAgent::Codex => CliKind::Codex,
        CapabilityAgent::ClaudeCode => CliKind::ClaudeCode,
    };
    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        run_capability_probe_cli(
            CapabilityProbeCliConfig {
                kind,
                executable: executable.clone(),
                mcp_bridge: bridge.clone(),
                relay_executable: std::env::current_exe()?.canonicalize()?,
                version: cli_version.clone(),
                model: config.model.clone(),
                relay_endpoint: provider.endpoint().into(),
                maximum_turns: 20,
                sandbox_profile: sandbox_profile.clone(),
                sandbox_jail: root.join("jail"),
                harness_root: root.join("harness"),
            },
            "Execute every requested tool exactly once, then report completion.",
            &endpoint,
            &root.join("jail/cwd"),
        ),
    )
    .await;
    let reason = if matches!(outcome, Ok(Ok(_))) {
        CloseReason::AgentFinished
    } else {
        CloseReason::Cancelled
    };
    let drained = supervisor.finish(reason).await?;
    let outcome = outcome.map_err(|_| io::Error::other("capability discovery CLI deadline"))??;
    let control_reached_after =
        tokio::time::timeout(Duration::from_millis(1), control_listener.accept())
            .await
            .is_ok();
    if !drained.verified_rpc_drain()
        || drained.relay.policy_rejections != expected_mcp_policy_rejections(config.agent)
        || outcome.status != "finished"
        || fs::read(&host_canary)? != canary_value.as_bytes()
        || write_canary.exists()
        || control_reached_after
    {
        return Err(io::Error::other("capability discovery boundary failed"));
    }
    host_io::json_new(
        &root.join("harness/control-socket-negative.json"),
        &serde_json::json!({"attempted":true,"accepted_connections":0,
            "positive_control_attempted":true,"positive_control_accepted_connections":1,
            "profile_sha256":host_io::digest(&sandbox_profile)?}),
    )?;
    let requests = provider.requests()?;
    if requests.len() < 8 {
        return Err(io::Error::other(
            "capability discovery request sequence incomplete",
        ));
    }
    let catalogs: Vec<Vec<Value>> = requests
        .iter()
        .map(|request| request.tools.clone())
        .collect();
    let tool_outputs: Vec<Vec<Value>> = requests
        .iter()
        .map(|request| request.tool_outputs.clone())
        .collect();
    let request_contract_values = requests
        .iter()
        .map(|request| {
            [
                "client_metadata",
                "include",
                "parallel_tool_calls",
                "prompt_cache_key",
                "reasoning",
                "store",
                "stream",
                "tool_choice",
            ]
            .into_iter()
            .filter_map(|name| {
                request
                    .body
                    .get(name)
                    .cloned()
                    .map(|value| (name.to_owned(), value))
            })
            .collect::<BTreeMap<_, _>>()
        })
        .collect::<Vec<_>>();
    host_io::json_new(
        &root.join("harness/provider-observations.json"),
        &serde_json::json!({"catalogs":catalogs,"tool_outputs":tool_outputs,
            "request_contract_values":request_contract_values,
            "request_observed_ns":requests.iter().map(|request| request.observed_ns).collect::<Vec<_>>(),
            "request_paths":requests.iter().map(|request| &request.path).collect::<Vec<_>>(),
            "request_headers":requests.iter().map(|request| &request.headers).collect::<Vec<_>>() }),
    )?;
    validate_catalog(config.agent, &catalogs)?;
    validate_tool_outputs(config.agent, &tool_outputs, &capability, &canary_value)?;
    let discovery_framework_response_ns = match config.agent {
        CapabilityAgent::Codex => Some(codex_framework_response_ns(&requests)?),
        CapabilityAgent::ClaudeCode => None,
    };
    let strict_tempest_only = strict_tempest_catalog(config.agent, &catalogs[0]);
    let codex_framework_exception_verified =
        config.agent == CapabilityAgent::Codex && codex_framework_exception_catalog(&catalogs[0]);
    let launch_catalog_accepted = strict_tempest_only || codex_framework_exception_verified;
    let mut authorized_adapter = None;
    let acceptance_relay_verified = if launch_catalog_accepted {
        let acceptance_jail = root.join("acceptance/jail");
        for directory in [
            "acceptance",
            "acceptance/jail",
            "acceptance/jail/bin",
            "acceptance/jail/home",
            "acceptance/jail/cwd",
        ] {
            host_io::directory(&root.join(directory))?;
        }
        let acceptance_executable = acceptance_jail.join("bin/agent");
        let acceptance_bridge = acceptance_jail.join("bin/tempest");
        let acceptance_profile = acceptance_jail.join("agent.sb");
        host_io::private_copy(&source, &acceptance_executable)?;
        host_io::private_copy(&std::env::current_exe()?, &acceptance_bridge)?;
        fs::set_permissions(&acceptance_executable, fs::Permissions::from_mode(0o500))?;
        fs::set_permissions(&acceptance_bridge, fs::Permissions::from_mode(0o500))?;
        private_file(&acceptance_profile, include_bytes!("darwin-agent.sb"))?;
        let provider_url = provider
            .endpoint()
            .parse::<reqwest::Url>()
            .map_err(io::Error::other)?;
        let observed_policy = frozen_request_policy(&requests, provider_url.path())?;
        host_io::json_new(
            &root.join("harness/observed-request-policy.json"),
            &observed_policy,
        )?;
        let policy = approved_request_policy(config.agent, &cli_version, &config.model)?;
        if observed_policy != approved_observation(&policy)? {
            host_io::json_new(
                &root.join("harness/unapproved-request-policy.json"),
                &observed_policy,
            )?;
            return Err(io::Error::other(
                "native CLI request policy is not repository-approved",
            ));
        }
        let policy_path = root.join("harness/request-policy.json");
        host_io::json_new(&policy_path, &policy)?;
        let staged_code = stage_authorized_code(&root, &source)?;
        if staged_code != root.join("authorized-code") {
            return Err(io::Error::other("staged code path mismatch"));
        }
        let prepared_proof = prepare_agent_proof(
            &root,
            config.agent,
            &source,
            &source_sha256,
            &cli_version,
            &config.model,
            &policy_path,
            &catalogs[0],
        )?;
        let challenge = ProbeChallenge::generate()?;
        let acceptance_capability = challenge.probe_id().to_owned();
        let acceptance_control_socket = socket_directory.path.join("control-acceptance");
        let acceptance_provider = ProbeProvider::start_with_sse_delay(
            ProbeIdentity {
                agent: provider_agent,
                model: &config.model,
                capability: &acceptance_capability,
            },
            &host_canary,
            &write_canary,
            &acceptance_control_socket,
            &hmac_file,
            Some(Duration::from_secs(2)),
        )
        .await?;
        let upstream = format!("{}/", acceptance_provider.endpoint())
            .parse::<reqwest::Url>()
            .map_err(io::Error::other)?;
        let relay = model_api_relay::start_probe_relay(
            upstream,
            host_io::random_hex()?,
            acceptance_policy(&policy)?,
            &root.join("harness/model-relay-audit.jsonl"),
        )
        .await?;
        let acceptance_socket = socket_directory.path.join("mcp-acceptance");
        let control_started_ns = host_io::now_ns()?;
        let acceptance_control_listener = prove_control_socket_denied(
            &acceptance_control_socket,
            &acceptance_profile,
            &acceptance_jail,
            relay
                .endpoint()
                .parse::<reqwest::Url>()
                .ok()
                .and_then(|url| url.port())
                .ok_or_else(|| io::Error::other("acceptance relay port missing"))?,
            &acceptance_socket,
        )
        .await?;
        let control_finished_ns = host_io::now_ns()?;
        let acceptance_started_ns = host_io::now_ns()?;
        let baseline_path = requests[0]
            .path
            .strip_prefix(provider_url.path())
            .ok_or_else(|| io::Error::other("baseline request path escaped capability"))?
            .to_owned();
        let mut relay_rejections =
            prove_relay_rejections(relay.endpoint(), &baseline_path, &requests[0].body).await?;
        if !acceptance_provider.requests()?.is_empty() {
            return Err(io::Error::other(
                "relay negative probe reached the trusted upstream",
            ));
        }
        let acceptance_supervisor = Supervisor::start(SupervisorConfig {
            executable: acceptance_bridge.clone(),
            args: vec![
                OsString::from("capability-probe-mcp"),
                OsString::from("--probe-id"),
                OsString::from(&acceptance_capability),
            ],
            cwd: root.join("harness"),
            socket: acceptance_socket.clone(),
            log: root.join("harness/acceptance-mcp.jsonl"),
            stderr: root.join("harness/acceptance-mcp.stderr"),
            secret_file: None,
            owner_file: Some(root.join("harness/acceptance-mcp-owner.json")),
            relay: RelayConfig {
                max_calls: 4,
                timeout: Duration::from_secs(60),
                ..RelayConfig::default()
            },
        })?;
        let acceptance_endpoint = McpCommand {
            executable: acceptance_bridge.clone(),
            socket: acceptance_socket,
            owner_file: root.join("harness/acceptance-agent-owner.json"),
            raw_stdout: root.join("harness/acceptance-agent.events.jsonl"),
            raw_stderr: root.join("harness/acceptance-agent.stderr"),
        };
        let acceptance = tokio::time::timeout(
            Duration::from_secs(60),
            run_capability_probe_cli(
                CapabilityProbeCliConfig {
                    kind,
                    executable: acceptance_executable,
                    mcp_bridge: acceptance_bridge,
                    relay_executable: std::env::current_exe()?.canonicalize()?,
                    version: cli_version.clone(),
                    model: config.model.clone(),
                    relay_endpoint: relay.endpoint().into(),
                    maximum_turns: 20,
                    sandbox_profile: acceptance_profile,
                    sandbox_jail: acceptance_jail.clone(),
                    harness_root: root.join("harness"),
                },
                "Execute every requested tool exactly once, then report completion.",
                &acceptance_endpoint,
                &acceptance_jail.join("cwd"),
            ),
        )
        .await;
        let reason = if matches!(acceptance, Ok(Ok(_))) {
            CloseReason::AgentFinished
        } else {
            CloseReason::Cancelled
        };
        let drained = acceptance_supervisor.finish(reason).await?;
        let acceptance =
            acceptance.map_err(|_| io::Error::other("capability acceptance CLI deadline"))??;
        let acceptance_requests = acceptance_provider.requests()?;
        let acceptance_catalogs = acceptance_requests
            .iter()
            .map(|request| request.tools.clone())
            .collect::<Vec<_>>();
        let acceptance_outputs = acceptance_requests
            .iter()
            .map(|request| request.tool_outputs.clone())
            .collect::<Vec<_>>();
        validate_catalog(config.agent, &acceptance_catalogs)?;
        validate_tool_outputs(
            config.agent,
            &acceptance_outputs,
            &acceptance_capability,
            &canary_value,
        )?;
        let framework_response_ns = match config.agent {
            CapabilityAgent::Codex => Some(
                codex_framework_response_ns(&acceptance_requests)?.max(
                    discovery_framework_response_ns
                        .ok_or_else(|| io::Error::other("Codex discovery timing missing"))?,
                ),
            ),
            CapabilityAgent::ClaudeCode => None,
        };
        relay_rejections.push(
            submit_relay_rejection(
                relay.endpoint(),
                &baseline_path,
                &requests[0].body,
                "model request budget exhausted",
            )
            .await?,
        );
        let relay_audit = root.join("harness/model-relay-audit.jsonl");
        validate_relay_rejections(&relay_audit, &relay_rejections)?;
        let expected_hello_path = format!(
            "{}/api/hello",
            reqwest::Url::parse(relay.endpoint())
                .map_err(io::Error::other)?
                .path()
                .trim_end_matches('/')
        );
        validate_relay_audit(
            &relay_audit,
            requests.len(),
            relay_rejections.len(),
            &expected_hello_path,
        )?;
        if !drained.verified_rpc_drain()
            || drained.relay.policy_rejections != expected_mcp_policy_rejections(config.agent)
            || acceptance.status != "finished"
            || acceptance_requests.len() != requests.len()
            || acceptance_provider.requests()?.len() != requests.len()
            || acceptance_catalogs != catalogs
            || fs::read(&host_canary)? != canary_value.as_bytes()
            || write_canary.exists()
        {
            return Err(io::Error::other("capability acceptance boundary failed"));
        }
        let acceptance_finished_ns = host_io::now_ns()?;
        if tokio::time::timeout(
            Duration::from_millis(1),
            acceptance_control_listener.accept(),
        )
        .await
        .is_ok()
        {
            return Err(io::Error::other(
                "acceptance control socket was reached after its negative probe",
            ));
        }
        let production_relay = match production {
            Some(production) => {
                let state_root = root.join("production-relay");
                host_io::directory(&state_root)?;
                Some(
                    model_api_relay::start_production_relay(
                        model_api_relay::ProductionRelayConfig {
                            executable: &staged_code.join("host/model-api-relay"),
                            upstream: &production.upstream,
                            policy_file: &policy_path,
                            auth: model_api_relay::ProductionRelayAuth::Fixed {
                                file: &production.auth_file,
                                header: production_auth_header(config.agent),
                            },
                            audit_file: &production.audit_file,
                            state_root: &state_root,
                            owner_file: &production.owner_file,
                            timeout_seconds: 120,
                        },
                    )
                    .await?,
                )
            }
            None => None,
        };
        let launch_relay_endpoint = production_relay
            .as_ref()
            .map(model_api_relay::ProductionRelay::endpoint)
            .unwrap_or("http://127.0.0.1:1234/capabilitycapabilitycapability12");
        let launch_harness_root = production.map_or_else(
            || staged_code.join("harness"),
            |production| production.launch_harness_root.clone(),
        );
        let adapter = write_and_authorize_agent_proof(
            ProofInputs {
                root: &root,
                prepared: &prepared_proof,
                request_count: requests.len(),
                negative_count: relay_rejections.len(),
                canary_sha256: &host_io::digest(&host_canary)?,
                started_ns: acceptance_started_ns,
                finished_ns: acceptance_finished_ns,
                control_started_ns,
                control_finished_ns,
                framework_response_ns,
                framework_mcp_policy_rejections: (config.agent == CapabilityAgent::Codex)
                    .then_some(drained.relay.policy_rejections),
            },
            challenge,
            launch_relay_endpoint,
            &launch_harness_root,
        )?;
        if let Some(relay) = production_relay {
            authorized_adapter = Some((adapter, relay));
        }
        true
    } else {
        false
    };
    let request_fields = requests
        .iter()
        .map(|request| {
            request
                .body
                .as_object()
                .map(|body| body.keys().cloned().collect())
                .ok_or_else(|| io::Error::other("provider request is not an object"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok((
        CapabilityDiscovery {
            agent: config.agent,
            cli_version,
            model: config.model,
            executable_sha256: source_sha256,
            catalogs,
            tool_outputs,
            request_fields,
            strict_tempest_only,
            codex_framework_exception_verified,
            acceptance_relay_verified,
            launch_permit_verified: acceptance_relay_verified,
        },
        authorized_adapter,
    ))
}

pub async fn discover(config: CapabilityDiscoveryConfig) -> io::Result<CapabilityDiscovery> {
    discover_inner(config, None)
        .await
        .map(|(discovery, _)| discovery)
}

pub(crate) async fn discover_for_launch(
    config: CapabilityDiscoveryConfig,
    production: ProductionLaunchConfig,
) -> io::Result<AuthorizedNativeLaunch> {
    let (discovery, launch) = discover_inner(config, Some(&production)).await?;
    let (adapter, relay) = launch.ok_or_else(|| {
        io::Error::other("native CLI did not establish a strict launch capability")
    })?;
    Ok(AuthorizedNativeLaunch {
        discovery,
        adapter,
        relay,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn capability_sockets_stay_below_the_darwin_unix_path_limit() {
        let root = std::env::temp_dir().join(format!(
            "tempest-capability-long-output-{}/nested/discovery",
            "x".repeat(120)
        ));
        let directory = capability_socket_directory(&root).unwrap();
        if cfg!(target_os = "macos") {
            assert!(directory.path.join("control-acceptance").as_os_str().len() < 104);
            assert!(!directory.path.starts_with(&root));
        } else {
            assert_eq!(directory.path, root.join("socket"));
        }
    }

    fn codex_outputs() -> Vec<Vec<Value>> {
        let mut outputs = (0..5)
            .zip([
                "exec_command",
                "apply_patch",
                "view_image",
                "exec_command",
                "exec_command",
            ])
            .map(|(index, name)| {
                json!({"type":"function_call_output","call_id":format!("call_{index}"),
                    "output":format!("unsupported call: {name}")})
            })
            .collect::<Vec<_>>();
        for (index, output) in [
            "{\"resources\":[]}",
            "resources/list failed: resources/list failed for `tempest`: Mcp error: -32601: MCP method not allowed",
            "{\"resourceTemplates\":[]}",
            "resources/templates/list failed: resources/templates/list failed for `tempest`: Mcp error: -32601: MCP method not allowed",
            "resources/read failed: resources/read failed for `tempest` (file:///host/canary): Mcp error: -32601: MCP method not allowed",
            "unknown MCP server 'other'",
            "request_user_input is unavailable in Default mode",
        ]
        .into_iter()
        .enumerate()
        {
            let call = index + 5;
            outputs.push(json!({"type":"function_call_output","call_id":format!("call_{call}"),
                "output":output}));
        }
        outputs.push(json!({"type":"function_call_output","call_id":"call_12",
            "output":[{"type":"input_text","text":"status"},
                {"type":"input_text","text":"{\"probe_id\":\"probe-test\",\"running\":true}"}]}));
        vec![outputs]
    }

    #[test]
    fn typed_tool_results_accept_the_exact_rejection_and_status() {
        validate_tool_outputs(
            CapabilityAgent::Codex,
            &codex_outputs(),
            "probe-test",
            "secret-canary",
        )
        .unwrap();
    }

    #[test]
    fn codex_framework_catalog_is_version_pinned_and_fail_closed() {
        let policy =
            approved_request_policy(CapabilityAgent::Codex, "codex-cli 0.169.0", "gpt-6.1")
                .unwrap();
        let mut catalog = policy["tools"].as_array().unwrap().clone();
        assert!(codex_framework_exception_catalog(&catalog));
        catalog[0]["description"] = "changed".into();
        assert!(!codex_framework_exception_catalog(&catalog));
    }

    #[test]
    fn success_content_containing_error_does_not_prove_bypass_rejection() {
        let mut outputs = codex_outputs();
        outputs[0][9] = json!({"type":"function_call_output","call_id":"call_9",
            "output":"success: no error occurred"});
        assert!(
            validate_tool_outputs(
                CapabilityAgent::Codex,
                &outputs,
                "probe-test",
                "secret-canary",
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_tool_result_call_id_is_rejected() {
        let mut outputs = codex_outputs();
        outputs[0][9]["call_id"] = "call_4".into();
        assert!(
            validate_tool_outputs(
                CapabilityAgent::Codex,
                &outputs,
                "probe-test",
                "secret-canary",
            )
            .is_err()
        );
    }

    #[test]
    fn socket_denial_requires_a_working_positive_control() {
        assert!(validate_socket_probe(true, true, false, false).is_ok());
        assert!(validate_socket_probe(false, true, false, false).is_ok());
        for fixture in [
            (false, false, false, false),
            (true, false, false, false),
            (true, true, true, false),
            (true, true, false, true),
        ] {
            assert!(validate_socket_probe(fixture.0, fixture.1, fixture.2, fixture.3).is_err());
        }
    }

    #[test]
    fn only_the_reviewed_cli_policy_can_be_selected() {
        assert_eq!(
            production_auth_header(CapabilityAgent::Codex),
            "authorization"
        );
        assert_eq!(
            production_auth_header(CapabilityAgent::ClaudeCode),
            "x-api-key"
        );
        let policy = approved_request_policy(
            CapabilityAgent::ClaudeCode,
            "2.1.323 (Claude Code)",
            "claude-sonnet-5-5",
        )
        .unwrap();
        assert_eq!(policy["paths"], json!(["/v1/messages?beta=true"]));
        assert_eq!(policy["models"], json!(["claude-sonnet-5-5"]));
        assert_eq!(policy["acceptance_requests"], 8);
        assert_eq!(policy["maximum_requests"], 19);
        assert_eq!(acceptance_policy(&policy).unwrap()["maximum_requests"], 8);
        assert_eq!(
            policy["request_headers"],
            json!({"content-type":"application/json"})
        );
        let codex = approved_request_policy(CapabilityAgent::Codex, "codex-cli 0.169.0", "gpt-6.1")
            .unwrap();
        assert_eq!(codex["paths"], json!(["/responses"]));
        assert_eq!(codex["acceptance_requests"], 14);
        assert_eq!(codex["maximum_requests"], 19);
        for (agent, version, model) in [
            (
                CapabilityAgent::ClaudeCode,
                "2.1.323 (Claude Code)",
                "tempest-capability-probe",
            ),
            (
                CapabilityAgent::ClaudeCode,
                "2.1.323 (Claude Code)",
                "sonnet",
            ),
            (
                CapabilityAgent::ClaudeCode,
                "2.1.324 (Claude Code)",
                "claude-sonnet-5-5",
            ),
            (CapabilityAgent::Codex, "codex-cli 0.169.1", "gpt-6.1"),
        ] {
            assert!(approved_request_policy(agent, version, model).is_err());
        }
    }
}
