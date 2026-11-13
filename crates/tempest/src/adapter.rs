//! Deterministic mock and proof-gated real CLI adapter process contracts.
use crate::{
    capability_proof::{EnvironmentRule, LaunchPermit},
    host_io::command,
    rpc::Rpc,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    future::Future,
    io,
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

const MAX_AGENT_STREAM: u64 = 16 * 1024 * 1024;

pub struct McpCommand {
    pub executable: PathBuf,
    pub socket: PathBuf,
    pub owner_file: PathBuf,
    pub raw_stdout: PathBuf,
    pub raw_stderr: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CliKind {
    Codex,
    ClaudeCode,
}

pub struct CliAdapterConfig {
    pub relay_endpoint: String,
    pub maximum_turns: u64,
    pub sandbox_profile: PathBuf,
    pub sandbox_jail: PathBuf,
    pub harness_root: PathBuf,
}

pub(crate) struct CapabilityProbeCliConfig {
    pub kind: CliKind,
    pub executable: PathBuf,
    pub mcp_bridge: PathBuf,
    pub relay_executable: PathBuf,
    pub version: String,
    pub model: String,
    pub relay_endpoint: String,
    pub maximum_turns: u64,
    pub sandbox_profile: PathBuf,
    pub sandbox_jail: PathBuf,
    pub harness_root: PathBuf,
}

pub struct CliAdapter {
    contract: CliContract,
    permit: LaunchPermit,
    launch_claimed: AtomicBool,
}

#[derive(Clone)]
struct CliContract {
    kind: CliKind,
    executable: PathBuf,
    executable_sha256: String,
    mcp_bridge: PathBuf,
    relay_executable: PathBuf,
    version: String,
    model: String,
    home: PathBuf,
    relay_endpoint: String,
    maximum_turns: u64,
    sandbox_executable: PathBuf,
    sandbox_executable_sha256: String,
    sandbox_profile: PathBuf,
    sandbox_profile_sha256: String,
    sandbox_jail: PathBuf,
    harness_root: PathBuf,
    system_profile_sha256: String,
    dyld_profile_sha256: String,
}

struct CliLaunch {
    arguments: Vec<OsString>,
    environment: BTreeMap<OsString, OsString>,
}

fn sha256(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

pub(crate) fn claude_argument_template(maximum_turns: u64) -> Vec<String> {
    [
        "-p",
        "--model",
        "<MODEL>",
        "--max-turns",
        &maximum_turns.to_string(),
        "--bare",
        "--tools",
        "",
        "--strict-mcp-config",
        "--mcp-config",
        "<FIXED_TEMPEST_MCP>",
        "--setting-sources",
        "",
        "--disable-slash-commands",
        "--permission-mode",
        "dontAsk",
        "--no-session-persistence",
        "--output-format",
        "stream-json",
        "--verbose",
        "--allowedTools",
        "mcp__tempest__sandbox_status",
        "mcp__tempest__sandbox_exec",
        "mcp__tempest__sandbox_shell",
        "<PROMPT_STDIN>",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

pub(crate) fn claude_environment_rules() -> Vec<EnvironmentRule> {
    [
        (
            "ANTHROPIC_API_KEY",
            "fixed_placeholder",
            Some(sha256("tempest-relay-placeholder")),
        ),
        ("ANTHROPIC_BASE_URL", "relay_endpoint", None),
        ("CLAUDE_CODE_TMPDIR", "generated_private_directory", None),
        ("DISABLE_AUTOUPDATER", "fixed_nonsecret", Some(sha256("1"))),
        ("HOME", "generated_private_directory", None),
        ("LANG", "fixed_nonsecret", Some(sha256("C.UTF-8"))),
        ("LC_ALL", "fixed_nonsecret", Some(sha256("C.UTF-8"))),
        ("TMPDIR", "generated_private_directory", None),
    ]
    .into_iter()
    .map(|(name, source, value_sha256)| EnvironmentRule {
        name: name.to_owned(),
        source: source.to_owned(),
        value_sha256,
    })
    .collect()
}

fn claude_environment(
    home: &Path,
    cwd: &Path,
    relay_endpoint: &str,
) -> io::Result<BTreeMap<OsString, OsString>> {
    claude_environment_rules()
        .into_iter()
        .map(|rule| {
            let value = match (rule.name.as_str(), rule.source.as_str()) {
                ("ANTHROPIC_API_KEY", "fixed_placeholder") => {
                    OsString::from("tempest-relay-placeholder")
                }
                ("ANTHROPIC_BASE_URL", "relay_endpoint") => relay_endpoint.into(),
                ("CLAUDE_CODE_TMPDIR" | "TMPDIR", "generated_private_directory") => {
                    cwd.as_os_str().to_owned()
                }
                ("HOME", "generated_private_directory") => home.as_os_str().to_owned(),
                ("DISABLE_AUTOUPDATER", "fixed_nonsecret") => "1".into(),
                ("LANG" | "LC_ALL", "fixed_nonsecret") => "C.UTF-8".into(),
                _ => return Err(io::Error::other("invalid Claude environment contract")),
            };
            Ok((rule.name.into(), value))
        })
        .collect()
}

fn measured_launch_contract_matches(
    profile: &crate::capability_proof::LauncherProfile,
    kind: CliKind,
    maximum_turns: u64,
) -> bool {
    match kind {
        CliKind::ClaudeCode => {
            profile.argument_template == claude_argument_template(maximum_turns)
                && profile.environment == claude_environment_rules()
        }
        CliKind::Codex => false,
    }
}

fn measured_launch_identity_matches(
    profile: &crate::capability_proof::LauncherProfile,
    kind: CliKind,
    version: &str,
    model: &str,
) -> bool {
    let agent = match kind {
        CliKind::Codex => "codex",
        CliKind::ClaudeCode => "claude-code",
    };
    profile.agent == agent && profile.cli_version == version && profile.model == model
}

fn claim_measured_launch(claimed: &AtomicBool) -> io::Result<()> {
    claimed
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .map(|_| ())
        .map_err(|_| io::Error::other("measured CLI launch permit was already consumed"))
}

fn private_directory(path: &Path) -> io::Result<PathBuf> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = path.symlink_metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(io::Error::other("CLI jail directory is not owner-private"));
    }
    path.canonicalize()
}

fn exact_names(path: &Path, expected: &[&str]) -> io::Result<bool> {
    let mut names = fs::read_dir(path)?
        .map(|entry| {
            entry.and_then(|entry| {
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| io::Error::other("non-UTF-8 CLI jail entry"))
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    names.sort();
    Ok(names == expected)
}

fn private_regular(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = path.symlink_metadata()?;
    Ok(metadata.is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.permissions().mode() & 0o077 == 0)
}

#[derive(Debug, Serialize)]
pub struct AgentOutcome {
    pub status: String,
    pub final_output: String,
    pub calls_attempted: u64,
    pub responses: Vec<Value>,
}
pub trait AgentAdapter {
    fn describe(&self) -> Value;
    fn run<'a>(
        &'a self,
        prompt: &'a str,
        endpoint: &'a McpCommand,
        cwd: &'a Path,
    ) -> impl Future<Output = io::Result<AgentOutcome>> + Send + 'a;
}

fn profile_file_sha256(
    profile: &crate::capability_proof::LauncherProfile,
    path: &Path,
) -> io::Result<String> {
    profile
        .system_configuration
        .iter()
        .find(|item| item.path == path && item.state == "file")
        .and_then(|item| item.sha256.clone())
        .ok_or_else(|| io::Error::other("launcher profile does not bind a required system file"))
}

impl CliAdapter {
    pub fn new(permit: LaunchPermit, config: CliAdapterConfig) -> io::Result<Self> {
        permit.verify_immediately_before_launch()?;
        let profile = permit.profile();
        let (kind, protocol) = match profile.agent.as_str() {
            "codex" => (CliKind::Codex, "openai-responses"),
            "claude-code" => (CliKind::ClaudeCode, "anthropic-messages"),
            _ => return Err(io::Error::other("unsupported measured CLI adapter")),
        };
        if profile.provider_protocol != protocol {
            return Err(io::Error::other(
                "CLI provider protocol does not match adapter",
            ));
        }
        let executable = permit.code_path("agent_executable")?.canonicalize()?;
        let mcp_bridge = permit.code_path("mcp_bridge")?.canonicalize()?;
        let relay_executable = permit.code_path("model_api_relay")?.canonicalize()?;
        let artifact_sha = |role: &str| {
            profile
                .code_closure
                .iter()
                .find(|item| item.role == role)
                .map(|item| item.sha256.clone())
                .ok_or_else(|| io::Error::other("measured CLI code role missing"))
        };
        let executable_sha256 = artifact_sha("agent_executable")?;
        let sandbox_executable = PathBuf::from("/usr/bin/sandbox-exec");
        let sandbox_executable_sha256 = profile_file_sha256(profile, &sandbox_executable)?;
        let system_profile_sha256 = profile_file_sha256(
            profile,
            Path::new("/System/Library/Sandbox/Profiles/system.sb"),
        )?;
        let dyld_profile_sha256 = profile_file_sha256(
            profile,
            Path::new("/System/Library/Sandbox/Profiles/dyld-support.sb"),
        )?;
        let sandbox_profile_sha256 = crate::host_io::digest(&config.sandbox_profile)?;
        let version = profile.cli_version.clone();
        let model = profile.model.clone();
        let sandbox_jail = private_directory(&config.sandbox_jail)?;
        let home = sandbox_jail.join("home");
        let contract = CliContract {
            kind,
            executable,
            executable_sha256,
            mcp_bridge,
            relay_executable,
            version,
            model,
            home,
            relay_endpoint: config.relay_endpoint,
            maximum_turns: config.maximum_turns,
            sandbox_executable,
            sandbox_executable_sha256,
            sandbox_profile: config.sandbox_profile,
            sandbox_profile_sha256,
            sandbox_jail,
            harness_root: config.harness_root,
            system_profile_sha256,
            dyld_profile_sha256,
        };
        if !measured_launch_contract_matches(profile, kind, config.maximum_turns) {
            return Err(io::Error::other(
                "measured CLI argv or environment contract does not match launch",
            ));
        }
        if !measured_launch_identity_matches(profile, kind, &contract.version, &contract.model) {
            return Err(io::Error::other(
                "measured CLI identity does not match launch",
            ));
        }
        if contract.executable != contract.sandbox_jail.join("bin/agent")
            || contract.mcp_bridge != contract.sandbox_jail.join("bin/tempest")
            || contract
                .relay_executable
                .starts_with(&contract.sandbox_jail)
        {
            return Err(io::Error::other(
                "authorized launcher code is outside its measured layout",
            ));
        }
        Ok(Self {
            contract,
            permit,
            launch_claimed: AtomicBool::new(false),
        })
    }

    pub fn model_api_relay_path(&self) -> &Path {
        &self.contract.relay_executable
    }

    pub fn mcp_bridge_path(&self) -> &Path {
        &self.contract.mcp_bridge
    }
}

impl CliContract {
    fn launch(&self, _prompt: &str, endpoint: &McpCommand, cwd: &Path) -> io::Result<CliLaunch> {
        let relay = self
            .relay_endpoint
            .parse::<reqwest::Url>()
            .map_err(|_| io::Error::other("invalid model relay endpoint"))?;
        let capability = relay.path().strip_prefix('/').unwrap_or_default();
        let jail = private_directory(&self.sandbox_jail)?;
        let harness = private_directory(&self.harness_root)?;
        let executable = self.executable.canonicalize()?;
        let home = private_directory(&self.home)?;
        let cwd = private_directory(cwd)?;
        let bridge_path = endpoint.executable.canonicalize()?;
        let profile = self.sandbox_profile.canonicalize()?;
        if !self.executable.is_absolute()
            || !self.home.is_absolute()
            || !endpoint.executable.is_absolute()
            || !endpoint.socket.is_absolute()
            || !endpoint.owner_file.is_absolute()
            || !endpoint.raw_stdout.is_absolute()
            || !endpoint.raw_stderr.is_absolute()
            || !cwd.is_absolute()
            || self.model.is_empty()
            || self.maximum_turns == 0
            || !self.relay_endpoint.starts_with("http://127.0.0.1:")
            || relay.scheme() != "http"
            || relay.host_str() != Some("127.0.0.1")
            || relay.port().is_none()
            || !relay.username().is_empty()
            || relay.password().is_some()
            || relay.query().is_some()
            || relay.fragment().is_some()
            || capability.len() < 32
            || capability.contains(['/', '%'])
            || !capability
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || crate::host_io::digest(&self.executable)? != self.executable_sha256
            || bridge_path != self.mcp_bridge
            || self.sandbox_executable != Path::new("/usr/bin/sandbox-exec")
            || crate::host_io::digest(&self.sandbox_executable)? != self.sandbox_executable_sha256
            || crate::host_io::digest(&self.sandbox_profile)? != self.sandbox_profile_sha256
            || fs::read(&self.sandbox_profile)? != include_bytes!("darwin-agent.sb")
            || crate::host_io::digest(Path::new("/System/Library/Sandbox/Profiles/system.sb"))?
                != self.system_profile_sha256
            || crate::host_io::digest(Path::new(
                "/System/Library/Sandbox/Profiles/dyld-support.sb",
            ))? != self.dyld_profile_sha256
            || jail == Path::new("/")
            || jail.starts_with(&harness)
            || harness.starts_with(&jail)
            || executable != jail.join("bin/agent")
            || bridge_path != jail.join("bin/tempest")
            || profile != jail.join("agent.sb")
            || home != jail.join("home")
            || cwd != jail.join("cwd")
            || !private_regular(&executable)?
            || !private_regular(&bridge_path)?
            || !private_regular(&profile)?
            || !exact_names(&jail, &["agent.sb", "bin", "cwd", "home"])?
            || !exact_names(&jail.join("bin"), &["agent", "tempest"])?
            || !exact_names(&home, &[])?
            || !exact_names(&cwd, &[])?
            || !endpoint.owner_file.starts_with(&self.harness_root)
            || !endpoint.raw_stdout.starts_with(&self.harness_root)
            || !endpoint.raw_stderr.starts_with(&self.harness_root)
            || endpoint.socket.starts_with(&jail)
            || endpoint.socket.starts_with(&harness)
        {
            return Err(io::Error::other("invalid measured CLI launch contract"));
        }
        let bridge = endpoint.executable.to_string_lossy().into_owned();
        let socket = endpoint.socket.to_string_lossy().into_owned();
        let environment = match self.kind {
            CliKind::Codex => {
                let mut environment = BTreeMap::from([
                    (OsString::from("HOME"), self.home.clone().into_os_string()),
                    (OsString::from("LANG"), OsString::from("C.UTF-8")),
                    (OsString::from("LC_ALL"), OsString::from("C.UTF-8")),
                    (OsString::from("TMPDIR"), cwd.to_path_buf().into_os_string()),
                ]);
                environment.insert("OPENAI_API_KEY".into(), "tempest-relay-placeholder".into());
                environment
            }
            CliKind::ClaudeCode => claude_environment(&self.home, &cwd, &self.relay_endpoint)?,
        };
        let environment_policy = match self.kind {
            CliKind::Codex => "codex-v1",
            CliKind::ClaudeCode => "claude-code-v1",
        };
        let agent_arguments = match self.kind {
            CliKind::Codex => {
                let mut values = vec![
                    "exec".into(),
                    "--ignore-user-config".into(),
                    "--ignore-rules".into(),
                    "--ephemeral".into(),
                    "--skip-git-repo-check".into(),
                    "--json".into(),
                    "-s".into(),
                    "read-only".into(),
                    "-m".into(),
                    self.model.clone().into(),
                ];
                for feature in [
                    "shell_tool",
                    "apps",
                    "view_image",
                    "multi_agent",
                    "plugins",
                    "remote_plugin",
                    "plugin_sharing",
                    "plugin_discovery_prefetch",
                    "skill_search",
                    "skill_mcp_dependency_install",
                    "hooks",
                    "goals",
                    "image_generation",
                ] {
                    values.extend([OsString::from("--disable"), feature.into()]);
                }
                for setting in [
                    "model_provider=\"tempest\"".to_owned(),
                    "model_providers.tempest.name=\"Tempest relay\"".to_owned(),
                    format!(
                        "model_providers.tempest.base_url={}",
                        serde_json::to_string(&self.relay_endpoint)?
                    ),
                    "model_providers.tempest.wire_api=\"responses\"".to_owned(),
                    "model_providers.tempest.requires_openai_auth=true".to_owned(),
                    "web_search=\"disabled\"".to_owned(),
                    format!("mcp_servers.tempest.command={}", serde_json::to_string(&bridge)?),
                    format!(
                        "mcp_servers.tempest.args={}",
                        serde_json::to_string(&[
                            "mcp-connect",
                            socket.as_str(),
                            "--environment-policy",
                            environment_policy,
                        ])?
                    ),
                    "mcp_servers.tempest.enabled_tools=[\"sandbox_status\",\"sandbox_exec\",\"sandbox_shell\"]".to_owned(),
                    "mcp_servers.tempest.default_tools_approval_mode=\"approve\"".to_owned(),
                ] {
                    values.extend([OsString::from("-c"), setting.into()]);
                }
                values.push("-".into());
                values
            }
            CliKind::ClaudeCode => {
                let mcp = json!({"mcpServers":{"tempest":{"command":bridge,
                    "args":["mcp-connect",socket,"--environment-policy",environment_policy],"env":{}}}});
                let mcp = serde_json::to_string(&mcp)?;
                claude_argument_template(self.maximum_turns)
                    .into_iter()
                    .filter_map(|value| match value.as_str() {
                        "<MODEL>" => Some(self.model.clone().into()),
                        "<FIXED_TEMPEST_MCP>" => Some(mcp.clone().into()),
                        "<PROMPT_STDIN>" => None,
                        _ => Some(value.into()),
                    })
                    .collect()
            }
        };
        let mut arguments = vec![
            "-D".into(),
            format!("RELAY=localhost:{}", relay.port().unwrap()).into(),
            "-D".into(),
            format!("JAIL={}", jail.display()).into(),
            "-D".into(),
            format!("MCP_SOCKET={}", endpoint.socket.display()).into(),
            "-f".into(),
            self.sandbox_profile.clone().into_os_string(),
            "--".into(),
            self.executable.clone().into_os_string(),
        ];
        arguments.extend(agent_arguments);
        Ok(CliLaunch {
            arguments,
            environment,
        })
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockAdapter {
    pub calls: Vec<MockCall>,
    pub final_output: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockCall {
    pub name: String,
    pub arguments: Value,
}
impl AgentAdapter for MockAdapter {
    fn describe(&self) -> Value {
        json!({"adapter":"mock","model":"deterministic_script","tempest_version":env!("CARGO_PKG_VERSION")})
    }
    async fn run<'a>(
        &'a self,
        prompt: &'a str,
        endpoint: &'a McpCommand,
        cwd: &'a Path,
    ) -> io::Result<AgentOutcome> {
        let key = prompt
            .lines()
            .filter_map(|line| line.strip_prefix("AccessKeyId: "))
            .next_back()
            .ok_or_else(|| io::Error::other("mock prompt credential missing"))?;
        crate::host_io::json_new(
            &endpoint.owner_file,
            &json!({"state":"launching","role":"agent_bridge"}),
        )?;
        let mut child = command(&endpoint.executable)
            .arg("mcp-connect")
            .arg(&endpoint.socket)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true)
            .spawn()?;
        crate::host_io::json_replace(
            &endpoint.owner_file,
            &json!({"state":"running","process_group":child.id(),"role":"agent_bridge"}),
        )?;
        let mut rpc = Rpc::new(child.stdout.take().unwrap(), child.stdin.take().unwrap());
        let timeout = Duration::from_secs(320);
        let initialize = rpc.request("initialize", json!({}), timeout).await?;
        let tools = rpc.request("tools/list", json!({}), timeout).await?;
        if initialize.get("error").is_some() || tools.get("error").is_some() {
            return Err(io::Error::other("mock MCP initialization rejected"));
        }
        let mut responses = Vec::new();
        let mut status = "finished";
        for call in &self.calls {
            let arguments = replace(&call.arguments, key);
            let response = rpc
                .request(
                    "tools/call",
                    json!({"name":call.name,"arguments":arguments}),
                    timeout,
                )
                .await?;
            let rejected = response.get("error").is_some();
            responses.push(response);
            if rejected {
                status = "admission_rejected";
                break;
            }
        }
        // Return the mock's report even after a rejected call. M5 must compare
        // claims against actual observations, rather than trusting this output.
        let outcome = AgentOutcome {
            status: status.into(),
            final_output: self.final_output.clone(),
            calls_attempted: responses.len() as u64,
            responses,
        };
        drop(rpc);
        let exit = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
        if !matches!(exit,Ok(Ok(status)) if status.success()) {
            child.kill().await?;
            return Err(io::Error::other("mock bridge failed"));
        }
        Ok(outcome)
    }
}

struct ProcessGroupGuard(Option<i32>);

impl ProcessGroupGuard {
    fn stop(&mut self) {
        if let Some(group) = self.0.take() {
            unsafe {
                libc::kill(-group, libc::SIGKILL);
            }
        }
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn bounded_stream<R: tokio::io::AsyncRead + Unpin>(reader: R) -> io::Result<(Vec<u8>, bool)> {
    use tokio::io::AsyncReadExt;
    let mut reader = reader;
    let mut bytes = Vec::new();
    let mut exceeded = false;
    let mut chunk = [0_u8; 8192];
    loop {
        let count = reader.read(&mut chunk).await?;
        if count == 0 {
            break;
        }
        let remaining = (MAX_AGENT_STREAM as usize).saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..count.min(remaining)]);
        exceeded |= count > remaining;
    }
    Ok((bytes, exceeded))
}

async fn run_cli_contract(
    contract: &CliContract,
    prompt: &str,
    endpoint: &McpCommand,
    cwd: &Path,
    require_final_report: bool,
    authorize: impl FnOnce() -> io::Result<()>,
) -> io::Result<AgentOutcome> {
    let launch = contract.launch(prompt, endpoint, cwd)?;
    crate::host_io::json_new(
        &endpoint.owner_file,
        &json!({"state":"launching","role":"model_cli"}),
    )?;
    authorize()?;
    let mut child = command(&contract.sandbox_executable)
        .args(launch.arguments)
        .env_clear()
        .envs(launch.environment)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()?;
    let mut group = ProcessGroupGuard(child.id().map(|id| id as i32));
    crate::host_io::json_replace(
        &endpoint.owner_file,
        &json!({"state":"running","process_group":child.id(),"role":"model_cli"}),
    )?;
    {
        use tokio::io::AsyncWriteExt;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("agent stdin unavailable"))?;
        stdin.write_all(prompt.as_bytes()).await?;
        stdin.shutdown().await?;
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("agent stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("agent stderr unavailable"))?;
    let ((stdout, stdout_exceeded), (stderr, stderr_exceeded), status) =
        tokio::try_join!(bounded_stream(stdout), bounded_stream(stderr), child.wait())?;
    group.stop();
    crate::host_io::write_new(&endpoint.raw_stdout, &stdout)?;
    crate::host_io::write_new(&endpoint.raw_stderr, &stderr)?;
    if stdout_exceeded || stderr_exceeded {
        return Err(io::Error::other("agent process stream too large"));
    }
    if !status.success() {
        return Err(io::Error::other("capability CLI process failed"));
    }
    let final_output = match (require_final_report, contract.kind) {
        (true, CliKind::Codex) => codex_final_message(&stdout, true)?,
        (true, CliKind::ClaudeCode) => claude_final_message(&stdout, true, contract.maximum_turns)?,
        (false, _) => String::new(),
    };
    Ok(AgentOutcome {
        status: "finished".into(),
        final_output,
        calls_attempted: 0,
        responses: Vec::new(),
    })
}

pub(crate) async fn run_capability_probe_cli(
    config: CapabilityProbeCliConfig,
    prompt: &str,
    endpoint: &McpCommand,
    cwd: &Path,
) -> io::Result<AgentOutcome> {
    let sandbox_executable = PathBuf::from("/usr/bin/sandbox-exec");
    let contract = CliContract {
        kind: config.kind,
        executable_sha256: crate::host_io::digest(&config.executable)?,
        executable: config.executable,
        mcp_bridge: config.mcp_bridge,
        relay_executable: config.relay_executable,
        version: config.version,
        model: config.model,
        home: config.sandbox_jail.join("home"),
        relay_endpoint: config.relay_endpoint,
        maximum_turns: config.maximum_turns,
        sandbox_executable_sha256: crate::host_io::digest(&sandbox_executable)?,
        sandbox_executable,
        sandbox_profile_sha256: crate::host_io::digest(&config.sandbox_profile)?,
        sandbox_profile: config.sandbox_profile,
        sandbox_jail: config.sandbox_jail,
        harness_root: config.harness_root,
        system_profile_sha256: crate::host_io::digest(Path::new(
            "/System/Library/Sandbox/Profiles/system.sb",
        ))?,
        dyld_profile_sha256: crate::host_io::digest(Path::new(
            "/System/Library/Sandbox/Profiles/dyld-support.sb",
        ))?,
    };
    run_cli_contract(&contract, prompt, endpoint, cwd, false, || Ok(())).await
}

impl AgentAdapter for CliAdapter {
    fn describe(&self) -> Value {
        let contract = &self.contract;
        json!({"adapter":match contract.kind {CliKind::Codex=>"codex",CliKind::ClaudeCode=>"claude-code"},
            "model":contract.model,"cli_version":contract.version,
            "executable_sha256":contract.executable_sha256,
            "sandbox_executable_sha256":contract.sandbox_executable_sha256,
            "sandbox_profile_sha256":contract.sandbox_profile_sha256,
            "system_profile_sha256":contract.system_profile_sha256,
            "dyld_profile_sha256":contract.dyld_profile_sha256})
    }

    async fn run<'a>(
        &'a self,
        prompt: &'a str,
        endpoint: &'a McpCommand,
        cwd: &'a Path,
    ) -> io::Result<AgentOutcome> {
        let contract = &self.contract;
        run_cli_contract(contract, prompt, endpoint, cwd, true, || {
            claim_measured_launch(&self.launch_claimed)?;
            let profile = self.permit.profile();
            if !measured_launch_identity_matches(
                profile,
                contract.kind,
                &contract.version,
                &contract.model,
            ) || !measured_launch_contract_matches(
                profile,
                contract.kind,
                contract.maximum_turns,
            ) {
                return Err(io::Error::other(
                    "measured CLI identity or launch contract changed",
                ));
            }
            self.permit.verify_immediately_before_launch()
        })
        .await
    }
}
fn replace(value: &Value, key: &str) -> Value {
    match value {
        Value::String(text) => text.replace("${ACCESS_KEY_ID}", key).into(),
        Value::Array(values) => Value::Array(values.iter().map(|v| replace(v, key)).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(name, v)| (name.clone(), replace(v, key)))
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn json_lines(bytes: &[u8]) -> io::Result<Vec<Value>> {
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(io::Error::other("agent event stream too large"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| io::Error::other("agent stream is not UTF-8"))?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(io::Error::other))
        .collect()
}

/// Extract only a final top-level assistant message from a successful Codex
/// JSONL turn. Tool output and intermediate text are never fallback reports.
pub fn codex_final_message(bytes: &[u8], process_success: bool) -> io::Result<String> {
    if !process_success {
        return Err(io::Error::other("Codex process failed"));
    }
    let mut thread = None;
    let mut final_message = None;
    let mut completed = false;
    for event in json_lines(bytes)? {
        if completed
            && matches!(
                event["type"].as_str(),
                Some(
                    "thread.started" | "item.completed" | "turn.started" | "turn.failed" | "error"
                )
            )
        {
            return Err(io::Error::other("Codex emitted work after terminal event"));
        }
        match event["type"].as_str() {
            Some("thread.started") => {
                if thread.is_some() {
                    return Err(io::Error::other("Codex thread changed"));
                }
                thread = event["thread_id"].as_str().map(str::to_owned);
            }
            Some("item.completed") => {
                let item = event["item"]
                    .as_object()
                    .ok_or_else(|| io::Error::other("invalid Codex completed item"))?;
                match item.get("type").and_then(Value::as_str) {
                    Some("agent_message") => {
                        final_message = item
                            .get("text")
                            .and_then(Value::as_str)
                            .filter(|text| !text.is_empty())
                            .map(str::to_owned);
                    }
                    Some("reasoning") => {}
                    Some(_) => final_message = None,
                    None => return Err(io::Error::other("Codex item type missing")),
                }
            }
            Some("turn.completed") => completed = true,
            Some("turn.failed" | "error") => {
                return Err(io::Error::other("Codex turn failed"));
            }
            _ => {}
        }
    }
    if thread.as_deref().is_none_or(str::is_empty) || !completed {
        return Err(io::Error::other("Codex turn did not complete"));
    }
    final_message.ok_or_else(|| io::Error::other("Codex final assistant message missing"))
}

/// Extract only the last top-level, text-only assistant message preceding a
/// successful Claude result. Nested/subagent and tool-use events are excluded.
pub fn claude_final_message(
    bytes: &[u8],
    process_success: bool,
    maximum_turns: u64,
) -> io::Result<String> {
    if !process_success {
        return Err(io::Error::other("Claude process failed"));
    }
    let mut session = None;
    let mut final_message = None;
    let mut result = None;
    for event in json_lines(bytes)? {
        if result.is_some() && matches!(event["type"].as_str(), Some("assistant" | "result")) {
            return Err(io::Error::other(
                "Claude emitted work after terminal result",
            ));
        }
        match event["type"].as_str() {
            Some("system") if event["subtype"] == "init" => {
                if session.is_some() {
                    return Err(io::Error::other("Claude session changed"));
                }
                session = event["session_id"].as_str().map(str::to_owned);
            }
            Some("assistant") if event["parent_tool_use_id"].is_null() => {
                if event["session_id"].as_str() != session.as_deref() {
                    return Err(io::Error::other("Claude assistant session mismatch"));
                }
                let blocks = event
                    .pointer("/message/content")
                    .and_then(Value::as_array)
                    .ok_or_else(|| io::Error::other("invalid Claude assistant content"))?;
                let text_only = blocks.iter().all(|block| block["type"] == "text");
                final_message = if text_only {
                    let joined = blocks
                        .iter()
                        .filter_map(|block| block["text"].as_str())
                        .collect::<Vec<_>>()
                        .join("");
                    (!joined.is_empty()).then_some(joined)
                } else {
                    None
                };
            }
            Some("result") => result = Some(event),
            _ => {}
        }
    }
    let result = result.ok_or_else(|| io::Error::other("Claude result missing"))?;
    if result["subtype"] != "success"
        || result["is_error"] != false
        || result["stop_reason"] != "end_turn"
        || result["terminal_reason"] != "completed"
        || result["num_turns"]
            .as_u64()
            .is_none_or(|turns| turns > maximum_turns)
        || result["session_id"].as_str() != session.as_deref()
    {
        return Err(io::Error::other(
            "Claude session did not complete successfully",
        ));
    }
    final_message.ok_or_else(|| io::Error::other("Claude final assistant message missing"))
}

#[cfg(test)]
mod stream_tests {
    use super::*;

    #[test]
    fn measured_claude_contract_rejects_turn_or_environment_variance() {
        let (_, mut profile, _, _) = crate::capability_proof::tests::fixture();
        profile["agent"] = "claude-code".into();
        profile["cli_version"] = "2.1.323 (Claude Code)".into();
        profile["provider_protocol"] = "anthropic-messages".into();
        profile["argument_template"] = serde_json::to_value(claude_argument_template(20)).unwrap();
        profile["environment"] = serde_json::to_value(claude_environment_rules()).unwrap();
        let mut profile: crate::capability_proof::LauncherProfile =
            serde_json::from_value(profile).unwrap();
        let names = profile
            .environment
            .iter()
            .map(|rule| rule.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(measured_launch_contract_matches(
            &profile,
            CliKind::ClaudeCode,
            20
        ));
        assert!(measured_launch_identity_matches(
            &profile,
            CliKind::ClaudeCode,
            "2.1.323 (Claude Code)",
            "model-fixed"
        ));
        assert!(!measured_launch_identity_matches(
            &profile,
            CliKind::ClaudeCode,
            "2.1.323 (Claude Code)",
            "claude-haiku-5-5"
        ));
        assert!(!measured_launch_contract_matches(
            &profile,
            CliKind::ClaudeCode,
            19
        ));
        profile.environment[0].value_sha256 = Some("0".repeat(64));
        assert!(!measured_launch_contract_matches(
            &profile,
            CliKind::ClaudeCode,
            20
        ));
        assert!(!measured_launch_contract_matches(
            &profile,
            CliKind::Codex,
            20
        ));
    }

    #[test]
    fn measured_launch_can_be_claimed_only_once() {
        let claimed = AtomicBool::new(false);
        claim_measured_launch(&claimed).unwrap();
        assert!(claim_measured_launch(&claimed).is_err());
    }

    fn cli_fixture(kind: CliKind) -> (PathBuf, CliContract, McpCommand, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "tempest-cli-adapter-{}",
            crate::host_io::random_hex().unwrap()
        ));
        crate::host_io::directory(&root).unwrap();
        let jail = root.join("jail");
        let harness = root.join("harness");
        crate::host_io::directory(&jail).unwrap();
        crate::host_io::directory(&harness).unwrap();
        for directory in ["bin", "home", "cwd"] {
            crate::host_io::directory(&jail.join(directory)).unwrap();
        }
        let executable = jail.join("bin/agent");
        let bridge = jail.join("bin/tempest");
        crate::host_io::private_copy(&std::env::current_exe().unwrap(), &executable).unwrap();
        crate::host_io::private_copy(&std::env::current_exe().unwrap(), &bridge).unwrap();
        let profile = jail.join("agent.sb");
        crate::host_io::write_new(&profile, include_bytes!("darwin-agent.sb")).unwrap();
        let sandbox_executable = PathBuf::from("/usr/bin/sandbox-exec");
        let adapter = CliContract {
            kind,
            executable: executable.clone(),
            executable_sha256: crate::host_io::digest(&executable).unwrap(),
            mcp_bridge: bridge.canonicalize().unwrap(),
            relay_executable: root.join("relay"),
            version: "fixed".into(),
            model: "model-fixed".into(),
            home: jail.join("home"),
            relay_endpoint: "http://127.0.0.1:1234/capabilitycapabilitycapability12".into(),
            maximum_turns: 20,
            sandbox_executable: sandbox_executable.clone(),
            sandbox_executable_sha256: crate::host_io::digest(&sandbox_executable).unwrap(),
            sandbox_profile_sha256: crate::host_io::digest(&profile).unwrap(),
            sandbox_profile: profile,
            sandbox_jail: jail.clone(),
            harness_root: harness.clone(),
            system_profile_sha256: crate::host_io::digest(Path::new(
                "/System/Library/Sandbox/Profiles/system.sb",
            ))
            .unwrap(),
            dyld_profile_sha256: crate::host_io::digest(Path::new(
                "/System/Library/Sandbox/Profiles/dyld-support.sb",
            ))
            .unwrap(),
        };
        let endpoint = McpCommand {
            executable: bridge,
            socket: "/private/tmp/socket/s".into(),
            owner_file: harness.join("owner.json"),
            raw_stdout: harness.join("agent.events.jsonl"),
            raw_stderr: harness.join("agent.stderr"),
        };
        let cwd = jail.join("cwd");
        (root, adapter, endpoint, cwd)
    }

    fn lines(values: &[Value]) -> Vec<u8> {
        values
            .iter()
            .map(|value| serde_json::to_string(value).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    }

    #[test]
    fn unimplemented_codex_launch_contract_is_rejected_after_a_valid_permit() {
        let (root, _, _, challenge) = crate::capability_proof::tests::fixture();
        let code_root = root.join("authorized-code");
        let permit =
            crate::capability_proof::authorize_launch(&root, &code_root, challenge).unwrap();
        let jail = code_root.join("jail");
        for directory in ["home", "cwd"] {
            crate::host_io::directory(&jail.join(directory)).unwrap();
        }
        let profile = jail.join("agent.sb");
        crate::host_io::write_new(&profile, include_bytes!("darwin-agent.sb")).unwrap();
        let harness = root.join("harness");
        crate::host_io::directory(&harness).unwrap();
        let result = CliAdapter::new(
            permit,
            CliAdapterConfig {
                relay_endpoint: "http://127.0.0.1:1234/capabilitycapabilitycapability12".into(),
                maximum_turns: 20,
                sandbox_profile: profile,
                sandbox_jail: jail.clone(),
                harness_root: harness.clone(),
            },
        );
        let error = match result {
            Ok(_) => panic!("unimplemented Codex launch contract was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("argv or environment contract"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn real_cli_launches_bind_model_relay_mcp_and_empty_environment() {
        for kind in [CliKind::Codex, CliKind::ClaudeCode] {
            let (root, adapter, endpoint, cwd) = cli_fixture(kind);
            let launch = adapter.launch("fixed prompt", &endpoint, &cwd).unwrap();
            let arguments = launch
                .arguments
                .iter()
                .map(|value| value.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(arguments.contains("model-fixed"));
            assert!(arguments.contains("mcp-connect"));
            assert!(arguments.contains("--environment-policy"));
            assert!(arguments.contains("/private/tmp/socket/s"));
            assert!(!arguments.contains("fixed prompt"));
            assert_eq!(
                launch.environment[&OsString::from("HOME")],
                root.join("jail/home")
            );
            assert!(!launch.environment.contains_key(&OsString::from("PATH")));
            assert!(
                !launch
                    .environment
                    .contains_key(&OsString::from("AWS_SECRET_ACCESS_KEY"))
            );
            match kind {
                CliKind::Codex => {
                    assert!(arguments.contains("--ignore-user-config"));
                    assert!(arguments.contains("shell_tool"));
                    assert!(arguments.contains("wire_api=\"responses\""));
                }
                CliKind::ClaudeCode => {
                    assert!(arguments.contains("--strict-mcp-config"));
                    assert!(arguments.contains("--setting-sources"));
                    assert_eq!(
                        launch.environment[&OsString::from("DISABLE_AUTOUPDATER")],
                        "1"
                    );
                }
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn relay_endpoint_rejects_authority_and_encoding_confusion() {
        let (root, adapter, endpoint, cwd) = cli_fixture(CliKind::Codex);
        for value in [
            "http://127.0.0.1:1234@other.example/capabilitycapabilitycapability12",
            "http://2130706433:1234/capabilitycapabilitycapability12",
            "https://127.0.0.1:1234/capabilitycapabilitycapability12",
            "http://127.0.0.1:1234/capabilitycapabilitycapability12?q=x",
            "http://127.0.0.1:1234/capability%2Fcapabilitycapability12",
        ] {
            let mut changed = adapter.clone();
            changed.relay_endpoint = value.into();
            assert!(changed.launch("prompt", &endpoint, &cwd).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn jail_rejects_root_overlap_and_unlisted_secret_material() {
        let (root, adapter, endpoint, cwd) = cli_fixture(CliKind::Codex);
        let mut invalid = adapter.clone();
        invalid.sandbox_jail = "/".into();
        assert!(invalid.launch("prompt", &endpoint, &cwd).is_err());
        let mut invalid = adapter.clone();
        invalid.harness_root = root.clone();
        assert!(invalid.launch("prompt", &endpoint, &cwd).is_err());
        crate::host_io::write_new(&adapter.sandbox_jail.join("secret"), b"hidden").unwrap();
        assert!(adapter.launch("prompt", &endpoint, &cwd).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_allows_only_jail_files_and_the_fixed_relay_port() {
        use std::net::TcpListener;
        let (root, adapter, _, _) = cli_fixture(CliKind::Codex);
        let canary_root = std::env::temp_dir().join(format!(
            "tempest-seatbelt-canary-{}",
            crate::host_io::random_hex().unwrap()
        ));
        crate::host_io::directory(&canary_root).unwrap();
        let canary = canary_root.join("host-canary");
        crate::host_io::write_new(&canary, b"must-not-read").unwrap();
        let allowed = TcpListener::bind("127.0.0.1:0").unwrap();
        let denied = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = || {
            let mut command = std::process::Command::new(&adapter.sandbox_executable);
            command.args([
                "-D",
                &format!("RELAY=localhost:{}", allowed.local_addr().unwrap().port()),
                "-D",
                &format!("JAIL={}", root.canonicalize().unwrap().display()),
                "-D",
                "MCP_SOCKET=/private/tmp/tempest-missing-socket",
                "-f",
                adapter.sandbox_profile.to_str().unwrap(),
                "--",
            ]);
            command
        };
        assert!(
            base()
                .args([
                    "/usr/bin/nc",
                    "-z",
                    "127.0.0.1",
                    &allowed.local_addr().unwrap().port().to_string(),
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            !base()
                .args([
                    "/usr/bin/nc",
                    "-z",
                    "127.0.0.1",
                    &denied.local_addr().unwrap().port().to_string(),
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            !base()
                .args(["/bin/cat", canary.to_str().unwrap()])
                .status()
                .unwrap()
                .success()
        );
        let preference_control = std::process::Command::new("/usr/bin/defaults")
            .args(["read", "NSGlobalDomain", "AppleLocale"])
            .output()
            .unwrap();
        assert!(
            preference_control.status.success() && !preference_control.stdout.is_empty(),
            "CFPreferences positive control is unavailable"
        );
        assert!(
            !base()
                .args(["/usr/bin/defaults", "read", "NSGlobalDomain", "AppleLocale",])
                .status()
                .unwrap()
                .success(),
            "Seatbelt allowed a CFPreferences read"
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(canary_root).unwrap();
    }

    #[test]
    fn codex_accepts_only_the_last_completed_assistant_item() {
        let valid = lines(&[
            json!({"type":"thread.started","thread_id":"thread-1"}),
            json!({"type":"item.completed","item":{"type":"tool_call","output":"```json secret ```"}}),
            json!({"type":"item.completed","item":{"type":"agent_message","text":"final"}}),
            json!({"type":"turn.completed"}),
        ]);
        assert_eq!(codex_final_message(&valid, true).unwrap(), "final");
        let tool_ended = lines(&[
            json!({"type":"thread.started","thread_id":"thread-1"}),
            json!({"type":"item.completed","item":{"type":"agent_message","text":"intermediate"}}),
            json!({"type":"item.completed","item":{"type":"tool_call"}}),
            json!({"type":"turn.completed"}),
        ]);
        assert!(codex_final_message(&tool_ended, true).is_err());
        let post_terminal = lines(&[
            json!({"type":"thread.started","thread_id":"thread-1"}),
            json!({"type":"item.completed","item":{"type":"agent_message","text":"first"}}),
            json!({"type":"turn.completed"}),
            json!({"type":"item.completed","item":{"type":"agent_message","text":"late"}}),
        ]);
        assert!(codex_final_message(&post_terminal, true).is_err());
        let changed_thread = lines(&[
            json!({"type":"thread.started","thread_id":"thread-1"}),
            json!({"type":"thread.started","thread_id":"thread-2"}),
            json!({"type":"turn.completed"}),
        ]);
        assert!(codex_final_message(&changed_thread, true).is_err());
        assert!(codex_final_message(&valid[..valid.len() - 26], true).is_err());
        assert!(codex_final_message(&valid, false).is_err());
    }

    #[test]
    fn claude_rejects_nested_intermediate_truncated_and_tool_ended_streams() {
        let init = json!({"type":"system","subtype":"init","session_id":"session-1"});
        let result = json!({"type":"result","subtype":"success","is_error":false,
            "stop_reason":"end_turn","terminal_reason":"completed","num_turns":2,
            "session_id":"session-1"});
        let valid = lines(&[
            init.clone(),
            json!({"type":"assistant","parent_tool_use_id":"tool-parent",
                "message":{"content":[{"type":"text","text":"```json nested ```"}]}}),
            json!({"type":"assistant","session_id":"session-1","parent_tool_use_id":null,
                "message":{"content":[{"type":"text","text":"final"}]}}),
            result.clone(),
        ]);
        assert_eq!(claude_final_message(&valid, true, 3).unwrap(), "final");
        assert!(claude_final_message(&valid, true, 1).is_err());
        let tool_ended = lines(&[
            init,
            json!({"type":"assistant","session_id":"session-1","parent_tool_use_id":null,
                "message":{"content":[{"type":"text","text":"intermediate"},
                    {"type":"tool_use","name":"mcp"}]}}),
            result,
        ]);
        assert!(claude_final_message(&tool_ended, true, 3).is_err());
        let changed_session = lines(&[
            json!({"type":"system","subtype":"init","session_id":"session-1"}),
            json!({"type":"system","subtype":"init","session_id":"session-2"}),
            json!({"type":"result","subtype":"success","is_error":false,
                "stop_reason":"end_turn","terminal_reason":"completed","num_turns":1,
                "session_id":"session-2"}),
        ]);
        assert!(claude_final_message(&changed_session, true, 3).is_err());
        let mut post_terminal = valid.clone();
        post_terminal.extend_from_slice(
            b"\n{\"type\":\"assistant\",\"parent_tool_use_id\":null,\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"late\"}]}}",
        );
        assert!(claude_final_message(&post_terminal, true, 3).is_err());
        assert!(claude_final_message(&valid[..valid.len() / 2], true, 3).is_err());
        assert!(claude_final_message(&valid, false, 3).is_err());
    }
}
