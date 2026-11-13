//! Fail-closed acceptance proof for real model CLI launchers.
use crate::host_io;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

const LIMIT: u64 = 1024 * 1024;
const REQUIRED_CHECKS: [&str; 9] = [
    "allowed_mcp_succeeded",
    "control_socket_unavailable",
    "hmac_unavailable",
    "host_canary_read_denied",
    "host_canary_write_denied",
    "host_tools_rejected",
    "mcp_child_env_sanitized",
    "provider_request_policy",
    "tool_catalog_exact",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    schema_version: u64,
    proof_id: String,
    created_ns: u64,
    profile_sha256: String,
    checks: BTreeMap<String, Check>,
    evidence: Vec<Evidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    performed: bool,
    passed: bool,
    profile_sha256: String,
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    name: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceEvidence {
    schema_version: u64,
    check: String,
    profile_sha256: String,
    runner_sha256: String,
    started_ns: u64,
    finished_ns: u64,
    facts: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LauncherProfile {
    pub schema_version: u64,
    pub agent: String,
    pub model: String,
    pub cli_version: String,
    pub provider_protocol: String,
    pub upstream_authority: String,
    pub proof_upstream_kind: String,
    pub allowed_runtime_variance: Vec<String>,
    pub request_policy_sha256: String,
    pub argument_template: Vec<String>,
    pub environment: Vec<EnvironmentRule>,
    pub home_policy: String,
    pub cwd_policy: String,
    pub prompt_policy: String,
    pub real_authentication_owner: String,
    pub system_configuration: Vec<SystemPathRule>,
    pub code_closure: Vec<LiveArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveArtifact {
    pub role: String,
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentRule {
    pub name: String,
    pub source: String,
    pub value_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemPathRule {
    pub path: PathBuf,
    pub state: String,
    pub sha256: Option<String>,
}

#[derive(Debug)]
pub struct VerifiedEnvelope {
    pub proof_id: String,
    pub profile_sha256: String,
    pub profile: LauncherProfile,
}

/// In-memory, process-bound authorization. It is deliberately neither Clone
/// nor serializable; a proof directory by itself is not a launcher permit.
pub struct LaunchPermit {
    envelope: VerifiedEnvelope,
    proof_root: PathBuf,
    code: BTreeMap<String, PathBuf>,
    issued_pid: u32,
    issued_ns: u64,
}

impl LaunchPermit {
    pub fn profile(&self) -> &LauncherProfile {
        &self.envelope.profile
    }

    pub fn profile_sha256(&self) -> &str {
        &self.envelope.profile_sha256
    }

    pub fn code_path(&self, role: &str) -> io::Result<&Path> {
        self.code
            .get(role)
            .map(PathBuf::as_path)
            .ok_or_else(|| invalid("authorized launcher code role missing"))
    }

    pub fn verify_immediately_before_launch(&self) -> io::Result<()> {
        if self.issued_pid != std::process::id()
            || host_io::now_ns()?.saturating_sub(self.issued_ns) > 60_000_000_000
        {
            return Err(invalid(
                "launcher permit expired or crossed a process boundary",
            ));
        }
        let current = load_envelope(&self.proof_root)?;
        if current.proof_id != self.envelope.proof_id
            || current.profile_sha256 != self.envelope.profile_sha256
        {
            return Err(invalid("launcher proof changed after authorization"));
        }
        for artifact in &self.envelope.profile.code_closure {
            let path = self.code_path(&artifact.role)?;
            if host_io::digest(path)? != artifact.sha256 {
                return Err(invalid("authorized launcher copy changed"));
            }
        }
        Ok(())
    }
}

pub fn authorize_launch(proof_root: &Path, code_destination: &Path) -> io::Result<LaunchPermit> {
    if code_destination.exists() {
        return Err(invalid("launcher code destination already exists"));
    }
    let envelope = load_envelope(proof_root)?;
    let code = materialize_code(&envelope, code_destination)?;
    let permit = LaunchPermit {
        envelope,
        proof_root: proof_root.canonicalize()?,
        code,
        issued_pid: std::process::id(),
        issued_ns: host_io::now_ns()?,
    };
    permit.verify_immediately_before_launch()?;
    Ok(permit)
}

/// Copy measured launcher code into one run-private directory and verify the
/// copies. Launchers must execute these paths, never the original live paths.
pub fn materialize_code(
    proof: &VerifiedEnvelope,
    destination: &Path,
) -> io::Result<BTreeMap<String, PathBuf>> {
    host_io::directory(destination)?;
    let mut paths = BTreeMap::new();
    for artifact in &proof.profile.code_closure {
        let target = destination.join(&artifact.role);
        host_io::private_copy(&artifact.path, &target)?;
        if host_io::digest(&target)? != artifact.sha256 {
            return Err(invalid("copied launcher code digest mismatch"));
        }
        fs::set_permissions(&target, fs::Permissions::from_mode(0o500))?;
        paths.insert(artifact.role.clone(), target);
    }
    Ok(paths)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn bounded(path: &Path) -> io::Result<Vec<u8>> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file() || metadata.len() > LIMIT {
        return Err(invalid("proof artifact must be a bounded regular file"));
    }
    fs::read(path)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct UniqueValue(serde_json::Value);

impl<'de> serde::Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(serde_json::Value::Number)
                    .map(UniqueValue)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(serde_json::Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(serde_json::Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(values.into()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut object: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((name, value)) = object.next_entry::<String, UniqueValue>()? {
                    if values.insert(name.clone(), value.0).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON key: {name}"
                        )));
                    }
                }
                Ok(UniqueValue(values.into()))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

pub(crate) fn parse_unique_value(bytes: &[u8]) -> io::Result<serde_json::Value> {
    let unique: UniqueValue = serde_json::from_slice(bytes)?;
    Ok(unique.0)
}

fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    serde_json::from_value(parse_unique_value(bytes)?).map_err(io::Error::other)
}

fn private_root(root: &Path) -> io::Result<()> {
    let metadata = root.symlink_metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(invalid("capability proof root must be owner-private"));
    }
    Ok(())
}

fn environment_contract(values: &[EnvironmentRule]) -> bool {
    if values.is_empty() {
        return false;
    }
    let mut prior = None;
    let mut home = false;
    let mut endpoint = false;
    let mut placeholder = false;
    for value in values {
        if value.name.is_empty()
            || !value
                .name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || prior.is_some_and(|prior| prior >= value.name.as_str())
            || !matches!(
                value.source.as_str(),
                "generated_private_directory"
                    | "fixed_nonsecret"
                    | "relay_endpoint"
                    | "fixed_placeholder"
            )
        {
            return false;
        }
        let fixed = matches!(
            value.source.as_str(),
            "fixed_nonsecret" | "fixed_placeholder"
        );
        if fixed != value.value_sha256.as_deref().is_some_and(digest)
            || (!fixed && value.value_sha256.is_some())
        {
            return false;
        }
        home |= value.name == "HOME" && value.source == "generated_private_directory";
        endpoint |= value.source == "relay_endpoint";
        placeholder |= value.source == "fixed_placeholder";
        prior = Some(value.name.as_str());
    }
    home && endpoint && placeholder
}

fn system_configuration_contract(values: &[SystemPathRule]) -> io::Result<bool> {
    if values.is_empty() {
        return Ok(false);
    }
    let mut prior: Option<&Path> = None;
    for value in values {
        if !value.path.is_absolute() || prior.is_some_and(|prior| prior >= value.path.as_path()) {
            return Ok(false);
        }
        match value.state.as_str() {
            "absent" => {
                if value.sha256.is_some() {
                    return Ok(false);
                }
                match value.path.symlink_metadata() {
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    _ => return Ok(false),
                }
            }
            "file" => {
                let expected = match value.sha256.as_deref().filter(|value| digest(value)) {
                    Some(value) => value,
                    None => return Ok(false),
                };
                if bounded(&value.path).map(|bytes| sha256(&bytes))? != expected {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
        prior = Some(&value.path);
    }
    Ok(true)
}

fn exact_facts<'a>(
    value: &'a Value,
    names: &[&str],
) -> io::Result<&'a serde_json::Map<String, Value>> {
    let values = value
        .as_object()
        .ok_or_else(|| invalid("acceptance facts are not an object"))?;
    if values.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != names.iter().copied().collect::<BTreeSet<_>>()
    {
        return Err(invalid("acceptance facts do not match the check contract"));
    }
    Ok(values)
}

fn positive(value: Option<&Value>) -> bool {
    value.and_then(Value::as_u64).is_some_and(|value| value > 0)
}

fn semantic_evidence(
    check: &str,
    bytes: &[u8],
    profile_sha256: &str,
    request_policy_sha256: &str,
) -> io::Result<()> {
    let evidence: AcceptanceEvidence = parse(bytes)?;
    if evidence.schema_version != 1
        || evidence.check != check
        || evidence.profile_sha256 != profile_sha256
        || !digest(&evidence.runner_sha256)
        || evidence.started_ns == 0
        || evidence.finished_ns < evidence.started_ns
    {
        return Err(invalid("acceptance evidence binding mismatch"));
    }
    let valid = match check {
        "allowed_mcp_succeeded" => {
            let facts = exact_facts(&evidence.facts, &["attempts", "successes", "audit_bound"])?;
            positive(facts.get("attempts"))
                && facts["attempts"] == facts["successes"]
                && facts["audit_bound"] == true
        }
        "control_socket_unavailable" | "hmac_unavailable" | "host_tools_rejected" => {
            let facts = exact_facts(
                &evidence.facts,
                &["attempts", "rejections", "bypass_events"],
            )?;
            positive(facts.get("attempts"))
                && facts["attempts"] == facts["rejections"]
                && facts["bypass_events"] == 0
        }
        "host_canary_read_denied" => {
            let facts = exact_facts(
                &evidence.facts,
                &["attempts", "rejections", "before_sha256", "after_sha256"],
            )?;
            positive(facts.get("attempts"))
                && facts["attempts"] == facts["rejections"]
                && facts["before_sha256"] == facts["after_sha256"]
                && facts["before_sha256"].as_str().is_some_and(digest)
        }
        "host_canary_write_denied" => {
            let facts = exact_facts(&evidence.facts, &["attempts", "rejections", "created"])?;
            positive(facts.get("attempts"))
                && facts["attempts"] == facts["rejections"]
                && facts["created"] == false
        }
        "mcp_child_env_sanitized" => {
            let facts = exact_facts(&evidence.facts, &["samples", "violations"])?;
            positive(facts.get("samples")) && facts["violations"] == 0
        }
        "provider_request_policy" => {
            let facts = exact_facts(&evidence.facts, &["requests", "rejected", "policy_sha256"])?;
            positive(facts.get("requests"))
                && facts["rejected"] == 0
                && facts["policy_sha256"] == request_policy_sha256
        }
        "tool_catalog_exact" => {
            let facts = exact_facts(
                &evidence.facts,
                &["requests", "expected_sha256", "observed_sha256"],
            )?;
            positive(facts.get("requests"))
                && facts["expected_sha256"] == facts["observed_sha256"]
                && facts["expected_sha256"].as_str().is_some_and(digest)
        }
        _ => false,
    };
    if !valid {
        return Err(invalid("acceptance evidence did not establish the check"));
    }
    Ok(())
}

/// Verify only the envelope, file integrity, and static profile contract.
/// This does not establish that any capability check was meaningfully run.
pub fn load_envelope(root: &Path) -> io::Result<VerifiedEnvelope> {
    private_root(root)?;
    private_root(&root.join("evidence"))?;
    let profile_bytes = bounded(&root.join("launcher-profile.json"))?;
    let profile_sha256 = sha256(&profile_bytes);
    let profile: LauncherProfile = parse(&profile_bytes)?;
    let proof: Proof = parse(&bounded(&root.join("capability-proof.json"))?)?;
    if proof.schema_version != 1
        || profile.schema_version != 1
        || !identifier(&proof.proof_id)
        || proof.created_ns == 0
        || !digest(&proof.profile_sha256)
        || proof.profile_sha256 != profile_sha256
    {
        return Err(invalid("invalid capability proof identity"));
    }
    if !matches!(profile.agent.as_str(), "codex" | "claude-code")
        || profile.model.is_empty()
        || profile.cli_version.is_empty()
        || !matches!(
            profile.provider_protocol.as_str(),
            "openai-responses" | "anthropic-messages"
        )
        || profile
            .upstream_authority
            .strip_prefix("https://")
            .is_none_or(|host| host.is_empty() || host.contains(['/', '?', '#', '@']))
        || profile.proof_upstream_kind != "local_deterministic_stub_through_relay"
        || profile.allowed_runtime_variance
            != ["relay_authentication_value", "relay_upstream_authority"]
        || !digest(&profile.request_policy_sha256)
        || profile.argument_template.is_empty()
        || !environment_contract(&profile.environment)
        || profile.home_policy != "empty_owner_private"
        || profile.cwd_policy != "empty_owner_private"
        || profile.prompt_policy != "tempest_generated_only"
        || profile.real_authentication_owner != "model_api_relay_only"
        || !system_configuration_contract(&profile.system_configuration)?
    {
        return Err(invalid("invalid launcher profile contract"));
    }
    let expected_checks: BTreeSet<_> = REQUIRED_CHECKS
        .iter()
        .map(|value| value.to_string())
        .collect();
    if proof.checks.keys().cloned().collect::<BTreeSet<_>>() != expected_checks {
        return Err(invalid("capability proof checks are incomplete"));
    }
    let mut evidence = BTreeMap::new();
    for artifact in &proof.evidence {
        if !identifier(&artifact.name)
            || !digest(&artifact.sha256)
            || artifact.bytes > LIMIT
            || evidence.insert(artifact.name.clone(), artifact).is_some()
        {
            return Err(invalid("invalid proof evidence manifest"));
        }
        let bytes = bounded(&root.join("evidence").join(&artifact.name))?;
        if bytes.len() as u64 != artifact.bytes || sha256(&bytes) != artifact.sha256 {
            return Err(invalid("proof evidence digest mismatch"));
        }
    }
    let mut used_evidence = BTreeSet::new();
    for (name, check) in &proof.checks {
        if !check.performed
            || !check.passed
            || check.profile_sha256 != profile_sha256
            || check.evidence.len() != 1
            || check
                .evidence
                .iter()
                .any(|name| !evidence.contains_key(name))
            || !used_evidence.insert(check.evidence[0].clone())
        {
            return Err(invalid("capability acceptance check not established"));
        }
        semantic_evidence(
            name,
            &bounded(&root.join("evidence").join(&check.evidence[0]))?,
            &profile_sha256,
            &profile.request_policy_sha256,
        )?;
    }
    let mut roles = BTreeSet::new();
    for artifact in &profile.code_closure {
        if !identifier(&artifact.role)
            || !roles.insert(artifact.role.clone())
            || !artifact.path.is_absolute()
            || !artifact.path.symlink_metadata()?.is_file()
            || artifact.path.canonicalize()? != artifact.path
            || !digest(&artifact.sha256)
            || host_io::digest(&artifact.path)? != artifact.sha256
        {
            return Err(invalid("launcher code closure mismatch"));
        }
    }
    for required in ["agent_executable", "mcp_bridge", "model_api_relay"] {
        if !roles.contains(required) {
            return Err(invalid("launcher code closure is incomplete"));
        }
    }
    Ok(VerifiedEnvelope {
        proof_id: proof.proof_id,
        profile_sha256,
        profile,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn fixture() -> (PathBuf, Value, Value) {
        let root = std::env::temp_dir().join(format!(
            "tempest-capability-proof-{}",
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        let root = root.canonicalize().unwrap();
        host_io::directory(&root.join("evidence")).unwrap();
        let executable = root.join("agent");
        host_io::write_new(&executable, b"agent").unwrap();
        let bridge = root.join("bridge");
        host_io::write_new(&bridge, b"bridge").unwrap();
        let relay = root.join("relay");
        host_io::write_new(&relay, b"relay").unwrap();
        let closure = |role: &str, path: &Path| json!({"role":role,"path":path,"sha256":host_io::digest(path).unwrap()});
        let profile = json!({
            "schema_version":1,"agent":"codex","model":"model-fixed","cli_version":"1.0",
            "provider_protocol":"openai-responses","upstream_authority":"https://api.example.invalid",
            "proof_upstream_kind":"local_deterministic_stub_through_relay",
            "allowed_runtime_variance":["relay_authentication_value","relay_upstream_authority"],
            "request_policy_sha256":"a".repeat(64),"argument_template":["exec","<PROMPT>"],
            "environment":[
                {"name":"HOME","source":"generated_private_directory","value_sha256":null},
                {"name":"OPENAI_API_KEY","source":"fixed_placeholder","value_sha256":"b".repeat(64)},
                {"name":"OPENAI_BASE_URL","source":"relay_endpoint","value_sha256":null},
                {"name":"PATH","source":"fixed_nonsecret","value_sha256":"c".repeat(64)}],"home_policy":"empty_owner_private",
            "cwd_policy":"empty_owner_private","prompt_policy":"tempest_generated_only",
            "real_authentication_owner":"model_api_relay_only",
            "system_configuration":[{"path":root.join("absent-managed-config"),
                "state":"absent","sha256":null}],
            "code_closure":[closure("agent_executable",&executable),closure("mcp_bridge",&bridge),
                closure("model_api_relay",&relay)]
        });
        let profile_bytes = serde_json::to_vec_pretty(&profile).unwrap();
        host_io::write_new(&root.join("launcher-profile.json"), &profile_bytes).unwrap();
        let profile_hash = sha256(&profile_bytes);
        let mut checks = serde_json::Map::new();
        let mut evidence_index = Vec::new();
        for name in REQUIRED_CHECKS {
            let facts = match name {
                "allowed_mcp_succeeded" => json!({"attempts":1,"successes":1,"audit_bound":true}),
                "control_socket_unavailable" | "hmac_unavailable" | "host_tools_rejected" => {
                    json!({"attempts":2,"rejections":2,"bypass_events":0})
                }
                "host_canary_read_denied" => json!({"attempts":1,"rejections":1,
                    "before_sha256":"e".repeat(64),"after_sha256":"e".repeat(64)}),
                "host_canary_write_denied" => json!({"attempts":1,"rejections":1,"created":false}),
                "mcp_child_env_sanitized" => json!({"samples":1,"violations":0}),
                "provider_request_policy" => {
                    json!({"requests":1,"rejected":0,"policy_sha256":"a".repeat(64)})
                }
                "tool_catalog_exact" => json!({"requests":1,
                    "expected_sha256":"f".repeat(64),"observed_sha256":"f".repeat(64)}),
                _ => unreachable!(),
            };
            let filename = format!("{name}.json");
            let bytes = serde_json::to_vec(&json!({"schema_version":1,"check":name,
                "profile_sha256":profile_hash,"runner_sha256":"d".repeat(64),
                "started_ns":1,"finished_ns":2,"facts":facts}))
            .unwrap();
            host_io::write_new(&root.join("evidence").join(&filename), &bytes).unwrap();
            checks.insert(
                name.to_owned(),
                json!({"performed":true,"passed":true,
                "profile_sha256":profile_hash,"evidence":[filename]}),
            );
            evidence_index.push(json!({"name":filename,"sha256":sha256(&bytes),
                "bytes":bytes.len()}));
        }
        let proof = json!({"schema_version":1,"proof_id":"proof-001","created_ns":1,
            "profile_sha256":profile_hash,"checks":checks,"evidence":evidence_index});
        host_io::json_new(&root.join("capability-proof.json"), &proof).unwrap();
        (root, profile, proof)
    }

    #[test]
    fn complete_bound_proof_is_accepted_and_live_code_changes_are_rejected() {
        let (root, _, _) = fixture();
        let proof = load_envelope(&root).unwrap();
        assert_eq!(proof.proof_id, "proof-001");
        let copies = materialize_code(&proof, &root.join("copies")).unwrap();
        assert_eq!(
            host_io::digest(&copies["agent_executable"]).unwrap(),
            proof
                .profile
                .code_closure
                .iter()
                .find(|item| item.role == "agent_executable")
                .unwrap()
                .sha256
        );
        host_io::replace(&root.join("agent"), b"changed").unwrap();
        assert!(
            load_envelope(&root)
                .unwrap_err()
                .to_string()
                .contains("closure")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn old_summary_wrapping_missing_checks_and_evidence_changes_are_rejected() {
        let (root, _, mut proof) = fixture();
        proof["checks"]
            .as_object_mut()
            .unwrap()
            .remove("allowed_mcp_succeeded");
        host_io::json_replace(&root.join("capability-proof.json"), &proof).unwrap();
        assert!(load_envelope(&root).is_err());
        proof["checks"] = json!({"host_tools_rejected":{"performed":true,"passed":true,
            "profile_sha256":proof["profile_sha256"],"evidence":["acceptance.json"]}});
        proof["status"] = "observed".into();
        host_io::json_replace(&root.join("capability-proof.json"), &proof).unwrap();
        assert!(load_envelope(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn self_declared_pass_with_semantically_failed_measurement_is_rejected() {
        let (root, _, mut proof) = fixture();
        let name = "allowed_mcp_succeeded.json";
        let path = root.join("evidence").join(name);
        let mut evidence: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        evidence["facts"]["successes"] = 0.into();
        let bytes = serde_json::to_vec(&evidence).unwrap();
        host_io::replace(&path, &bytes).unwrap();
        let metadata = proof["evidence"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|item| item["name"] == name)
            .unwrap();
        metadata["sha256"] = sha256(&bytes).into();
        metadata["bytes"] = bytes.len().into();
        host_io::json_replace(&root.join("capability-proof.json"), &proof).unwrap();
        assert!(
            load_envelope(&root)
                .unwrap_err()
                .to_string()
                .contains("did not establish")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn launch_permit_is_process_bound_and_rechecks_proof_and_copies() {
        let (root, _, _) = fixture();
        let permit = authorize_launch(&root, &root.join("authorized-code")).unwrap();
        permit.verify_immediately_before_launch().unwrap();
        host_io::replace(permit.code_path("agent_executable").unwrap(), b"changed").unwrap();
        assert!(
            permit
                .verify_immediately_before_launch()
                .unwrap_err()
                .to_string()
                .contains("copy changed")
        );
        fs::remove_dir_all(root).unwrap();

        let (root, _, mut proof) = fixture();
        let permit = authorize_launch(&root, &root.join("authorized-code")).unwrap();
        proof["proof_id"] = "proof-replaced".into();
        host_io::json_replace(&root.join("capability-proof.json"), &proof).unwrap();
        assert!(permit.verify_immediately_before_launch().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_profile_keys_and_inherited_authentication_are_rejected() {
        let (root, profile, _) = fixture();
        let bytes = serde_json::to_vec(&profile).unwrap();
        let mut duplicate = b"{\"schema_version\":1,\"schema_version\":1,".to_vec();
        duplicate.extend_from_slice(&bytes[1..]);
        host_io::replace(&root.join("launcher-profile.json"), &duplicate).unwrap();
        assert!(load_envelope(&root).is_err());
        fs::remove_dir_all(root).unwrap();

        let (root, mut profile, mut proof) = fixture();
        profile["environment"][1]["source"] = "inherited".into();
        let profile_bytes = serde_json::to_vec_pretty(&profile).unwrap();
        host_io::replace(&root.join("launcher-profile.json"), &profile_bytes).unwrap();
        let profile_hash = Value::from(sha256(&profile_bytes));
        proof["profile_sha256"] = profile_hash.clone();
        for check in proof["checks"].as_object_mut().unwrap().values_mut() {
            check["profile_sha256"] = profile_hash.clone();
        }
        host_io::json_replace(&root.join("capability-proof.json"), &proof).unwrap();
        assert!(load_envelope(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
