//! Fail-closed acceptance proof for real model CLI launchers.
use crate::host_io;
use serde::Deserialize;
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
pub struct LauncherProfile {
    pub schema_version: u64,
    pub agent: String,
    pub model: String,
    pub cli_version: String,
    pub provider_protocol: String,
    pub upstream_authority: String,
    pub request_policy_sha256: String,
    pub argument_template: Vec<String>,
    pub environment: Vec<EnvironmentRule>,
    pub home_policy: String,
    pub cwd_policy: String,
    pub prompt_policy: String,
    pub real_authentication_owner: String,
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
}

#[derive(Debug)]
pub struct VerifiedProof {
    pub proof_id: String,
    pub profile_sha256: String,
    pub profile: LauncherProfile,
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

fn parse<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> io::Result<T> {
    let unique: UniqueValue = serde_json::from_slice(bytes)?;
    serde_json::from_value(unique.0).map_err(io::Error::other)
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
        home |= value.name == "HOME" && value.source == "generated_private_directory";
        endpoint |= value.source == "relay_endpoint";
        placeholder |= value.source == "fixed_placeholder";
        prior = Some(value.name.as_str());
    }
    home && endpoint && placeholder
}

pub fn load(root: &Path) -> io::Result<VerifiedProof> {
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
        || !digest(&profile.request_policy_sha256)
        || profile.argument_template.is_empty()
        || !environment_contract(&profile.environment)
        || profile.home_policy != "empty_owner_private"
        || profile.cwd_policy != "empty_owner_private"
        || profile.prompt_policy != "tempest_generated_only"
        || profile.real_authentication_owner != "model_api_relay_only"
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
    for check in proof.checks.values() {
        if !check.performed
            || !check.passed
            || check.profile_sha256 != profile_sha256
            || check.evidence.is_empty()
            || check
                .evidence
                .iter()
                .any(|name| !evidence.contains_key(name))
        {
            return Err(invalid("capability acceptance check not established"));
        }
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
    Ok(VerifiedProof {
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
            "request_policy_sha256":"a".repeat(64),"argument_template":["exec","<PROMPT>"],
            "environment":[
                {"name":"HOME","source":"generated_private_directory"},
                {"name":"OPENAI_API_KEY","source":"fixed_placeholder"},
                {"name":"OPENAI_BASE_URL","source":"relay_endpoint"},
                {"name":"PATH","source":"fixed_nonsecret"}],"home_policy":"empty_owner_private",
            "cwd_policy":"empty_owner_private","prompt_policy":"tempest_generated_only",
            "real_authentication_owner":"model_api_relay_only",
            "code_closure":[closure("agent_executable",&executable),closure("mcp_bridge",&bridge),
                closure("model_api_relay",&relay)]
        });
        let profile_bytes = serde_json::to_vec_pretty(&profile).unwrap();
        host_io::write_new(&root.join("launcher-profile.json"), &profile_bytes).unwrap();
        let evidence_bytes = b"measured\n";
        host_io::write_new(&root.join("evidence/acceptance.json"), evidence_bytes).unwrap();
        let profile_hash = sha256(&profile_bytes);
        let check = json!({"performed":true,"passed":true,"profile_sha256":profile_hash,
            "evidence":["acceptance.json"]});
        let checks = REQUIRED_CHECKS
            .iter()
            .map(|name| (name.to_string(), check.clone()))
            .collect::<serde_json::Map<_, _>>();
        let proof = json!({"schema_version":1,"proof_id":"proof-001","created_ns":1,
            "profile_sha256":profile_hash,"checks":checks,"evidence":[{
                "name":"acceptance.json","sha256":sha256(evidence_bytes),
                "bytes":evidence_bytes.len()}]});
        host_io::json_new(&root.join("capability-proof.json"), &proof).unwrap();
        (root, profile, proof)
    }

    #[test]
    fn complete_bound_proof_is_accepted_and_live_code_changes_are_rejected() {
        let (root, _, _) = fixture();
        assert_eq!(load(&root).unwrap().proof_id, "proof-001");
        host_io::replace(&root.join("agent"), b"changed").unwrap();
        assert!(load(&root).unwrap_err().to_string().contains("closure"));
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
        assert!(load(&root).is_err());
        proof["checks"] = json!({"host_tools_rejected":{"performed":true,"passed":true,
            "profile_sha256":proof["profile_sha256"],"evidence":["acceptance.json"]}});
        proof["status"] = "observed".into();
        host_io::json_replace(&root.join("capability-proof.json"), &proof).unwrap();
        assert!(load(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn duplicate_profile_keys_and_inherited_authentication_are_rejected() {
        let (root, profile, _) = fixture();
        let bytes = serde_json::to_vec(&profile).unwrap();
        let mut duplicate = b"{\"schema_version\":1,\"schema_version\":1,".to_vec();
        duplicate.extend_from_slice(&bytes[1..]);
        host_io::replace(&root.join("launcher-profile.json"), &duplicate).unwrap();
        assert!(load(&root).is_err());
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
        assert!(load(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
