//! Wire and evidence types shared by host orchestration and the guest helper.
use crate::scenario::Setup;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type SeedBundle = Setup;
pub type AccessKeys = BTreeMap<String, String>;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    pub access_key_id: String,
    pub api: String,
    pub resource: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    Allow,
    Deny,
    Unsupported,
    Error,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProbeResult {
    pub outcome: ProbeOutcome,
    pub status: Option<u16>,
    pub error_code: Option<String>,
    pub complete: bool,
    pub credential_known: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiRecord {
    pub seq: u64,
    pub ts: String,
    pub method: String,
    /// Path only: query signatures and credentials are never persisted here.
    pub path: String,
    pub service: String,
    pub action: Option<String>,
    pub resource: Option<String>,
    /// Observed credential claim, not a verified identity.
    pub access_key_id: Option<String>,
    pub user_agent: Option<String>,
    pub status: Option<u16>,
    pub error_code: Option<String>,
    pub req_bytes: u64,
    pub req_sha256: String,
    pub resp_bytes: u64,
    pub resp_sha256: String,
    pub request_complete: bool,
    pub response_complete: bool,
    pub mapping_diagnostic: Option<String>,
    pub transport_error: Option<String>,
}
