//! Native fail-closed relay for model-provider requests.
use crate::{capability_proof::parse_unique_value, host_io};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full, Limited, StreamBody, combinators::UnsyncBoxBody};
use hyper::{Request, Response, StatusCode, body::Frame, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsString,
    fs::{self, File},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{ExitCode, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::task::JoinHandle;

const MAX_REQUEST: usize = 16 * 1024 * 1024;
const MAX_RESPONSE: usize = 64 * 1024 * 1024;
const MAX_FOREIGN_CAPABILITY_AUDIT_ROWS: u64 = 32;
const HOP_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "location",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];
const AUTH_HEADERS: &[&str] = &["authorization", "x-api-key"];
const FORBIDDEN_KEYS: &[&str] = &[
    "attachments",
    "conversation",
    "conversation_id",
    "file",
    "file_id",
    "files",
    "image_url",
    "previous_response_id",
    "remote_mcp",
    "url",
    "urls",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    schema_version: u64,
    acceptance_requests: u64,
    paths: Vec<String>,
    models: Vec<String>,
    top_level_fields: Vec<String>,
    request_value_types: Vec<String>,
    request_headers: BTreeMap<String, String>,
    maximum_requests: u64,
    mcp_catalog_source: McpCatalogSource,
    tools: Vec<Value>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpCatalogSource {
    executable_sha256: String,
    host_arch: String,
    host_os: String,
    version: String,
}
struct ValidatedPolicy {
    paths: BTreeSet<String>,
    models: BTreeSet<String>,
    fields: BTreeSet<String>,
    request_value_types: BTreeSet<String>,
    request_headers: Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
    maximum_requests: u64,
    tools: Vec<(String, String)>,
}
struct Admission {
    model: String,
    tools: Vec<String>,
}
type RelayBody = UnsyncBoxBody<Bytes, io::Error>;
struct Options {
    upstream: reqwest::Url,
    path_capability: String,
    policy: ValidatedPolicy,
    audit: PathBuf,
    ready: PathBuf,
    auth_header: reqwest::header::HeaderName,
    auth_value: reqwest::header::HeaderValue,
    timeout: std::time::Duration,
    lifetime: File,
}
struct State {
    upstream: reqwest::Url,
    path_capability: String,
    policy: ValidatedPolicy,
    audit: Mutex<File>,
    auth_header: reqwest::header::HeaderName,
    auth_value: reqwest::header::HeaderValue,
    client: reqwest::Client,
    requests: AtomicU64,
    foreign_capability_requests: AtomicU64,
}

pub(crate) struct ProbeRelay {
    endpoint: String,
    task: JoinHandle<()>,
}

pub(crate) struct ProductionRelay {
    endpoint: String,
    child: tokio::process::Child,
    process_group: i32,
    owner_file: PathBuf,
    lifetime: Option<File>,
    stopped: bool,
}

impl ProductionRelay {
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) async fn shutdown(mut self) -> io::Result<()> {
        drop(self.lifetime.take());
        let status = tokio::time::timeout(std::time::Duration::from_secs(10), self.child.wait())
            .await
            .map_err(|_| invalid("production model relay shutdown deadline"))??;
        if !status.success() {
            return Err(invalid("production model relay did not stop cleanly"));
        }
        self.stopped = true;
        host_io::json_replace(
            &self.owner_file,
            &json!({"state":"stopped","process_group":self.process_group,"role":"model_api_relay"}),
        )
    }
}

impl Drop for ProductionRelay {
    fn drop(&mut self) {
        if !self.stopped {
            let _ = self.child.start_kill();
            let _ = host_io::json_replace(
                &self.owner_file,
                &json!({"state":"stop_requested","process_group":self.process_group,"role":"model_api_relay"}),
            );
        }
    }
}

pub(crate) struct ProductionRelayConfig<'a> {
    pub(crate) executable: &'a Path,
    pub(crate) upstream: &'a str,
    pub(crate) policy_file: &'a Path,
    pub(crate) auth_file: &'a Path,
    pub(crate) auth_header: &'a str,
    pub(crate) audit_file: &'a Path,
    pub(crate) state_root: &'a Path,
    pub(crate) owner_file: &'a Path,
    pub(crate) timeout_seconds: u64,
}

fn create_lifetime_fifo(path: &Path) -> io::Result<()> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| invalid("invalid relay lifetime path"))?;
    if unsafe { libc::mkfifo(path.as_ptr(), 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn validate_lifetime_fifo(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.file_type().is_fifo()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(invalid("relay lifetime file is not an owner-private FIFO"));
    }
    Ok(())
}

fn bind_lifetime_fifo(path: &Path, timeout: std::time::Duration) -> io::Result<File> {
    let path_metadata = path
        .symlink_metadata()
        .map_err(|error| invalid(format!("relay lifetime path metadata: {error}")))?;
    validate_lifetime_fifo(&path_metadata)?;
    let mut lifetime = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| invalid(format!("relay lifetime open: {error}")))?;
    let opened_metadata = lifetime
        .metadata()
        .map_err(|error| invalid(format!("relay lifetime descriptor metadata: {error}")))?;
    validate_lifetime_fifo(&opened_metadata)?;
    if opened_metadata.dev() != path_metadata.dev() || opened_metadata.ino() != path_metadata.ino()
    {
        return Err(invalid("relay lifetime FIFO changed during open"));
    }
    let deadline = std::time::Instant::now() + timeout;
    let mut marker = [0_u8; 1];
    loop {
        match lifetime.read(&mut marker) {
            Ok(1) if marker[0] == b'L' => break,
            Ok(1) => return Err(invalid("invalid relay lifetime handshake")),
            Ok(0) => {}
            Ok(_) => unreachable!(),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        if std::time::Instant::now() >= deadline {
            return Err(invalid("relay lifetime handshake deadline"));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok(lifetime)
}

impl ProbeRelay {
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl Drop for ProbeRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}
fn private_bytes(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > limit
    {
        return Err(invalid(
            "relay input must be an owner-private bounded regular file",
        ));
    }
    fs::read(path)
}

pub(crate) async fn start_production_relay(
    config: ProductionRelayConfig<'_>,
) -> io::Result<ProductionRelay> {
    let capability = host_io::random_hex()?;
    let capability_file = config.state_root.join("model-relay-capability");
    let ready_file = config.state_root.join("model-relay-ready.json");
    let lifetime_file = config.state_root.join("model-relay-lifetime");
    host_io::write_new(&capability_file, capability.as_bytes())?;
    create_lifetime_fifo(&lifetime_file)?;
    host_io::json_new(
        config.owner_file,
        &json!({"state":"launching","role":"model_api_relay"}),
    )?;
    let mut child = host_io::command(config.executable)
        .args([
            OsString::from("model-api-relay"),
            OsString::from("--upstream"),
            OsString::from(config.upstream),
            OsString::from("--capability-file"),
            capability_file.as_os_str().to_owned(),
            OsString::from("--policy-file"),
            config.policy_file.as_os_str().to_owned(),
            OsString::from("--audit"),
            config.audit_file.as_os_str().to_owned(),
            OsString::from("--ready-file"),
            ready_file.as_os_str().to_owned(),
            OsString::from("--auth-file"),
            config.auth_file.as_os_str().to_owned(),
            OsString::from("--auth-header"),
            OsString::from(config.auth_header),
            OsString::from("--timeout-seconds"),
            OsString::from(config.timeout_seconds.to_string()),
            OsString::from("--lifetime-file"),
            lifetime_file.as_os_str().to_owned(),
            OsString::from("--lifetime-bind-timeout-ms"),
            OsString::from("10000"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .kill_on_drop(true)
        .spawn()?;
    let lifetime_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let lifetime_write = loop {
        match fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lifetime_file)
        {
            Ok(file) => break file,
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {}
            Err(error) => return Err(error),
        }
        if child.try_wait()?.is_some() {
            return Err(invalid(
                "production model relay exited before lifetime bind",
            ));
        }
        if tokio::time::Instant::now() >= lifetime_deadline {
            return Err(invalid("production model relay lifetime bind deadline"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    (&lifetime_write).write_all(b"L")?;
    fs::remove_file(&lifetime_file)?;
    let process_group = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .ok_or_else(|| invalid("production model relay process ID unavailable"))?;
    host_io::json_replace(
        config.owner_file,
        &json!({"state":"running","process_group":process_group,"role":"model_api_relay",
            "executable_sha256":host_io::digest(config.executable)?}),
    )?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if ready_file.exists() {
            let ready: Value = parse_unique_value(&private_bytes(&ready_file, 4096)?)?;
            let port = ready["port"]
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0)
                .ok_or_else(|| invalid("invalid production relay ready port"))?;
            if ready["schema_version"] != 1
                || ready["host"] != "127.0.0.1"
                || ready["path_prefix"] != format!("/{capability}")
            {
                return Err(invalid("invalid production relay ready contract"));
            }
            return Ok(ProductionRelay {
                endpoint: format!("http://127.0.0.1:{port}/{capability}"),
                child,
                process_group,
                owner_file: config.owner_file.to_owned(),
                lifetime: Some(lifetime_write),
                stopped: false,
            });
        }
        if child.try_wait()?.is_some() {
            return Err(invalid("production model relay exited before ready"));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(invalid("production model relay ready deadline"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
fn sorted_unique(values: &[String]) -> bool {
    !values.is_empty() && values.windows(2).all(|pair| pair[0] < pair[1])
}
fn tool_identity(tool: &Value) -> io::Result<String> {
    let object = tool
        .as_object()
        .ok_or_else(|| invalid("tool is not an object"))?;
    let kind = object.get("type").and_then(Value::as_str);
    if kind == Some("namespace") {
        return object
            .get("name")
            .and_then(Value::as_str)
            .map(|name| format!("namespace:{name}"))
            .ok_or_else(|| invalid("namespace name missing"));
    }
    if let Some(name) = object.get("name").and_then(Value::as_str) {
        return Ok(format!("{}:{name}", kind.unwrap_or("tool")));
    }
    if kind == Some("function") {
        return object
            .get("function")
            .and_then(Value::as_object)
            .and_then(|function| function.get("name"))
            .and_then(Value::as_str)
            .map(|name| format!("function:{name}"))
            .ok_or_else(|| invalid("function name missing"));
    }
    Err(invalid("unknown tool representation"))
}
fn canonical_tools(tools: &[Value]) -> io::Result<Vec<(String, String)>> {
    let mut values = tools
        .iter()
        .map(|tool| Ok((tool_identity(tool)?, serde_json::to_string(tool)?)))
        .collect::<io::Result<Vec<_>>>()?;
    values.sort();
    if values.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(invalid("duplicate tool identity"));
    }
    Ok(values)
}
fn validate_policy(value: Value) -> io::Result<ValidatedPolicy> {
    let policy: Policy = serde_json::from_value(value).map_err(io::Error::other)?;
    if policy.schema_version != 1
        || !sorted_unique(&policy.paths)
        || !sorted_unique(&policy.models)
        || !sorted_unique(&policy.top_level_fields)
        || !policy.top_level_fields.iter().any(|value| value == "model")
        || !policy.top_level_fields.iter().any(|value| value == "tools")
        || policy.paths.iter().any(|path| {
            !path.starts_with('/')
                || path.contains('#')
                || path.matches('?').count() > 1
                || path.ends_with('?')
        })
        || policy.tools.is_empty()
        || !(1..=policy.maximum_requests).contains(&policy.acceptance_requests)
        || !(1..=1000).contains(&policy.maximum_requests)
        || policy.mcp_catalog_source.version.is_empty()
        || policy.mcp_catalog_source.version.len() > 256
        || policy.mcp_catalog_source.host_os.is_empty()
        || policy.mcp_catalog_source.host_arch.is_empty()
        || policy.mcp_catalog_source.executable_sha256.len() != 64
        || !policy
            .mcp_catalog_source
            .executable_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid("invalid model relay policy"));
    }
    let mut request_headers = Vec::new();
    for (name, value) in policy.request_headers {
        let name = name
            .parse::<reqwest::header::HeaderName>()
            .map_err(|_| invalid("invalid fixed request header name"))?;
        if HOP_HEADERS.contains(&name.as_str()) || AUTH_HEADERS.contains(&name.as_str()) {
            return Err(invalid("unsafe fixed request header"));
        }
        let value = value
            .parse::<reqwest::header::HeaderValue>()
            .map_err(|_| invalid("invalid fixed request header value"))?;
        request_headers.push((name, value));
    }
    if policy
        .request_value_types
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid("invalid request value type policy"));
    }
    Ok(ValidatedPolicy {
        paths: policy.paths.into_iter().collect(),
        models: policy.models.into_iter().collect(),
        fields: policy.top_level_fields.into_iter().collect(),
        request_value_types: policy.request_value_types.into_iter().collect(),
        request_headers,
        maximum_requests: policy.maximum_requests,
        tools: canonical_tools(&policy.tools)?,
    })
}
fn forbidden(value: &Value) -> Option<&str> {
    match value {
        Value::Object(values) => values.iter().find_map(|(name, value)| {
            FORBIDDEN_KEYS
                .contains(&name.as_str())
                .then_some(name.as_str())
                .or_else(|| forbidden(value))
        }),
        Value::Array(values) => values.iter().find_map(forbidden),
        _ => None,
    }
}
fn validate_value_types(value: &Value, allowed: &BTreeSet<String>) -> io::Result<()> {
    match value {
        Value::Object(values) => {
            if let Some(kind) = values.get("type") {
                let kind = kind
                    .as_str()
                    .ok_or_else(|| invalid("request value type is not text"))?;
                if !allowed.contains(kind) {
                    return Err(invalid(format!(
                        "request value type is not allowed: {kind}"
                    )));
                }
            }
            for value in values.values() {
                validate_value_types(value, allowed)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_value_types(value, allowed)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn admit(body: &[u8], path: &str, policy: &ValidatedPolicy) -> io::Result<Admission> {
    let value = parse_unique_value(body)?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("request is not an object"))?;
    if !policy.paths.contains(path) {
        return Err(invalid("request path is not allowed"));
    }
    let model = object
        .get("model")
        .and_then(Value::as_str)
        .filter(|model| policy.models.contains(*model))
        .ok_or_else(|| invalid("request model is not allowed"))?
        .to_owned();
    if !policy.models.contains(&model) {
        return Err(invalid("request model is not allowed"));
    }
    if object.keys().any(|name| !policy.fields.contains(name)) {
        return Err(invalid("unknown top-level request field"));
    }
    if let Some(name) = forbidden(&value) {
        return Err(invalid(format!("forbidden request capability: {name}")));
    }
    let mut capability_value = value.clone();
    capability_value.as_object_mut().unwrap().remove("tools");
    validate_value_types(&capability_value, &policy.request_value_types)?;
    let tools = object
        .get("tools")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("request has no explicit tool catalog"))?;
    let tools = canonical_tools(tools)?;
    if tools != policy.tools {
        return Err(invalid("tool catalog mismatch"));
    }
    Ok(Admission {
        model,
        tools: tools.into_iter().map(|(identity, _)| identity).collect(),
    })
}
fn body(bytes: Bytes) -> RelayBody {
    Full::new(bytes)
        .map_err(|never| match never {})
        .boxed_unsync()
}
fn response(status: StatusCode, reason: &str) -> Response<RelayBody> {
    let bytes = Bytes::from(
        serde_json::to_vec(&json!({"error":"request_rejected","reason":reason})).unwrap(),
    );
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::CONTENT_LENGTH, bytes.len())
        .body(body(bytes))
        .unwrap()
}

fn reviewed_preflight(method: &hyper::Method, request_target: &str, capability: &str) -> bool {
    method == hyper::Method::HEAD && request_target == format!("/{capability}/api/hello")
}

fn delivery_state(forwarded: bool, reason: Option<&str>) -> &'static str {
    match (forwarded, reason) {
        (true, _) => "response_complete",
        (false, Some("upstream transport failed")) => "request_outcome_unknown",
        (false, Some(reason)) if reason.starts_with("upstream redirect ") => {
            "request_sent_response_rejected"
        }
        (false, Some("upstream response failed" | "upstream response too large")) => {
            "request_sent_response_failed"
        }
        (false, Some("downstream response closed")) => "request_sent_downstream_closed",
        _ => "not_sent",
    }
}

#[allow(clippy::too_many_arguments)]
fn audit(
    state: &State,
    method: &str,
    forwarded: bool,
    body: &[u8],
    reason: Option<&str>,
    path: &str,
    admission: Option<&Admission>,
    upstream_status: Option<u16>,
) -> io::Result<()> {
    audit_with_response(
        state,
        method,
        forwarded,
        body,
        reason,
        path,
        admission,
        upstream_status,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn audit_with_response(
    state: &State,
    method: &str,
    forwarded: bool,
    body: &[u8],
    reason: Option<&str>,
    path: &str,
    admission: Option<&Admission>,
    upstream_status: Option<u16>,
    response_observation: Option<(usize, String)>,
) -> io::Result<()> {
    let model = admission.map(|value| value.model.as_str());
    let tools = admission.map(|value| value.tools.as_slice()).unwrap_or(&[]);
    let delivery_state = delivery_state(forwarded, reason);
    let (response_bytes, response_sha256) = response_observation
        .map(|(bytes, sha256)| (Some(bytes), Some(sha256)))
        .unwrap_or((None, None));
    let event = json!({"forwarded":forwarded,"request_sha256":format!("{:x}",Sha256::digest(body)),
        "request_bytes":body.len(),"method":method,"path":path,"model":model,"tools":tools,"reason":reason,
        "upstream_status":upstream_status,"delivery_state":delivery_state,
        "response_bytes":response_bytes,"response_sha256":response_sha256});
    let mut file = state
        .audit
        .lock()
        .map_err(|_| invalid("relay audit lock poisoned"))?;
    serde_json::to_writer(&mut *file, &event)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn audit_foreign_capability(state: &State, method: &str, request_target: &str) {
    let index = state
        .foreign_capability_requests
        .fetch_add(1, Ordering::SeqCst);
    if index < MAX_FOREIGN_CAPABILITY_AUDIT_ROWS {
        let target = format!("sha256:{:x}", Sha256::digest(request_target.as_bytes()));
        let _ = audit(
            state,
            method,
            false,
            &[],
            Some("foreign relay capability"),
            &target,
            None,
            None,
        );
    } else if index == MAX_FOREIGN_CAPABILITY_AUDIT_ROWS {
        let _ = audit(
            state,
            method,
            false,
            &[],
            Some("foreign relay capability overflow"),
            "bounded",
            None,
            None,
        );
    }
}
async fn handle(
    request: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<RelayBody>, std::convert::Infallible> {
    let request_target = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| request.uri().path())
        .to_owned();
    let prefix = format!("/{}", state.path_capability);
    let Some(suffix) = request_target
        .strip_prefix(&prefix)
        .filter(|suffix| suffix.starts_with('/'))
        .map(str::to_owned)
    else {
        audit_foreign_capability(&state, request.method().as_str(), &request_target);
        return Ok(response(StatusCode::NOT_FOUND, "invalid relay capability"));
    };
    if request.method() != hyper::Method::POST {
        let reviewed_hello =
            reviewed_preflight(request.method(), &request_target, &state.path_capability);
        let reason = if reviewed_hello {
            "reviewed preflight rejected"
        } else {
            "method is not allowed"
        };
        let _ = audit(
            &state,
            request.method().as_str(),
            false,
            &[],
            Some(reason),
            &request_target,
            None,
            None,
        );
        return Ok(response(StatusCode::METHOD_NOT_ALLOWED, reason));
    }
    if request
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_none_or(|length| length > MAX_REQUEST)
    {
        let _ = audit(
            &state,
            "POST",
            false,
            &[],
            Some("invalid request length"),
            &suffix,
            None,
            None,
        );
        return Ok(response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invalid request length",
        ));
    }
    let body = match Limited::new(request.into_body(), MAX_REQUEST)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(_) => return Ok(response(StatusCode::PAYLOAD_TOO_LARGE, "request too large")),
    };
    let admission = match admit(&body, &suffix, &state.policy) {
        Ok(admission) => admission,
        Err(error) => {
            let _ = audit(
                &state,
                "POST",
                false,
                &body,
                Some(&error.to_string()),
                &suffix,
                None,
                None,
            );
            return Ok(response(StatusCode::CONFLICT, &error.to_string()));
        }
    };
    if state.requests.fetch_add(1, Ordering::SeqCst) >= state.policy.maximum_requests {
        let _ = audit(
            &state,
            "POST",
            false,
            &body,
            Some("model request budget exhausted"),
            &suffix,
            Some(&admission),
            None,
        );
        return Ok(response(
            StatusCode::TOO_MANY_REQUESTS,
            "model request budget exhausted",
        ));
    }
    let target = match state.upstream.join(suffix.trim_start_matches('/')) {
        Ok(target)
            if target.scheme() == state.upstream.scheme()
                && target.host_str() == state.upstream.host_str()
                && target.port_or_known_default() == state.upstream.port_or_known_default() =>
        {
            target
        }
        _ => {
            let _ = audit(
                &state,
                "POST",
                false,
                &body,
                Some("upstream authority changed"),
                &suffix,
                Some(&admission),
                None,
            );
            return Ok(response(
                StatusCode::BAD_GATEWAY,
                "upstream authority changed",
            ));
        }
    };
    if audit(
        &state,
        "POST",
        false,
        &body,
        Some("admission_verified"),
        &suffix,
        Some(&admission),
        None,
    )
    .is_err()
    {
        return Ok(response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "relay audit unavailable",
        ));
    }
    let mut upstream = state.client.post(target).body(body.clone());
    for (name, value) in &state.policy.request_headers {
        upstream = upstream.header(name, value);
    }
    upstream = upstream.header(state.auth_header.clone(), state.auth_value.clone());
    let upstream = match upstream.send().await {
        Ok(value) => value,
        Err(_) => {
            let _ = audit(
                &state,
                "POST",
                false,
                &body,
                Some("upstream transport failed"),
                &suffix,
                Some(&admission),
                None,
            );
            return Ok(response(
                StatusCode::BAD_GATEWAY,
                "upstream transport failed",
            ));
        }
    };
    if upstream.status().is_redirection() {
        let _ = audit(
            &state,
            "POST",
            false,
            &body,
            Some(&format!("upstream redirect {}", upstream.status())),
            &suffix,
            Some(&admission),
            Some(upstream.status().as_u16()),
        );
        return Ok(response(
            StatusCode::BAD_GATEWAY,
            "upstream redirect rejected",
        ));
    }
    let status = upstream.status();
    let response_headers = upstream.headers().clone();
    let mut upstream = upstream.bytes_stream();
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        let mut total = 0usize;
        let mut response_digest = Sha256::new();
        let mut downstream_open = true;
        while let Some(chunk) = upstream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(_) => {
                    let _ = audit_with_response(
                        &state,
                        "POST",
                        false,
                        &body,
                        Some("upstream response failed"),
                        &suffix,
                        Some(&admission),
                        Some(status.as_u16()),
                        Some((total, format!("{:x}", response_digest.finalize()))),
                    );
                    if downstream_open {
                        let _ = sender
                            .send(Err(io::Error::other("upstream response failed")))
                            .await;
                    }
                    return;
                }
            };
            total = total.saturating_add(chunk.len());
            response_digest.update(&chunk);
            if total > MAX_RESPONSE {
                let _ = audit_with_response(
                    &state,
                    "POST",
                    false,
                    &body,
                    Some("upstream response too large"),
                    &suffix,
                    Some(&admission),
                    Some(status.as_u16()),
                    Some((total, format!("{:x}", response_digest.finalize()))),
                );
                if downstream_open {
                    let _ = sender
                        .send(Err(io::Error::other("upstream response too large")))
                        .await;
                }
                return;
            }
            if downstream_open && sender.send(Ok(Frame::data(chunk))).await.is_err() {
                downstream_open = false;
            }
        }
        let reason = (!downstream_open).then_some("downstream response closed");
        let audited = audit_with_response(
            &state,
            "POST",
            downstream_open,
            &body,
            reason,
            &suffix,
            Some(&admission),
            Some(status.as_u16()),
            Some((total, format!("{:x}", response_digest.finalize()))),
        );
        if audited.is_err() && downstream_open {
            let _ = sender
                .send(Err(io::Error::other("relay audit completion unavailable")))
                .await;
        }
    });
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    });
    let mut downstream = Response::builder().status(status);
    for (name, value) in &response_headers {
        let lower = name.as_str().to_ascii_lowercase();
        if !HOP_HEADERS.contains(&lower.as_str()) {
            downstream = downstream.header(name, value);
        }
    }
    Ok(downstream
        .body(StreamBody::new(stream).boxed_unsync())
        .unwrap())
}

/// Start the acceptance probe relay against a loopback deterministic peer.
/// This deliberately reuses the production admission and forwarding path;
/// only the upstream scheme restriction differs from the public CLI.
pub(crate) async fn start_probe_relay(
    upstream: reqwest::Url,
    path_capability: String,
    policy: Value,
    audit_path: &Path,
) -> io::Result<ProbeRelay> {
    if upstream.scheme() != "http"
        || upstream.host_str() != Some("127.0.0.1")
        || upstream.port().is_none()
        || upstream.path().is_empty()
        || !upstream.path().ends_with('/')
        || upstream.query().is_some()
        || upstream.fragment().is_some()
        || path_capability.len() < 32
        || !path_capability
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid("invalid acceptance probe relay endpoint"));
    }
    let audit = fs::OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(audit_path)?;
    let state = Arc::new(State {
        upstream,
        path_capability: path_capability.clone(),
        policy: validate_policy(policy)?,
        audit: Mutex::new(audit),
        auth_header: reqwest::header::AUTHORIZATION,
        auth_value: "tempest-probe-relay-placeholder"
            .parse()
            .expect("fixed header value"),
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(std::time::Duration::from_secs(60))
            .read_timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|error| invalid(error.to_string()))?,
        requests: AtomicU64::new(0),
        foreign_capability_requests: AtomicU64::new(0),
    });
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let port = listener.local_addr()?.port();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let state = state.clone();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |request| handle(request, state.clone())),
                    )
                    .await;
            });
        }
    });
    Ok(ProbeRelay {
        endpoint: format!("http://127.0.0.1:{port}/{path_capability}"),
        task,
    })
}

fn parse_options(args: &[OsString]) -> io::Result<Options> {
    if args.len() != 20 {
        return Err(invalid("invalid model-api-relay arguments"));
    }
    let mut values = HashMap::new();
    for pair in args.chunks_exact(2) {
        let name = pair[0]
            .to_str()
            .ok_or_else(|| invalid("invalid relay option"))?;
        if !matches!(
            name,
            "--upstream"
                | "--capability-file"
                | "--policy-file"
                | "--audit"
                | "--ready-file"
                | "--auth-file"
                | "--auth-header"
                | "--timeout-seconds"
                | "--lifetime-file"
                | "--lifetime-bind-timeout-ms"
        ) || values.insert(name, pair[1].clone()).is_some()
        {
            return Err(invalid("unknown or duplicate relay option"));
        }
    }
    let required = |name: &str| {
        values
            .get(name)
            .cloned()
            .ok_or_else(|| invalid("required relay option missing"))
    };
    let upstream = required("--upstream")?
        .to_str()
        .ok_or_else(|| invalid("invalid upstream URL"))?
        .parse::<reqwest::Url>()
        .map_err(|error| invalid(error.to_string()))?;
    let production_upstream = upstream.scheme() == "https";
    #[cfg(feature = "native-test-upstream")]
    let test_upstream = upstream.scheme() == "http"
        && upstream.host_str() == Some("127.0.0.1")
        && upstream.port().is_some();
    #[cfg(not(feature = "native-test-upstream"))]
    let test_upstream = false;
    if (!production_upstream && !test_upstream)
        || upstream.host_str().is_none()
        || !upstream.username().is_empty()
        || upstream.password().is_some()
        || upstream.path() != "/"
        || upstream.query().is_some()
        || upstream.fragment().is_some()
    {
        return Err(invalid("invalid upstream URL"));
    }
    let path_capability = String::from_utf8(private_bytes(
        Path::new(&required("--capability-file")?),
        256,
    )?)
    .map_err(|_| invalid("invalid path capability"))?
    .trim()
    .to_owned();
    if path_capability.len() < 32
        || !path_capability
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid("invalid path capability"));
    }
    let policy = validate_policy(parse_unique_value(&private_bytes(
        Path::new(&required("--policy-file")?),
        1024 * 1024,
    )?)?)?;
    let auth_header = required("--auth-header")?
        .to_str()
        .ok_or_else(|| invalid("invalid auth header"))?
        .parse::<reqwest::header::HeaderName>()
        .map_err(|error| invalid(error.to_string()))?;
    if !AUTH_HEADERS.contains(&auth_header.as_str()) {
        return Err(invalid("unsupported auth header"));
    }
    let timeout = required("--timeout-seconds")?
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (1..=3600).contains(value))
        .ok_or_else(|| invalid("invalid relay timeout"))?;
    let lifetime_timeout = required("--lifetime-bind-timeout-ms")?
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| (100..=10_000).contains(value))
        .ok_or_else(|| invalid("invalid relay lifetime bind timeout"))?;
    // Establish controller liveness before loading the real provider credential.
    let lifetime = bind_lifetime_fifo(
        Path::new(&required("--lifetime-file")?),
        std::time::Duration::from_millis(lifetime_timeout),
    )?;
    let auth_value = reqwest::header::HeaderValue::from_bytes(&private_bytes(
        Path::new(&required("--auth-file")?),
        8192,
    )?)
    .map_err(|error| invalid(error.to_string()))?;
    Ok(Options {
        upstream,
        path_capability,
        policy,
        audit: required("--audit")?.into(),
        ready: required("--ready-file")?.into(),
        auth_header,
        auth_value,
        timeout: std::time::Duration::from_secs(timeout),
        lifetime,
    })
}
async fn serve(options: Options) -> io::Result<()> {
    let audit = fs::OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&options.audit)?;
    let state = Arc::new(State {
        upstream: options.upstream,
        path_capability: options.path_capability.clone(),
        policy: options.policy,
        audit: Mutex::new(audit),
        auth_header: options.auth_header,
        auth_value: options.auth_value,
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(options.timeout)
            .read_timeout(options.timeout)
            .build()
            .map_err(|error| invalid(error.to_string()))?,
        requests: AtomicU64::new(0),
        foreign_capability_requests: AtomicU64::new(0),
    });
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let address = listener.local_addr()?;
    host_io::json_new(
        &options.ready,
        &json!({"schema_version":1,"host":"127.0.0.1","port":address.port(),
        "path_prefix":format!("/{}",options.path_capability)}),
    )?;
    let mut lifetime = tokio::task::spawn_blocking(move || {
        let mut lifetime = options.lifetime;
        let mut byte = [0_u8; 1];
        loop {
            match lifetime.read(&mut byte) {
                Ok(0) => return Ok(0),
                Ok(read) => return Ok(read),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
    });
    let mut connections = tokio::task::JoinSet::new();
    let (shutdown, _) = tokio::sync::watch::channel(false);
    loop {
        let (stream, _) = tokio::select! {
            result = &mut lifetime => {
                result.map_err(io::Error::other)??;
                break;
            }
            accepted = listener.accept() => accepted?,
        };
        let state = state.clone();
        let mut shutdown = shutdown.subscribe();
        connections.spawn(async move {
            let connection = hyper::server::conn::http1::Builder::new().serve_connection(
                TokioIo::new(stream),
                service_fn(move |request| handle(request, state.clone())),
            );
            tokio::pin!(connection);
            tokio::select! {
                _ = &mut connection => {}
                changed = shutdown.changed() => {
                    if changed.is_ok() {
                        connection.as_mut().graceful_shutdown();
                        let _ = connection.await;
                    }
                }
            }
        });
    }
    let _ = shutdown.send(true);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while let Some(result) = connections.join_next().await {
            result.map_err(io::Error::other)?;
        }
        Ok::<_, io::Error>(())
    })
    .await
    .map_err(|_| invalid("production model relay connection drain deadline"))??;
    Ok(())
}
pub fn run(args: &[OsString]) -> ExitCode {
    const USAGE: &str = "Usage: tempest model-api-relay --upstream URL --capability-file FILE --policy-file FILE --audit FILE --ready-file FILE --auth-file FILE --auth-header NAME --timeout-seconds N --lifetime-file FIFO --lifetime-bind-timeout-ms N";
    let options = match parse_options(args) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match tokio::runtime::Runtime::new().and_then(|runtime| runtime.block_on(serve(options))) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("model-api-relay: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd};

    #[tokio::test]
    async fn production_relay_closes_idle_keepalive_when_controller_lifetime_closes() {
        let root = std::env::temp_dir().join(format!(
            "tempest-model-relay-lifetime-{}",
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        let mut descriptors = [-1; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        let read = unsafe { File::from_raw_fd(descriptors[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        let options = Options {
            upstream: "https://api.example.invalid/".parse().unwrap(),
            path_capability: "x".repeat(32),
            policy: validate_policy(policy_value()).unwrap(),
            audit: root.join("audit.jsonl"),
            ready: root.join("ready.json"),
            auth_header: reqwest::header::HeaderName::from_static("x-api-key"),
            auth_value: reqwest::header::HeaderValue::from_static("fixture"),
            timeout: std::time::Duration::from_secs(1),
            lifetime: read,
        };
        let task = tokio::spawn(serve(options));
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while !root.join("ready.json").is_file() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(root.join("ready.json").is_file());
        let ready: Value =
            serde_json::from_slice(&fs::read(root.join("ready.json")).unwrap()).unwrap();
        let _idle =
            tokio::net::TcpStream::connect(("127.0.0.1", ready["port"].as_u64().unwrap() as u16))
                .await
                .unwrap();
        drop(write);
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    use std::sync::atomic::{AtomicBool, Ordering};

    fn policy_value() -> Value {
        json!({"schema_version":1,"acceptance_requests":1,
        "paths":["/v1/messages"],"models":["model-1"],
        "top_level_fields":["model","prompt","tools"],"request_value_types":["text"],
        "request_headers":{"content-type":"application/json","x-tempest-profile":"fixed"},
        "maximum_requests":20,"mcp_catalog_source":{"version":"izanagi 0.2.7",
        "host_os":"macos","host_arch":"aarch64",
        "executable_sha256":"a".repeat(64)},
        "tools":[{"type":"function","name":"mcp__tempest__status","description":"fixed","input_schema":{"type":"object"}}]})
    }

    fn valid_request() -> Value {
        json!({"model":"model-1","prompt":"secret","tools":[{"description":"fixed",
            "input_schema":{"type":"object"},"name":"mcp__tempest__status","type":"function"}]})
    }

    fn policy() -> ValidatedPolicy {
        validate_policy(policy_value()).unwrap()
    }
    #[test]
    fn reviewed_preflight_requires_head_exact_capability_and_no_query() {
        let capability = "c".repeat(32);
        assert!(reviewed_preflight(
            &hyper::Method::HEAD,
            &format!("/{capability}/api/hello"),
            &capability
        ));
        for (method, target) in [
            (hyper::Method::GET, format!("/{capability}/api/hello")),
            (
                hyper::Method::HEAD,
                format!("/{capability}/api/hello?extra=1"),
            ),
            (
                hyper::Method::HEAD,
                format!("/{}/api/hello", "x".repeat(32)),
            ),
        ] {
            assert!(!reviewed_preflight(&method, &target, &capability));
        }
    }
    #[test]
    fn foreign_capability_audit_is_bounded_and_hashes_the_target() {
        let root = std::env::temp_dir().join(format!(
            "tempest-foreign-relay-audit-{}",
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        let audit_path = root.join("audit.jsonl");
        let state = State {
            upstream: "https://api.example.invalid/".parse().unwrap(),
            path_capability: "c".repeat(32),
            policy: policy(),
            audit: Mutex::new(
                fs::OpenOptions::new()
                    .append(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&audit_path)
                    .unwrap(),
            ),
            auth_header: reqwest::header::HeaderName::from_static("x-api-key"),
            auth_value: reqwest::header::HeaderValue::from_static("fixture"),
            client: reqwest::Client::new(),
            requests: AtomicU64::new(0),
            foreign_capability_requests: AtomicU64::new(0),
        };
        for index in 0..100 {
            audit_foreign_capability(&state, "DELETE", &format!("/foreign/{index}"));
        }
        let rows = fs::read_to_string(&audit_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), MAX_FOREIGN_CAPABILITY_AUDIT_ROWS as usize + 1);
        assert!(
            rows[..MAX_FOREIGN_CAPABILITY_AUDIT_ROWS as usize]
                .iter()
                .all(|row| row["reason"] == "foreign relay capability"
                    && row["method"] == "DELETE"
                    && row["path"].as_str().is_some_and(|path| path.len() == 71))
        );
        assert_eq!(
            rows.last().unwrap()["reason"],
            "foreign relay capability overflow"
        );
        assert_eq!(rows.last().unwrap()["path"], "bounded");
        assert_eq!(
            state.foreign_capability_requests.load(Ordering::SeqCst),
            100
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn exact_request_is_admitted_and_expansion_is_rejected() {
        let policy = policy();
        let valid=serde_json::to_vec(&json!({"model":"model-1","prompt":"secret","tools":[{"description":"fixed","input_schema":{"type":"object"},"name":"mcp__tempest__status","type":"function"}]})).unwrap();
        let admission = admit(&valid, "/v1/messages", &policy).unwrap();
        assert_eq!(admission.model, "model-1");
        assert_eq!(admission.tools, ["function:mcp__tempest__status"]);
        for invalid in [br#"{"model":"model-1","tools":[],"tools":[{"type":"function","name":"mcp__tempest__status","description":"fixed","input_schema":{"type":"object"}}]}"#.as_slice(),br#"{"model":"model-2","tools":[]}"#.as_slice(),br#"{"model":"model-1","previous_response_id":"old","tools":[]}"#.as_slice(),br#"{"model":"model-1","prompt":{"image_url":"https://example.invalid"},"tools":[]}"#.as_slice(),br#"{"model":"model-1","prompt":{"type":"file_url"},"tools":[]}"#.as_slice()]{assert!(admit(invalid,"/v1/messages",&policy).is_err())}
        assert!(admit(&valid, "/v1/files", &policy).is_err());

        let query_policy = validate_policy(json!({"schema_version":1,"acceptance_requests":1,
            "paths":["/v1/messages?beta=true"],"models":["model-1"],
            "top_level_fields":["model","prompt","tools"],
            "request_value_types":["text"],"request_headers":{},"maximum_requests":1,
            "mcp_catalog_source":{"version":"izanagi 0.2.7","host_os":"macos",
                "host_arch":"aarch64","executable_sha256":"a".repeat(64)},
            "tools":[{"type":"function","name":"mcp__tempest__status",
                "description":"fixed","input_schema":{"type":"object"}}]}))
        .unwrap();
        assert!(admit(&valid, "/v1/messages?beta=true", &query_policy).is_ok());
        assert!(admit(&valid, "/v1/messages?beta=false", &query_policy).is_err());
    }

    #[test]
    fn delivery_audit_distinguishes_unsent_uncertain_and_response_failure() {
        assert_eq!(delivery_state(false, Some("model mismatch")), "not_sent");
        assert_eq!(
            delivery_state(false, Some("upstream transport failed")),
            "request_outcome_unknown"
        );
        assert_eq!(
            delivery_state(false, Some("upstream response failed")),
            "request_sent_response_failed"
        );
        assert_eq!(delivery_state(true, None), "response_complete");
    }

    #[tokio::test]
    async fn redirect_is_replaced_before_client_can_follow_and_auth_is_replaced() {
        let root = std::env::temp_dir().join(format!(
            "tempest-native-model-relay-{}",
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let sink = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sink_address = sink.local_addr().unwrap();
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let auth_replaced = Arc::new(AtomicBool::new(false));
        let observed = auth_replaced.clone();
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |request: Request<Incoming>| {
                        observed.store(
                            request.headers()[hyper::header::AUTHORIZATION] == "fixture-value"
                                && !request.headers().contains_key("x-api-key")
                                && !request.headers().contains_key("x-agent-controlled")
                                && request.headers()["x-tempest-profile"] == "fixed",
                            Ordering::SeqCst,
                        );
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::FOUND)
                                    .header(
                                        hyper::header::LOCATION,
                                        format!("http://{sink_address}/stolen"),
                                    )
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            )
                        }
                    }),
                )
                .await
                .unwrap();
        });
        let audit_file = root.join("audit.jsonl");
        let audit = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&audit_file)
            .unwrap();
        let state = Arc::new(State {
            upstream: format!("http://{upstream_address}/").parse().unwrap(),
            path_capability: "x".repeat(32),
            policy: policy(),
            audit: Mutex::new(audit),
            auth_header: hyper::header::AUTHORIZATION,
            auth_value: "fixture-value".parse().unwrap(),
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .unwrap(),
            requests: AtomicU64::new(0),
            foreign_capability_requests: AtomicU64::new(0),
        });
        let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (stream, _) = relay.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |request| handle(request, state.clone())),
                )
                .await
                .unwrap();
        });
        let value = json!({"model":"model-1","prompt":"fixture","tools":[{
            "type":"function","name":"mcp__tempest__status","description":"fixed",
            "input_schema":{"type":"object"}}]});
        let result = reqwest::Client::new()
            .post(format!(
                "http://{relay_address}/{}{}",
                "x".repeat(32),
                "/v1/messages"
            ))
            .header(hyper::header::AUTHORIZATION, "agent-placeholder")
            .header("x-api-key", "agent-placeholder")
            .header("x-agent-controlled", "must-not-forward")
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&value).unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_GATEWAY);
        assert!(!result.headers().contains_key(hyper::header::LOCATION));
        assert!(auth_replaced.load(Ordering::SeqCst));
        upstream_task.abort();
        relay_task.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), sink.accept())
                .await
                .is_err()
        );
        let rows = fs::read_to_string(&audit_file).unwrap();
        let last: Value = serde_json::from_str(rows.lines().last().unwrap()).unwrap();
        assert_eq!(last["path"], "/v1/messages");
        assert_eq!(last["model"], "model-1");
        assert_eq!(last["upstream_status"], 302);
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn delayed_sse_is_streamed_and_completed_delivery_is_audited() {
        let root = std::env::temp_dir().join(format!(
            "tempest-model-relay-stream-{}",
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(|_: Request<Incoming>| async move {
                        let chunks = futures_util::stream::unfold(0, |step| async move {
                            match step {
                                0 => Some((
                                    Ok::<_, io::Error>(Frame::data(Bytes::from_static(b"first\n"))),
                                    1,
                                )),
                                1 => {
                                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                                    Some((Ok(Frame::data(Bytes::from_static(b"second\n"))), 2))
                                }
                                _ => None,
                            }
                        });
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .header(hyper::header::CONTENT_TYPE, "text/event-stream")
                                .body(StreamBody::new(chunks))
                                .unwrap(),
                        )
                    }),
                )
                .await
                .unwrap();
        });
        let audit_path = root.join("audit.jsonl");
        let relay = start_probe_relay(
            format!("http://{address}/base/").parse().unwrap(),
            "x".repeat(32),
            policy_value(),
            &audit_path,
        )
        .await
        .unwrap();
        let response = reqwest::Client::new()
            .post(format!("{}/v1/messages", relay.endpoint()))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&valid_request()).unwrap())
            .send()
            .await
            .unwrap();
        let mut chunks = response.bytes_stream();
        let first = tokio::time::timeout(std::time::Duration::from_millis(100), chunks.next())
            .await
            .expect("first chunk must not wait for upstream completion")
            .unwrap()
            .unwrap();
        assert_eq!(first, "first\n");
        let delayed_at = tokio::time::Instant::now();
        assert_eq!(chunks.next().await.unwrap().unwrap(), "second\n");
        assert!(delayed_at.elapsed() >= std::time::Duration::from_millis(200));
        assert!(chunks.next().await.is_none());
        upstream_task.abort();
        let rows = fs::read_to_string(audit_path).unwrap();
        assert!(rows.lines().any(|line| {
            let row: Value = serde_json::from_str(line).unwrap();
            row["forwarded"] == true && row["delivery_state"] == "response_complete"
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn response_stream_failure_is_distinct_from_an_unsent_request() {
        let root = std::env::temp_dir().join(format!(
            "tempest-model-relay-stream-failure-{}",
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(|_: Request<Incoming>| async move {
                        let chunks = futures_util::stream::unfold(0, |step| async move {
                            match step {
                                0 => Some((Ok(Frame::data(Bytes::from_static(b"partial\n"))), 1)),
                                1 => {
                                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                    Some((Err(io::Error::other("fixture stream failure")), 2))
                                }
                                _ => None,
                            }
                        });
                        Ok::<_, std::convert::Infallible>(
                            Response::builder().body(StreamBody::new(chunks)).unwrap(),
                        )
                    }),
                )
                .await;
        });
        let audit_path = root.join("audit.jsonl");
        let relay = start_probe_relay(
            format!("http://{address}/base/").parse().unwrap(),
            "x".repeat(32),
            policy_value(),
            &audit_path,
        )
        .await
        .unwrap();
        let response = reqwest::Client::new()
            .post(format!("{}/v1/messages", relay.endpoint()))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&valid_request()).unwrap())
            .send()
            .await
            .unwrap();
        assert!(response.bytes().await.is_err());
        upstream_task.await.unwrap();
        let rows = fs::read_to_string(audit_path).unwrap();
        assert!(rows.lines().any(|line| {
            let row: Value = serde_json::from_str(line).unwrap();
            row["forwarded"] == false
                && row["reason"] == "upstream response failed"
                && row["delivery_state"] == "request_sent_response_failed"
                && row["response_bytes"] == 8
                && row["response_sha256"] == format!("{:x}", Sha256::digest(b"partial\n"))
        }));
        fs::remove_dir_all(root).unwrap();
    }
}
