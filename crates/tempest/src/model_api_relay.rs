//! Native fail-closed relay for model-provider requests.
use crate::{capability_proof::parse_unique_value, host_io};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsString,
    fs::{self, File},
    io::{self, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex},
};

const MAX_REQUEST: usize = 16 * 1024 * 1024;
const MAX_RESPONSE: usize = 64 * 1024 * 1024;
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
    paths: Vec<String>,
    models: Vec<String>,
    top_level_fields: Vec<String>,
    request_value_types: Vec<String>,
    request_headers: BTreeMap<String, String>,
    tools: Vec<Value>,
}
struct ValidatedPolicy {
    paths: BTreeSet<String>,
    models: BTreeSet<String>,
    fields: BTreeSet<String>,
    request_value_types: BTreeSet<String>,
    request_headers: Vec<(reqwest::header::HeaderName, reqwest::header::HeaderValue)>,
    tools: Vec<(String, String)>,
}
struct Admission {
    model: String,
    tools: Vec<String>,
}
struct Options {
    upstream: reqwest::Url,
    path_capability: String,
    policy: ValidatedPolicy,
    audit: PathBuf,
    ready: PathBuf,
    auth_header: reqwest::header::HeaderName,
    auth_value: reqwest::header::HeaderValue,
    timeout: std::time::Duration,
}
struct State {
    upstream: reqwest::Url,
    path_capability: String,
    policy: ValidatedPolicy,
    audit: Mutex<File>,
    auth_header: reqwest::header::HeaderName,
    auth_value: reqwest::header::HeaderValue,
    client: reqwest::Client,
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
        || policy
            .paths
            .iter()
            .any(|path| !path.starts_with('/') || path.contains(['?', '#']))
        || policy.tools.is_empty()
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
fn response(status: StatusCode, reason: &str) -> Response<Full<Bytes>> {
    let bytes = Bytes::from(
        serde_json::to_vec(&json!({"error":"request_rejected","reason":reason})).unwrap(),
    );
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::CONTENT_LENGTH, bytes.len())
        .body(Full::new(bytes))
        .unwrap()
}
fn audit(
    state: &State,
    forwarded: bool,
    body: &[u8],
    reason: Option<&str>,
    path: &str,
    admission: Option<&Admission>,
    upstream_status: Option<u16>,
) -> io::Result<()> {
    let model = admission.map(|value| value.model.as_str());
    let tools = admission.map(|value| value.tools.as_slice()).unwrap_or(&[]);
    let event = json!({"forwarded":forwarded,"request_sha256":format!("{:x}",Sha256::digest(body)),
        "request_bytes":body.len(),"path":path,"model":model,"tools":tools,"reason":reason,
        "upstream_status":upstream_status});
    let mut file = state
        .audit
        .lock()
        .map_err(|_| invalid("relay audit lock poisoned"))?;
    serde_json::to_writer(&mut *file, &event)?;
    file.write_all(b"\n")?;
    file.sync_all()
}
async fn handle(
    request: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    if request.method() != hyper::Method::POST {
        return Ok(response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method is not allowed",
        ));
    }
    let prefix = format!("/{}", state.path_capability);
    let Some(suffix) = request
        .uri()
        .path()
        .strip_prefix(&prefix)
        .map(str::to_owned)
    else {
        return Ok(response(StatusCode::NOT_FOUND, "invalid relay capability"));
    };
    if !suffix.starts_with('/') || request.uri().query().is_some() {
        return Ok(response(StatusCode::NOT_FOUND, "invalid relay path"));
    }
    if request
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_none_or(|length| length > MAX_REQUEST)
    {
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
    let mut stream = upstream.bytes_stream();
    let mut output = Vec::new();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            let _ = audit(
                &state,
                false,
                &body,
                Some("upstream response failed"),
                &suffix,
                Some(&admission),
                Some(status.as_u16()),
            );
            return Ok(response(
                StatusCode::BAD_GATEWAY,
                "upstream response failed",
            ));
        };
        if output.len().saturating_add(chunk.len()) > MAX_RESPONSE {
            let _ = audit(
                &state,
                false,
                &body,
                Some("upstream response too large"),
                &suffix,
                Some(&admission),
                Some(status.as_u16()),
            );
            return Ok(response(
                StatusCode::BAD_GATEWAY,
                "upstream response too large",
            ));
        }
        output.extend_from_slice(&chunk);
    }
    if audit(
        &state,
        true,
        &body,
        None,
        &suffix,
        Some(&admission),
        Some(status.as_u16()),
    )
    .is_err()
    {
        return Ok(response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "relay audit completion unavailable",
        ));
    }
    let mut downstream = Response::builder().status(status);
    for (name, value) in &response_headers {
        let lower = name.as_str().to_ascii_lowercase();
        if !HOP_HEADERS.contains(&lower.as_str()) {
            downstream = downstream.header(name, value);
        }
    }
    downstream = downstream.header(hyper::header::CONTENT_LENGTH, output.len());
    Ok(downstream.body(Full::new(Bytes::from(output))).unwrap())
}

fn parse_options(args: &[OsString]) -> io::Result<Options> {
    if args.len() != 16 {
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
    if upstream.scheme() != "https"
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
    let auth_value = reqwest::header::HeaderValue::from_bytes(&private_bytes(
        Path::new(&required("--auth-file")?),
        8192,
    )?)
    .map_err(|error| invalid(error.to_string()))?;
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
    Ok(Options {
        upstream,
        path_capability,
        policy,
        audit: required("--audit")?.into(),
        ready: required("--ready-file")?.into(),
        auth_header,
        auth_value,
        timeout: std::time::Duration::from_secs(timeout),
    })
}
async fn serve(options: Options) -> io::Result<()> {
    let audit = fs::OpenOptions::new()
        .append(true)
        .create(true)
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
            .timeout(options.timeout)
            .build()
            .map_err(|error| invalid(error.to_string()))?,
    });
    let listener =
        tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let address = listener.local_addr()?;
    host_io::json_new(
        &options.ready,
        &json!({"schema_version":1,"host":"127.0.0.1","port":address.port(),
        "path_prefix":format!("/{}",options.path_capability)}),
    )?;
    loop {
        let (stream, _) = listener.accept().await?;
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
}
pub fn run(args: &[OsString]) -> ExitCode {
    const USAGE: &str = "Usage: tempest model-api-relay --upstream URL --capability-file FILE --policy-file FILE --audit FILE --ready-file FILE --auth-file FILE --auth-header NAME --timeout-seconds N";
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
    use std::sync::atomic::{AtomicBool, Ordering};
    fn policy() -> ValidatedPolicy {
        validate_policy(json!({"schema_version":1,"paths":["/v1/messages"],"models":["model-1"],
        "top_level_fields":["model","prompt","tools"],"request_value_types":["text"],
        "request_headers":{"content-type":"application/json","x-tempest-profile":"fixed"},
        "tools":[{"type":"function","name":"mcp__tempest__status","description":"fixed","input_schema":{"type":"object"}}]})).unwrap()
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
        upstream_task.await.unwrap();
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
}
