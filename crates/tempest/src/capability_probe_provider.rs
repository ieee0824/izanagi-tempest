//! Deterministic local model-provider peer for launcher capability probes.
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited, StreamBody, combinators::UnsyncBoxBody};
use hyper::{Request, Response, StatusCode, body::Frame, body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinHandle};

const LIMIT: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProbeAgent {
    Codex,
    ClaudeCode,
}

#[derive(Clone, Debug)]
pub(crate) struct ProbeRequest {
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
    pub tools: Vec<Value>,
    pub tool_outputs: Vec<Value>,
}

struct State {
    agent: ProbeAgent,
    model: String,
    host_canary: String,
    write_canary: String,
    control_socket: String,
    hmac_file: String,
    requests: Mutex<Vec<ProbeRequest>>,
    sse_event_delay: Option<Duration>,
}

pub(crate) struct ProbeProvider {
    endpoint: String,
    state: Arc<State>,
    task: JoinHandle<()>,
}

#[derive(Clone, Copy)]
pub(crate) struct ProbeIdentity<'a> {
    pub(crate) agent: ProbeAgent,
    pub(crate) model: &'a str,
    pub(crate) capability: &'a str,
}

impl Drop for ProbeProvider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl ProbeProvider {
    pub async fn start(
        identity: ProbeIdentity<'_>,
        host_canary: &Path,
        write_canary: &Path,
        control_socket: &Path,
        hmac_file: &Path,
    ) -> io::Result<Self> {
        Self::start_with_sse_delay(
            identity,
            host_canary,
            write_canary,
            control_socket,
            hmac_file,
            None,
        )
        .await
    }

    pub async fn start_with_sse_delay(
        identity: ProbeIdentity<'_>,
        host_canary: &Path,
        write_canary: &Path,
        control_socket: &Path,
        hmac_file: &Path,
        sse_event_delay: Option<Duration>,
    ) -> io::Result<Self> {
        let listener =
            TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
        let address = listener.local_addr()?;
        let state = Arc::new(State {
            agent: identity.agent,
            model: identity.model.to_owned(),
            host_canary: host_canary.to_string_lossy().into_owned(),
            write_canary: write_canary.to_string_lossy().into_owned(),
            control_socket: control_socket.to_string_lossy().into_owned(),
            hmac_file: hmac_file.to_string_lossy().into_owned(),
            requests: Mutex::new(Vec::new()),
            sse_event_delay,
        });
        let serving = state.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = serving.clone();
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
        Ok(Self {
            endpoint: format!(
                "http://127.0.0.1:{}/{}",
                address.port(),
                identity.capability
            ),
            state,
            task,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn requests(&self) -> io::Result<Vec<ProbeRequest>> {
        self.state
            .requests
            .lock()
            .map(|requests| requests.clone())
            .map_err(|_| io::Error::other("probe provider observation poisoned"))
    }
}

type ProviderBody = UnsyncBoxBody<Bytes, io::Error>;

fn response(status: StatusCode, body: Vec<u8>, content_type: &str) -> Response<ProviderBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .header(hyper::header::CONTENT_LENGTH, body.len())
        .body(
            Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .expect("fixed provider response")
}

fn sse_response(body: Vec<u8>, delay: Duration) -> Response<ProviderBody> {
    let text = String::from_utf8(body).expect("fixed SSE is UTF-8");
    let events = text
        .split_inclusive("\n\n")
        .map(|event| Bytes::copy_from_slice(event.as_bytes()))
        .collect::<Vec<_>>();
    let mut chunks = Vec::with_capacity(events.len() + 1);
    for (index, event) in events.into_iter().enumerate() {
        chunks.push((Duration::ZERO, event));
        if index == 0 {
            chunks.push((delay, Bytes::from_static(b": heartbeat\n\n")));
        }
    }
    let stream = futures_util::stream::unfold(chunks.into_iter(), |mut chunks| async move {
        let (delay, chunk) = chunks.next()?;
        tokio::time::sleep(delay).await;
        Some((Ok::<_, io::Error>(Frame::data(chunk)), chunks))
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/event-stream")
        .body(StreamBody::new(stream).boxed_unsync())
        .expect("fixed streaming provider response")
}

async fn handle(
    request: Request<Incoming>,
    state: Arc<State>,
) -> Result<Response<ProviderBody>, hyper::Error> {
    if request.method() != hyper::Method::POST {
        return Ok(response(
            StatusCode::METHOD_NOT_ALLOWED,
            b"method not allowed".to_vec(),
            "text/plain",
        ));
    }
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| request.uri().path())
        .to_owned();
    let headers = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    let body = match Limited::new(request.into_body(), LIMIT).collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return Ok(response(
                StatusCode::PAYLOAD_TOO_LARGE,
                b"request too large".to_vec(),
                "text/plain",
            ));
        }
    };
    let value = match crate::capability_proof::parse_unique_value(&body) {
        Ok(value) => value,
        Err(_) => {
            return Ok(response(
                StatusCode::BAD_REQUEST,
                b"invalid JSON".to_vec(),
                "text/plain",
            ));
        }
    };
    let tools = value
        .get("tools")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if value.get("model").and_then(Value::as_str) != Some(state.model.as_str()) {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            b"unexpected model".to_vec(),
            "text/plain",
        ));
    }
    let tool_outputs = match state.agent {
        ProbeAgent::Codex => value
            .get("input")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|item| item["type"] == "function_call_output")
            .cloned()
            .collect(),
        ProbeAgent::ClaudeCode => value
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|message| message.get("content").and_then(Value::as_array))
            .flatten()
            .filter(|item| item["type"] == "tool_result")
            .cloned()
            .collect(),
    };
    let index = {
        let mut requests = match state.requests.lock() {
            Ok(requests) => requests,
            Err(_) => {
                return Ok(response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    b"observation unavailable".to_vec(),
                    "text/plain",
                ));
            }
        };
        let index = requests.len();
        requests.push(ProbeRequest {
            path,
            headers,
            body: value,
            tools: tools.clone(),
            tool_outputs,
        });
        index
    };
    let body = provider_response(&state, index, &tools);
    if state.agent == ProbeAgent::ClaudeCode && !claude_response_model_matches(&body, &state.model)
    {
        return Ok(response(
            StatusCode::INTERNAL_SERVER_ERROR,
            b"provider response model mismatch".to_vec(),
            "text/plain",
        ));
    }
    Ok(match state.sse_event_delay {
        Some(delay) if index == 0 => sse_response(body, delay),
        None => response(StatusCode::OK, body, "text/event-stream"),
        Some(_) => response(StatusCode::OK, body, "text/event-stream"),
    })
}

fn attempts(state: &State, tools: &[Value]) -> Vec<(String, Value, Option<String>)> {
    let mut attempts = match state.agent {
        ProbeAgent::Codex => vec![
            (
                "exec_command".into(),
                json!({"cmd":format!("cat {}", state.host_canary)}),
                None,
            ),
            (
                "apply_patch".into(),
                json!({"patch":format!("*** Begin Patch\n*** Add File: {}\n+probe\n*** End Patch",state.write_canary)}),
                None,
            ),
            ("view_image".into(), json!({"path":state.host_canary}), None),
            (
                "exec_command".into(),
                json!({"cmd":format!("cat {}",state.control_socket)}),
                None,
            ),
            (
                "exec_command".into(),
                json!({"cmd":format!("cat {}",state.hmac_file)}),
                None,
            ),
            (
                "read_mcp_resource".into(),
                json!({"server":"tempest","uri":format!("file://{}",state.host_canary)}),
                None,
            ),
        ],
        ProbeAgent::ClaudeCode => vec![
            (
                "Bash".into(),
                json!({"command":format!("cat {}", state.host_canary)}),
                None,
            ),
            (
                "Write".into(),
                json!({"file_path":state.write_canary,"content":"probe"}),
                None,
            ),
            ("Read".into(), json!({"file_path":state.host_canary}), None),
            (
                "Read".into(),
                json!({"file_path":state.control_socket}),
                None,
            ),
            ("Read".into(), json!({"file_path":state.hmac_file}), None),
            (
                "mcp__other__read".into(),
                json!({"file_path":state.host_canary}),
                None,
            ),
        ],
    };
    let namespace = tools
        .iter()
        .find(|tool| tool["type"] == "namespace" && tool["name"] == "mcp__tempest");
    let flat = tools
        .iter()
        .find(|tool| tool["name"] == "mcp__tempest__sandbox_status");
    if namespace.is_some() {
        attempts.push((
            "sandbox_status".into(),
            json!({}),
            Some("mcp__tempest".into()),
        ));
    } else if flat.is_some() {
        attempts.push(("mcp__tempest__sandbox_status".into(), json!({}), None));
    } else {
        attempts.push(("missing_allowed_mcp".into(), json!({}), None));
    }
    attempts
}

fn provider_response(state: &State, index: usize, tools: &[Value]) -> Vec<u8> {
    let attempts = attempts(state, tools);
    match state.agent {
        ProbeAgent::Codex => codex_response(index, attempts.get(index)),
        ProbeAgent::ClaudeCode => claude_response(index, attempts.get(index), &state.model),
    }
}

fn codex_response(index: usize, attempt: Option<&(String, Value, Option<String>)>) -> Vec<u8> {
    let item = attempt.map(|(name, arguments, namespace)| {
        let mut item = json!({"type":"function_call","id":format!("fc_{index}"),
            "call_id":format!("call_{index}"),"name":name,
            "arguments":serde_json::to_string(arguments).expect("fixed arguments")});
        if let Some(namespace) = namespace {
            item["namespace"] = namespace.clone().into();
        }
        item
    });
    let output = item.clone().into_iter().collect::<Vec<_>>();
    let mut events = vec![json!({"type":"response.created","response":{
        "id":format!("resp_{index}"),"object":"response","status":"in_progress","output":[]}})];
    if let Some(item) = item {
        events.push(json!({"type":"response.output_item.added","output_index":0,"item":item}));
        events.push(json!({"type":"response.output_item.done","output_index":0,"item":item}));
    }
    let final_output = if output.is_empty() {
        vec![
            json!({"type":"message","id":format!("msg_{index}"),"role":"assistant",
            "content":[{"type":"output_text","text":"Capability probe complete.","annotations":[]}]}),
        ]
    } else {
        output
    };
    events.push(json!({"type":"response.completed","response":{
        "id":format!("resp_{index}"),"object":"response","status":"completed",
        "output":final_output,"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}));
    events
        .into_iter()
        .map(|event| format!("data: {}\n\n", serde_json::to_string(&event).unwrap()))
        .collect::<String>()
        .into_bytes()
}

fn claude_response(
    index: usize,
    attempt: Option<&(String, Value, Option<String>)>,
    model: &str,
) -> Vec<u8> {
    let message = json!({"id":format!("msg_{index}"),"type":"message","role":"assistant",
        "model":model,"content":[],"stop_reason":null,
        "usage":{"input_tokens":1,"output_tokens":1}});
    let (block, delta, reason) = match attempt {
        Some((name, arguments, _)) => (
            json!({"type":"tool_use","id":format!("call_{index}"),"name":name,"input":{}}),
            json!({"type":"input_json_delta","partial_json":serde_json::to_string(arguments).unwrap()}),
            "tool_use",
        ),
        None => (
            json!({"type":"text","text":""}),
            json!({"type":"text_delta","text":"Capability probe complete."}),
            "end_turn",
        ),
    };
    let events = [
        (
            "message_start",
            json!({"type":"message_start","message":message}),
        ),
        (
            "content_block_start",
            json!({"type":"content_block_start","index":0,"content_block":block}),
        ),
        (
            "content_block_delta",
            json!({"type":"content_block_delta","index":0,"delta":delta}),
        ),
        (
            "content_block_stop",
            json!({"type":"content_block_stop","index":0}),
        ),
        (
            "message_delta",
            json!({"type":"message_delta","delta":{"stop_reason":reason,
            "stop_sequence":null},"usage":{"output_tokens":1}}),
        ),
        ("message_stop", json!({"type":"message_stop"})),
    ];
    events
        .into_iter()
        .map(|(name, event)| {
            format!(
                "event: {name}\ndata: {}\n\n",
                serde_json::to_string(&event).unwrap()
            )
        })
        .collect::<String>()
        .into_bytes()
}

fn claude_response_model_matches(body: &[u8], expected: &str) -> bool {
    let Some(first_event) = body.split(|byte| *byte == b'\n').take(2).last() else {
        return false;
    };
    let Some(payload) = first_event.strip_prefix(b"data: ") else {
        return false;
    };
    serde_json::from_slice::<Value>(payload)
        .ok()
        .and_then(|event| {
            event
                .pointer("/message/model")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .is_some_and(|model| model == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_sequences_finish_after_host_and_allowed_mcp_attempts() {
        let state = State {
            agent: ProbeAgent::Codex,
            model: "model-fixed".into(),
            host_canary: "/host/read".into(),
            write_canary: "/host/write".into(),
            control_socket: "/host/control".into(),
            hmac_file: "/host/hmac".into(),
            requests: Mutex::new(Vec::new()),
            sse_event_delay: None,
        };
        let tools = vec![json!({"type":"namespace","name":"mcp__tempest"})];
        let sequence = attempts(&state, &tools);
        assert_eq!(sequence.len(), 7);
        assert_eq!(sequence[6].0, "sandbox_status");
        assert_eq!(sequence[6].2.as_deref(), Some("mcp__tempest"));
        let final_response = String::from_utf8(provider_response(&state, 7, &tools)).unwrap();
        assert!(final_response.contains("Capability probe complete."));
        assert!(!final_response.contains("function_call"));
    }

    #[test]
    fn claude_response_is_bound_to_the_requested_model() {
        let response = claude_response(0, None, "claude-sonnet-5-5");
        assert!(claude_response_model_matches(
            &response,
            "claude-sonnet-5-5"
        ));
        assert!(!claude_response_model_matches(
            &response,
            "claude-haiku-5-5"
        ));
    }
}
