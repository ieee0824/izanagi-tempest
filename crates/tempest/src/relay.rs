//! Bounded JSON-lines relay for the pinned sequential Izanagi MCP server.
//! It drains RPCs, never certifies that guest descendants have exited.
use crate::admission::{Admission, CloseReason, DrainReceipt, RequestId};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    io,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::watch,
};

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub max_calls: u64,
    pub timeout: Duration,
    pub drain_timeout: Duration,
    pub io_timeout: Duration,
    pub max_agent_frame: usize,
    pub max_upstream_frame: usize,
    pub max_queue_bytes: usize,
    pub max_queue_frames: usize,
    pub max_policy_rejections: u64,
}
impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            max_calls: 50,
            timeout: Duration::from_secs(900),
            drain_timeout: Duration::from_secs(330),
            io_timeout: Duration::from_secs(5),
            max_agent_frame: 4 * 1024 * 1024,
            max_upstream_frame: 8 * 1024 * 1024,
            max_queue_bytes: 8 * 1024 * 1024,
            max_queue_frames: 32,
            max_policy_rejections: 32,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct RelayOutcome {
    pub drain: Option<DrainReceipt>,
    pub admitted_calls: u64,
    pub completed_calls: u64,
    pub pending_calls: usize,
    pub uncertain: bool,
    pub queue_rejections: u64,
    pub policy_rejections: u64,
    pub unforwarded_attempts: Vec<u64>,
}
struct Queued {
    value: Value,
    bytes: usize,
    attempt: Option<u64>,
}
struct Inflight {
    request: Value,
    id: RequestId,
    call: bool,
    sequence: Option<u64>,
    attempt: Option<u64>,
}

/// Cancellation-safe: consumed bytes remain in the caller-owned buffer.
pub(crate) async fn frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    limit: usize,
) -> io::Result<Option<Vec<u8>>> {
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if buffer.is_empty() {
                Ok(None)
            } else {
                Ok(Some(std::mem::take(buffer)))
            };
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let length = newline.map_or(available.len(), |n| n + 1);
        if length > limit.saturating_sub(buffer.len()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP frame exceeds limit",
            ));
        }
        buffer.extend_from_slice(&available[..length]);
        reader.consume(length);
        if newline.is_some() {
            return Ok(Some(std::mem::take(buffer)));
        }
    }
}
async fn write<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &Value,
    timeout: Duration,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    tokio::time::timeout(timeout, async {
        writer.write_all(&bytes).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MCP write deadline"))?
}
async fn audit<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: &str,
    fields: Value,
    timeout: Duration,
) -> io::Result<()> {
    let ts_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("clock precedes Unix epoch"))?
        .as_nanos();
    write(
        writer,
        &json!({"event":kind,"ts_ns":ts_ns,"data":fields}),
        timeout,
    )
    .await
}
fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn is_call(value: &Value) -> bool {
    value.get("method").and_then(Value::as_str) == Some("tools/call")
}
fn allowed_agent_request(value: &Value) -> bool {
    let method = value.get("method").and_then(Value::as_str);
    if value.get("id").is_some() {
        matches!(method, Some("initialize" | "tools/list" | "tools/call"))
    } else {
        method == Some("notifications/initialized")
    }
}
fn valid_request(value: &Value) -> bool {
    value.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && value.get("method").is_some_and(Value::is_string)
        && value.get("result").is_none()
        && value.get("error").is_none()
        && value
            .get("id")
            .is_none_or(|id| RequestId::parse(id).is_some())
}
fn valid_guest_command(request: &Value) -> bool {
    let Some(params) = request.get("params") else {
        return false;
    };
    let name = params.get("name").and_then(Value::as_str);
    if !matches!(name, Some("sandbox_exec" | "sandbox_shell")) {
        return false;
    }
    let Some(args) = params.get("arguments").filter(|v| v.is_object()) else {
        return false;
    };
    if !args
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty())
    {
        return false;
    }
    name == Some("sandbox_shell")
        || match args.get("args") {
            None | Some(Value::Null) => true,
            Some(Value::Array(args)) => args.iter().all(Value::is_string),
            _ => false,
        }
}
/// A conservative interpretation tied to the pinned tools.rs formatter.
/// User output can imitate an exec-failed prefix: ambiguity remains uncertain.
fn unverified_execution(request: &Value, response: &Value) -> bool {
    if !valid_guest_command(request) {
        return false;
    }
    let Some(result) = response.get("result") else {
        return true;
    };
    let Some(content) = result.get("content").and_then(Value::as_array) else {
        return true;
    };
    if content.len() != 1 || content[0].get("type").and_then(Value::as_str) != Some("text") {
        return true;
    }
    let Some(text) = content[0].get("text").and_then(Value::as_str) else {
        return true;
    };
    match result.get("isError") {
        None | Some(Value::Bool(false)) => false,
        Some(Value::Bool(true)) if text.starts_with("exec failed:") => true,
        Some(Value::Bool(true)) => !text
            .rsplit_once("(exit code: ")
            .and_then(|(_, n)| n.strip_suffix(')'))
            .is_some_and(|n| n.parse::<i32>().is_ok()),
        _ => true,
    }
}
async fn deliver<W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &Value,
    agent_open: &mut bool,
    gate: &mut Admission,
    timeout: Duration,
) {
    if *agent_open && write(writer, value, timeout).await.is_err() {
        *agent_open = false;
        gate.close(CloseReason::Cancelled, Instant::now());
    }
}

fn observe_close(gate: &mut Admission, close: &mut watch::Receiver<Option<CloseReason>>) {
    if close.has_changed().is_err() {
        gate.close(CloseReason::Cancelled, Instant::now());
    } else {
        let reason = *close.borrow_and_update();
        if let Some(reason) = reason {
            gate.close(reason, Instant::now());
        }
    }
}

/// The owner must preserve upstream lifetime while this function drains, even
/// after the agent disconnects. Any Err or uncertain outcome forbids normal export.
#[allow(clippy::too_many_arguments)]
pub async fn relay<AR, AW, UR, UW, LW>(
    agent_read: AR,
    mut agent_write: AW,
    upstream_read: UR,
    mut upstream_write: UW,
    mut log: LW,
    config: RelayConfig,
    mut close: watch::Receiver<Option<CloseReason>>,
) -> io::Result<RelayOutcome>
where
    AR: AsyncRead + Unpin,
    AW: AsyncWrite + Unpin,
    UR: AsyncRead + Unpin,
    UW: AsyncWrite + Unpin,
    LW: AsyncWrite + Unpin,
{
    let mut agent_read = BufReader::new(agent_read);
    let mut upstream_read = BufReader::new(upstream_read);
    let mut agent_buffer = Vec::new();
    let mut upstream_buffer = Vec::new();
    let mut queue: VecDeque<Queued> = VecDeque::new();
    let mut queued_bytes = 0usize;
    let mut active: Option<Inflight> = None;
    let mut gate = Admission::new(config.max_calls, config.timeout, Instant::now());
    let mut agent_read_open = true;
    let mut agent_write_open = true;
    let mut control_open = true;
    let mut drain_started = None;
    let mut attempts = 0u64;
    let mut queue_rejections = 0u64;
    let mut policy_rejections = 0u64;
    let mut timer = tokio::time::interval(Duration::from_millis(10));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        observe_close(&mut gate, &mut close);
        gate.tick(Instant::now());
        if gate.closed_reason().is_some() {
            let since = drain_started.get_or_insert_with(Instant::now);
            if active.is_some() && since.elapsed() >= config.drain_timeout {
                gate.upstream_lost(Instant::now());
                audit(
                    &mut log,
                    "drain_timeout",
                    json!({"pending_calls":gate.pending_calls()}),
                    config.io_timeout,
                )
                .await?;
                break;
            }
        }
        if active.is_none() {
            while let Some(queued) = queue.pop_front() {
                observe_close(&mut gate, &mut close);
                queued_bytes -= queued.bytes;
                let request = queued.value;
                let id_value = request.get("id").cloned();
                let id = id_value.as_ref().and_then(RequestId::parse);
                let call = is_call(&request);
                // Do potentially blocking audit I/O before authorizing a send.
                // A close/timeout during logging must not authorize stale work.
                audit(
                    &mut log,
                    "dispatch_ready",
                    json!({"attempt":queued.attempt,"request":request}),
                    config.io_timeout,
                )
                .await?;
                observe_close(&mut gate, &mut close);
                gate.tick(Instant::now());
                let sequence = if call {
                    match gate.admit(
                        id.clone().expect("validated tool request ID"),
                        Instant::now(),
                    ) {
                        Ok(sequence) => Some(sequence),
                        Err(reason) => {
                            audit(&mut log, "rejected", json!({"attempt":queued.attempt,"request":request,"reason":format!("{reason:?}")}), config.io_timeout).await?;
                            deliver(
                                &mut agent_write,
                                &error(id_value.unwrap(), -32001, "tool admission closed"),
                                &mut agent_write_open,
                                &mut gate,
                                config.io_timeout,
                            )
                            .await;
                            continue;
                        }
                    }
                } else if gate.closed_reason().is_some() {
                    audit(
                        &mut log,
                        "not_forwarded",
                        json!({"request":request,"reason":"admission_closed"}),
                        config.io_timeout,
                    )
                    .await?;
                    if let Some(id) = id_value {
                        deliver(
                            &mut agent_write,
                            &error(id, -32001, "admission closed"),
                            &mut agent_write_open,
                            &mut gate,
                            config.io_timeout,
                        )
                        .await;
                    }
                    continue;
                } else {
                    None
                };
                if write(&mut upstream_write, &request, config.io_timeout)
                    .await
                    .is_err()
                {
                    gate.upstream_lost(Instant::now());
                    audit(
                        &mut log,
                        "forward_uncertain",
                        json!({"attempt":queued.attempt,"sequence":sequence}),
                        config.io_timeout,
                    )
                    .await?;
                    break;
                }
                audit(
                    &mut log,
                    "forwarded",
                    json!({"attempt":queued.attempt,"sequence":sequence,"id":id_value}),
                    config.io_timeout,
                )
                .await?;
                if let Some(id) = id {
                    active = Some(Inflight {
                        request,
                        id,
                        call,
                        sequence,
                        attempt: queued.attempt,
                    });
                    break;
                }
            }
        }
        if !agent_read_open && active.is_none() && queue.is_empty() {
            gate.close(CloseReason::AgentFinished, Instant::now());
        }
        if gate.is_uncertain() {
            break;
        }
        if gate.closed_reason().is_some() && active.is_none() && queue.is_empty() {
            break;
        }
        tokio::select! {
            _ = timer.tick() => {},
            changed = close.changed(), if control_open => {
                if changed.is_err() {
                    control_open = false;
                    gate.close(CloseReason::Cancelled, Instant::now());
                } else if let Some(reason) = *close.borrow_and_update() {
                    gate.close(reason, Instant::now());
                }
            },
            incoming = frame(&mut agent_read, &mut agent_buffer, config.max_agent_frame), if agent_read_open => {
                let bytes = match incoming {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => { agent_read_open = false; continue; },
                    Err(_) => {
                        agent_read_open = false; gate.close(CloseReason::Cancelled, Instant::now());
                        audit(&mut log, "agent_frame_error", json!({"reason":"read_or_size_failure"}), config.io_timeout).await?;
                        continue;
                    }
                };
                if bytes.iter().all(u8::is_ascii_whitespace) { continue; }
                let value: Value = match serde_json::from_slice(&bytes) {
                    Ok(value) => value,
                    Err(_) => {
                        audit(&mut log, "agent_protocol_error", json!({"reason":"invalid_json","frame_bytes":bytes.len()}), config.io_timeout).await?;
                        deliver(&mut agent_write, &error(Value::Null, -32700, "invalid JSON"), &mut agent_write_open, &mut gate, config.io_timeout).await;
                        continue;
                    }
                };
                if !valid_request(&value) || (is_call(&value) && value.get("id").is_none()) {
                    audit(&mut log, "agent_protocol_error", json!({"reason":"invalid_request","frame_bytes":bytes.len()}), config.io_timeout).await?;
                    deliver(&mut agent_write, &error(value.get("id").filter(|id|RequestId::parse(id).is_some()).cloned().unwrap_or(Value::Null), -32600, "invalid MCP request"), &mut agent_write_open, &mut gate, config.io_timeout).await;
                    continue;
                }
                if !allowed_agent_request(&value) {
                    policy_rejections = policy_rejections
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("policy rejection counter overflow"))?;
                    audit(
                        &mut log,
                        "policy_rejected",
                        json!({"method":value["method"],"has_id":value.get("id").is_some(),
                            "rejection":policy_rejections,"limit":config.max_policy_rejections}),
                        config.io_timeout,
                    )
                    .await?;
                    if let Some(id) = value.get("id") {
                        deliver(
                            &mut agent_write,
                            &error(id.clone(), -32601, "MCP method not allowed"),
                            &mut agent_write_open,
                            &mut gate,
                            config.io_timeout,
                        )
                        .await;
                    }
                    if policy_rejections >= config.max_policy_rejections {
                        agent_read_open = false;
                        gate.close(CloseReason::Cancelled, Instant::now());
                    }
                    continue;
                }
                let attempt = if is_call(&value) {
                    attempts = attempts.checked_add(1).ok_or_else(|| io::Error::other("attempt counter overflow"))?;
                    Some(attempts)
                } else { None };
                let duplicate = value.get("id").is_some_and(|id| {
                    active.as_ref().is_some_and(|a| Some(&a.id) == RequestId::parse(id).as_ref())
                    || queue.iter().any(|q| q.value.get("id") == Some(id))
                });
                let full = queue.len() >= config.max_queue_frames || bytes.len() > config.max_queue_bytes.saturating_sub(queued_bytes);
                if duplicate || full {
                    queue_rejections = queue_rejections.saturating_add(1);
                    audit(&mut log, "queue_rejected", json!({"attempt":attempt,"request":value,"reason":if duplicate {"duplicate_id"} else {"queue_limit"}}), config.io_timeout).await?;
                    if let Some(id) = value.get("id") {
                        deliver(&mut agent_write, &error(id.clone(), -32002, "request cannot be queued"), &mut agent_write_open, &mut gate, config.io_timeout).await;
                    }
                    continue;
                }
                audit(&mut log, "queued", json!({"attempt":attempt,"request":value}), config.io_timeout).await?;
                queued_bytes += bytes.len();
                queue.push_back(Queued { value, bytes:bytes.len(), attempt });
            },
            incoming = frame(&mut upstream_read, &mut upstream_buffer, config.max_upstream_frame) => {
                let bytes = match incoming {
                    Ok(Some(bytes)) => bytes,
                    _ => {
                        gate.upstream_lost(Instant::now());
                        audit(&mut log, "upstream_error", json!({"reason":"read_or_eof","buffered_bytes":upstream_buffer.len()}), config.io_timeout).await?;
                        break;
                    }
                };
                if bytes.iter().all(u8::is_ascii_whitespace) { continue; }
                let value: Value = match serde_json::from_slice(&bytes) {
                    Ok(value) => value,
                    Err(_) => {
                        gate.upstream_lost(Instant::now());
                        audit(&mut log, "upstream_error", json!({"reason":"invalid_json","frame_bytes":bytes.len()}), config.io_timeout).await?;
                        break;
                    }
                };
                if value.get("method").is_some() {
                    // The pinned server sends no server requests or notifications.
                    gate.upstream_lost(Instant::now());
                    audit(&mut log, "upstream_error", json!({"reason":"unexpected_server_request_or_notification"}), config.io_timeout).await?;
                    break;
                }
                let Some(inflight) = active.take() else {
                    gate.upstream_lost(Instant::now());
                    audit(&mut log, "upstream_error", json!({"reason":"unsolicited_response","response":value}), config.io_timeout).await?;
                    break;
                };
                if value.get("id").and_then(RequestId::parse).as_ref() != Some(&inflight.id)
                    || value.get("result").is_some() == value.get("error").is_some()
                    || value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                    // Keep the tool pending: a mismatched frame is not its completion.
                    gate.upstream_lost(Instant::now());
                    audit(&mut log, "upstream_error", json!({"reason":"response_mismatch","response":value}), config.io_timeout).await?;
                    break;
                }
                if inflight.call { gate.complete(&inflight.id); }
                let unverified = unverified_execution(&inflight.request, &value);
                audit(&mut log, "response", json!({"attempt":inflight.attempt,"sequence":inflight.sequence,"response":value,"guest_completion_uncertain":unverified}), config.io_timeout).await?;
                deliver(&mut agent_write, &value, &mut agent_write_open, &mut gate, config.io_timeout).await;
                if unverified { gate.unverified_execution(Instant::now()); }
            },
        }
    }
    let outcome = RelayOutcome {
        drain: gate.receipt(),
        admitted_calls: gate.admitted_calls(),
        completed_calls: gate.completed_calls(),
        pending_calls: gate.pending_calls(),
        uncertain: gate.is_uncertain(),
        queue_rejections,
        policy_rejections,
        unforwarded_attempts: queue.iter().filter_map(|q| q.attempt).collect(),
    };
    audit(
        &mut log,
        "relay_closed",
        serde_json::to_value(&outcome)?,
        config.io_timeout,
    )
    .await?;
    Ok(outcome)
}
