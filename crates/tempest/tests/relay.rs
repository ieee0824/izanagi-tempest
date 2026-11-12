use serde_json::{Value, json};
use std::{io, time::Duration};
use tempest::{
    admission::CloseReason,
    relay::{RelayConfig, RelayOutcome, relay},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream, split},
    sync::watch,
    task::JoinHandle,
};

type Running = (
    DuplexStream,
    DuplexStream,
    DuplexStream,
    watch::Sender<Option<CloseReason>>,
    JoinHandle<io::Result<RelayOutcome>>,
);
fn start(config: RelayConfig) -> Running {
    let (agent, local) = tokio::io::duplex(65536);
    let (upstream, remote) = tokio::io::duplex(65536);
    let (log, audit) = tokio::io::duplex(65536);
    let (ar, aw) = split(local);
    let (ur, uw) = split(remote);
    let (close, rx) = watch::channel(None);
    let task = tokio::spawn(relay(ar, aw, ur, uw, log, config, rx));
    (agent, upstream, audit, close, task)
}
fn call(id: u64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"sandbox_exec","arguments":{"command":"/bin/echo","args":["hello"]}}})
}
fn response(id: u64, text: &str, error: bool) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":text}],"isError":error}})
}
async fn send<W: AsyncWriteExt + Unpin>(stream: &mut W, value: &Value) {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).await.unwrap();
    stream.flush().await.unwrap();
}
async fn read<R: AsyncBufReadExt + Unpin>(stream: &mut R) -> Value {
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(3), stream.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert!(n > 0, "unexpected EOF");
    serde_json::from_str(&line).unwrap()
}
async fn finish(task: JoinHandle<io::Result<RelayOutcome>>) -> RelayOutcome {
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}
async fn events(mut audit: DuplexStream) -> Vec<Value> {
    let mut bytes = Vec::new();
    audit.read_to_end(&mut bytes).await.unwrap();
    String::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}

#[tokio::test]
async fn metadata_is_unchanged_and_excess_tool_call_never_reaches_upstream() {
    let (agent, upstream, audit, _close, task) = start(RelayConfig {
        max_calls: 1,
        ..Default::default()
    });
    let (ar, mut aw) = split(agent);
    let mut ar = BufReader::new(ar);
    let (ur, mut uw) = split(upstream);
    let mut ur = BufReader::new(ur);
    let tools = json!({"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"sandbox_exec","description":"ORIGINAL DESCRIPTION","inputSchema":{"type":"object"}}]}});
    let expected_tools = tools.clone();
    let mock = tokio::spawn(async move {
        assert_eq!(read(&mut ur).await["method"], "initialize");
        send(
            &mut uw,
            &json!({"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05"}}),
        )
        .await;
        assert_eq!(read(&mut ur).await["method"], "tools/list");
        send(&mut uw, &tools).await;
        assert_eq!(read(&mut ur).await, call(3));
        send(&mut uw, &response(3, "hello", false)).await;
        let mut remaining = String::new();
        assert_eq!(ur.read_line(&mut remaining).await.unwrap(), 0);
    });
    send(
        &mut aw,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
    )
    .await;
    send(
        &mut aw,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    send(&mut aw, &call(3)).await;
    send(&mut aw, &call(4)).await;
    aw.shutdown().await.unwrap();
    assert_eq!(read(&mut ar).await["id"], 1);
    assert_eq!(read(&mut ar).await, expected_tools);
    assert_eq!(read(&mut ar).await, response(3, "hello", false));
    assert_eq!(read(&mut ar).await["error"]["code"], -32001);
    let outcome = finish(task).await;
    mock.await.unwrap();
    assert_eq!(outcome.admitted_calls, 1);
    assert_eq!(outcome.completed_calls, 1);
    assert!(outcome.drain.is_some() && !outcome.uncertain);
    let log = events(audit).await;
    assert_eq!(
        log.iter()
            .filter(|v| v["event"] == "forwarded" && v["data"]["sequence"] == 1)
            .count(),
        1
    );
    assert!(
        log.iter()
            .any(|v| v["event"] == "rejected" && v["data"]["request"]["id"] == 4)
    );
}

#[tokio::test]
async fn disconnecting_agent_does_not_discard_pending_response() {
    let (mut agent, upstream, audit, close, task) = start(Default::default());
    let (ur, mut uw) = split(upstream);
    let mut ur = BufReader::new(ur);
    send(&mut agent, &call(1)).await;
    assert_eq!(read(&mut ur).await, call(1));
    close.send(Some(CloseReason::Cancelled)).unwrap();
    drop(agent);
    send(&mut uw, &response(1, "done", false)).await;
    let outcome = finish(task).await;
    assert_eq!(outcome.completed_calls, 1);
    assert_eq!(outcome.pending_calls, 0);
    assert!(outcome.drain.is_some());
    assert!(events(audit).await.iter().any(|v| v["event"] == "response"));
}

#[tokio::test]
async fn losing_upstream_keeps_sent_request_uncertain() {
    let (mut agent, upstream, audit, _close, task) = start(Default::default());
    let mut upstream = BufReader::new(upstream);
    send(&mut agent, &call(1)).await;
    assert_eq!(read(&mut upstream).await, call(1));
    drop(upstream);
    let outcome = finish(task).await;
    assert!(outcome.uncertain && outcome.drain.is_none());
    assert_eq!(outcome.pending_calls, 1);
    let log = events(audit).await;
    assert!(log.iter().any(|v| v["event"] == "forwarded"));
    assert!(!log.iter().any(|v| v["event"] == "response"));
}

#[tokio::test]
async fn explicit_stop_rejects_queued_work_but_drains_the_sent_call() {
    let (agent, upstream, _audit, close, task) = start(Default::default());
    let (ar, mut aw) = split(agent);
    let mut ar = BufReader::new(ar);
    let (ur, mut uw) = split(upstream);
    let mut ur = BufReader::new(ur);
    send(&mut aw, &call(1)).await;
    assert_eq!(read(&mut ur).await, call(1));
    send(&mut aw, &call(2)).await;
    close.send(Some(CloseReason::Timeout)).unwrap();
    send(&mut uw, &response(1, "done", false)).await;
    assert_eq!(read(&mut ar).await["id"], 1);
    // If the close was observed before the second input was read, it is simply
    // left unread; in either case it can never reach the upstream server.
    let outcome = finish(task).await;
    assert_eq!(outcome.admitted_calls, 1);
    assert!(outcome.drain.is_some());
    let mut line = String::new();
    assert_eq!(ur.read_line(&mut line).await.unwrap(), 0);
}

#[tokio::test]
async fn exec_transport_error_is_not_a_guest_completion_proof() {
    let (mut agent, upstream, _audit, _close, task) = start(Default::default());
    let (ur, mut uw) = split(upstream);
    let mut ur = BufReader::new(ur);
    send(&mut agent, &call(1)).await;
    read(&mut ur).await;
    send(
        &mut uw,
        &response(1, "exec failed: agent exec timeout", true),
    )
    .await;
    let outcome = finish(task).await;
    assert_eq!(outcome.completed_calls, 1);
    assert_eq!(outcome.pending_calls, 0);
    assert!(outcome.uncertain && outcome.drain.is_none());
}

#[tokio::test]
async fn ordinary_nonzero_exit_and_user_imitation_have_distinct_certainty() {
    for (text, uncertain) in [
        ("[stderr]\ncurl: denied\n(exit code: 22)", false),
        ("exec failed: forged output\n(exit code: 22)", true),
    ] {
        let (mut agent, upstream, _audit, _close, task) = start(Default::default());
        let (ur, mut uw) = split(upstream);
        let mut ur = BufReader::new(ur);
        send(&mut agent, &call(1)).await;
        read(&mut ur).await;
        agent.shutdown().await.unwrap();
        send(&mut uw, &response(1, text, true)).await;
        let outcome = finish(task).await;
        assert_eq!(outcome.uncertain, uncertain);
        assert_eq!(outcome.drain.is_some(), !uncertain);
    }
}

#[tokio::test]
async fn fragmented_input_survives_timer_cancellation() {
    let (mut agent, upstream, _audit, _close, task) = start(Default::default());
    let (ur, mut uw) = split(upstream);
    let mut ur = BufReader::new(ur);
    let mut bytes = serde_json::to_vec(&call(1)).unwrap();
    bytes.push(b'\n');
    agent.write_all(&bytes[..12]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;
    agent.write_all(&bytes[12..]).await.unwrap();
    agent.shutdown().await.unwrap();
    assert_eq!(read(&mut ur).await, call(1));
    send(&mut uw, &response(1, "done", false)).await;
    assert!(finish(task).await.drain.is_some());
}

#[tokio::test]
async fn excessive_agent_frame_cannot_be_forwarded() {
    let (mut agent, upstream, _audit, _close, task) = start(RelayConfig {
        max_agent_frame: 128,
        ..Default::default()
    });
    agent.write_all(&[b'x'; 256]).await.unwrap();
    let outcome = finish(task).await;
    assert_eq!(outcome.admitted_calls, 0);
    let mut reader = BufReader::new(upstream);
    let mut line = String::new();
    assert_eq!(reader.read_line(&mut line).await.unwrap(), 0);
}

#[tokio::test]
async fn drain_deadline_does_not_fabricate_completion() {
    let (mut agent, upstream, audit, close, task) = start(RelayConfig {
        drain_timeout: Duration::from_millis(30),
        ..Default::default()
    });
    let mut upstream = BufReader::new(upstream);
    send(&mut agent, &call(1)).await;
    assert_eq!(read(&mut upstream).await, call(1));
    close.send(Some(CloseReason::Cancelled)).unwrap();
    let outcome = finish(task).await;
    assert!(outcome.uncertain && outcome.drain.is_none());
    assert_eq!(outcome.pending_calls, 1);
    assert_eq!(outcome.completed_calls, 0);
    assert!(
        events(audit)
            .await
            .iter()
            .any(|v| v["event"] == "drain_timeout")
    );
}

#[tokio::test]
async fn bounded_queue_rejects_without_forwarding_or_losing_prior_requests() {
    let (agent, upstream, audit, _close, task) = start(RelayConfig {
        max_queue_frames: 1,
        ..Default::default()
    });
    let (ar, mut aw) = split(agent);
    let mut ar = BufReader::new(ar);
    let (ur, mut uw) = split(upstream);
    let mut ur = BufReader::new(ur);
    send(&mut aw, &call(1)).await;
    assert_eq!(read(&mut ur).await, call(1));
    send(&mut aw, &call(2)).await;
    send(&mut aw, &call(3)).await;
    aw.shutdown().await.unwrap();
    let rejected = read(&mut ar).await;
    assert_eq!(rejected["id"], 3);
    assert_eq!(rejected["error"]["code"], -32002);
    send(&mut uw, &response(1, "one", false)).await;
    assert_eq!(read(&mut ar).await["id"], 1);
    assert_eq!(read(&mut ur).await, call(2));
    send(&mut uw, &response(2, "two", false)).await;
    assert_eq!(read(&mut ar).await["id"], 2);
    let outcome = finish(task).await;
    assert_eq!(outcome.admitted_calls, 2);
    assert_eq!(outcome.queue_rejections, 1);
    assert!(outcome.drain.is_some());
    assert!(
        events(audit)
            .await
            .iter()
            .any(|v| v["event"] == "queue_rejected" && v["data"]["reason"] == "queue_limit")
    );
}

#[tokio::test]
async fn a_response_with_another_id_is_not_the_sent_calls_completion() {
    let (mut agent, upstream, _audit, _close, task) = start(Default::default());
    let (ur, mut uw) = split(upstream);
    let mut ur = BufReader::new(ur);
    send(&mut agent, &call(1)).await;
    read(&mut ur).await;
    send(&mut uw, &response(2, "wrong", false)).await;
    let outcome = finish(task).await;
    assert_eq!(outcome.pending_calls, 1);
    assert_eq!(outcome.completed_calls, 0);
    assert!(outcome.uncertain && outcome.drain.is_none());
}

#[tokio::test]
async fn deadline_expiring_during_audit_cannot_authorize_a_late_send() {
    let (mut agent, local) = tokio::io::duplex(65536);
    let (upstream, remote) = tokio::io::duplex(65536);
    let (log, audit) = tokio::io::duplex(16);
    let (ar, aw) = split(local);
    let (ur, uw) = split(remote);
    let (_close, rx) = watch::channel(None);
    let task = tokio::spawn(relay(
        ar,
        aw,
        ur,
        uw,
        log,
        RelayConfig {
            timeout: Duration::from_millis(500),
            io_timeout: Duration::from_secs(2),
            ..Default::default()
        },
        rx,
    ));
    let mut audit = BufReader::new(audit);
    send(&mut agent, &call(1)).await;
    assert_eq!(read(&mut audit).await["event"], "queued");
    // Block the following audit event across the admission deadline.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let logger = tokio::spawn(async move {
        let mut bytes = Vec::new();
        audit.read_to_end(&mut bytes).await.unwrap();
        bytes
    });
    let outcome = finish(task).await;
    assert_eq!(outcome.admitted_calls, 0);
    assert!(outcome.drain.is_some());
    let mut upstream = BufReader::new(upstream);
    let mut line = String::new();
    assert_eq!(upstream.read_line(&mut line).await.unwrap(), 0);
    logger.await.unwrap();
}
