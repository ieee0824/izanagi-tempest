//! Deterministic mock adapter; real CLI launchers remain a separate milestone.
use crate::{host_io::command, rpc::Rpc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    future::Future,
    io,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

pub struct McpCommand {
    pub executable: PathBuf,
    pub socket: PathBuf,
    pub owner_file: PathBuf,
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
                Some("item.completed" | "turn.started")
            )
        {
            return Err(io::Error::other("Codex emitted work after terminal event"));
        }
        match event["type"].as_str() {
            Some("thread.started") => {
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
                session = event["session_id"].as_str().map(str::to_owned);
            }
            Some("assistant") if event["parent_tool_use_id"].is_null() => {
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

    fn lines(values: &[Value]) -> Vec<u8> {
        values
            .iter()
            .map(|value| serde_json::to_string(value).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
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
            json!({"type":"assistant","parent_tool_use_id":null,
                "message":{"content":[{"type":"text","text":"final"}]}}),
            result.clone(),
        ]);
        assert_eq!(claude_final_message(&valid, true, 3).unwrap(), "final");
        assert!(claude_final_message(&valid, true, 1).is_err());
        let tool_ended = lines(&[
            init,
            json!({"type":"assistant","parent_tool_use_id":null,
                "message":{"content":[{"type":"text","text":"intermediate"},
                    {"type":"tool_use","name":"mcp"}]}}),
            result,
        ]);
        assert!(claude_final_message(&tool_ended, true, 3).is_err());
        let mut post_terminal = valid.clone();
        post_terminal.extend_from_slice(
            b"\n{\"type\":\"assistant\",\"parent_tool_use_id\":null,\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"late\"}]}}",
        );
        assert!(claude_final_message(&post_terminal, true, 3).is_err());
        assert!(claude_final_message(&valid[..valid.len() / 2], true, 3).is_err());
        assert!(claude_final_message(&valid, false, 3).is_err());
    }
}
