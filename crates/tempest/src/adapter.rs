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
        crate::host_io::json_new(
            &endpoint.owner_file,
            &json!({"process_group":child.id(),"role":"agent_bridge"}),
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
