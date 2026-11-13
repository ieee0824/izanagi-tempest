//! Fixed MCP peer used only by the native launcher capability probe.
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    io::{self, BufRead, Write},
    process::ExitCode,
};

const LIMIT: usize = 1024 * 1024;

fn tools() -> Value {
    json!({"tools":[
        {"name":"sandbox_status","description":"Return the fixed capability probe status.",
         "inputSchema":{"type":"object","properties":{},"additionalProperties":false}},
        {"name":"sandbox_exec","description":"Execute an argv vector inside the Izanagi guest.",
         "inputSchema":{"type":"object","properties":{"command":{"type":"string"},
          "args":{"type":"array","items":{"type":"string"}}},"required":["command"],
          "additionalProperties":false}},
        {"name":"sandbox_shell","description":"Execute a shell command inside the Izanagi guest.",
         "inputSchema":{"type":"object","properties":{"command":{"type":"string"}},
          "required":["command"],"additionalProperties":false}}
    ]})
}

fn response(request: &Value, probe_id: &str) -> io::Result<Option<Value>> {
    if request["jsonrpc"] != "2.0" {
        return Err(io::Error::other("invalid probe MCP JSON-RPC version"));
    }
    let Some(id) = request.get("id") else {
        return Ok(None);
    };
    let method = request["method"]
        .as_str()
        .ok_or_else(|| io::Error::other("probe MCP method missing"))?;
    let result = match method {
        "initialize" => json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{}},
            "serverInfo":{"name":"tempest-capability-probe","version":env!("CARGO_PKG_VERSION")}}),
        "tools/list" => tools(),
        "tools/call" if request.pointer("/params/name") == Some(&json!("sandbox_status")) => {
            let text = serde_json::to_string(&json!({"probe_id":probe_id,"running":true}))?;
            json!({"content":[{"type":"text","text":text}],"isError":false})
        }
        "tools/call" => {
            return Ok(Some(json!({"jsonrpc":"2.0","id":id,"error":{
                "code":-32602,"message":"capability probe permits only sandbox_status"}})));
        }
        _ => {
            return Ok(Some(json!({"jsonrpc":"2.0","id":id,"error":{
                "code":-32601,"message":"method not found"}})));
        }
    };
    Ok(Some(json!({"jsonrpc":"2.0","id":id,"result":result})))
}

fn serve(probe_id: &str) -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.len() > LIMIT {
            return Err(io::Error::other("probe MCP request too large"));
        }
        let request = crate::capability_proof::parse_unique_value(line.as_bytes())?;
        if let Some(value) = response(&request, probe_id)? {
            serde_json::to_writer(&mut stdout, &value)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

pub fn run(args: &[OsString]) -> ExitCode {
    const USAGE: &str = "Usage: tempest capability-probe-mcp --probe-id ID";
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let probe_id = match args {
        [flag, value]
            if flag == "--probe-id"
                && value.to_str().is_some_and(|value| {
                    !value.is_empty()
                        && value.len() <= 128
                        && value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                        })
                }) =>
        {
            value.to_str().unwrap()
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match serve(probe_id) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("capability probe MCP: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_fixed_and_only_status_succeeds() {
        let list = response(
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
            "probe-1",
        )
        .unwrap()
        .unwrap();
        let names = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(names, ["sandbox_status", "sandbox_exec", "sandbox_shell"]);
        let status = response(
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
                "params":{"name":"sandbox_status","arguments":{}}}),
            "probe-1",
        )
        .unwrap()
        .unwrap();
        assert_eq!(status["result"]["isError"], false);
        let denied = response(
            &json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":"sandbox_exec","arguments":{}}}),
            "probe-1",
        )
        .unwrap()
        .unwrap();
        assert_eq!(denied["error"]["code"], -32602);
    }
}
