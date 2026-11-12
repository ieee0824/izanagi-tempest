use anyhow::{Context, Result, ensure};
use std::{ffi::OsString, io::Read, path::PathBuf};
use tempest_guest::{
    config::Config,
    control::{self, Operation, Request},
};
fn option(args: &mut Vec<OsString>, name: &str) -> Result<Option<OsString>> {
    if let Some(i) = args.iter().position(|a| a == name) {
        ensure!(i + 1 < args.len(), "option value required");
        args.remove(i);
        return Ok(Some(args.remove(i)));
    }
    Ok(None)
}
fn absolute(path: OsString) -> Result<PathBuf> {
    let path = PathBuf::from(path);
    Ok(if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    })
}
async fn run() -> Result<bool> {
    let mut args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "__proxy" {
        ensure!(
            unsafe { libc::geteuid() } != 0,
            "HTTP proxy must run as an unprivileged user"
        );
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(16 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 16 * 1024, "proxy setup oversized");
        let config: Config = serde_json::from_slice(&bytes).context("invalid proxy setup")?;
        ensure!(
            config.listen.ip().is_loopback() && config.upstream.ip().is_loopback(),
            "only loopback endpoints allowed"
        );
        ensure!(
            config.development || unsafe { libc::geteuid() } == config.service_uid,
            "wrong proxy uid"
        );
        tempest_guest::proxy::serve(config).await?;
        return Ok(true);
    }
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!(
            "Usage: tempest-guest --config FILE recorder|claim|seed|probe|seal|export\nseed/probe: --token TOKEN INPUT.json; export: --token TOKEN DIRECTORY\n--token-stdin reads one token from stdin instead of argv"
        );
        return Ok(true);
    }
    let config = option(&mut args, "--config")?
        .map_or_else(|| PathBuf::from("/etc/tempest/guest.json"), PathBuf::from);
    let config = Config::read(&config)?;
    ensure!(!args.is_empty(), "subcommand required (see --help)");
    let command = args.remove(0);
    if command == "recorder" {
        ensure!(args.is_empty(), "unexpected recorder arguments");
        control::serve(config).await?;
        return Ok(true);
    }
    let token = option(&mut args, "--token")?
        .map(|s| {
            s.into_string()
                .map_err(|_| anyhow::anyhow!("invalid token encoding"))
        })
        .transpose()?;
    let token = if let Some(i) = args.iter().position(|a| a == "--token-stdin") {
        args.remove(i);
        ensure!(token.is_none(), "choose one token input method");
        let mut value = String::new();
        std::io::stdin().take(1025).read_to_string(&mut value)?;
        ensure!(value.len() <= 1024, "token input oversized");
        Some(value.trim_end_matches(['\r', '\n']).to_owned())
    } else {
        token
    };
    let operation = match command.to_str() {
        Some("claim") if args.is_empty() && token.is_none() => Operation::Claim,
        Some("seed") if args.len() == 1 => Operation::Seed {
            file: absolute(args.remove(0))?,
        },
        Some("probe") if args.len() == 1 => Operation::Probe {
            file: absolute(args.remove(0))?,
        },
        Some("seal") if args.is_empty() => Operation::Seal,
        Some("export") if args.len() == 1 => Operation::Export {
            directory: absolute(args.remove(0))?,
        },
        _ => anyhow::bail!("invalid subcommand or arguments (see --help)"),
    };
    let audit_id = std::env::var("TEMPEST_AUDIT_ID")
        .ok()
        .filter(|value| value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let value = control::call(
        &config,
        Request {
            token,
            operation,
            audit_id,
        },
    )
    .await?;
    println!("{}", serde_json::to_string(&value)?);
    Ok(value
        .get("complete")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true))
}
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(true) => std::process::ExitCode::SUCCESS,
        Ok(false) => std::process::ExitCode::from(1),
        Err(error) => {
            eprintln!("tempest-guest: {error}");
            std::process::ExitCode::from(1)
        }
    }
}
