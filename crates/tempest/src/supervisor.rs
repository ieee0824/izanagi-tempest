//! Controller-owned upstream lifetime, independent of the agent/stdio bridge.
use crate::{
    admission::CloseReason,
    proxy_cli::private_new,
    relay::{RelayConfig, RelayOutcome, relay},
};
use std::{
    env,
    ffi::OsString,
    fs, io,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    process::{ExitCode, Stdio},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWriteExt, ReadBuf},
    net::{UnixListener, UnixStream},
    process::Command,
    sync::watch,
    task::JoinHandle,
};

fn request_close(sender: &watch::Sender<Option<CloseReason>>, reason: CloseReason) {
    sender.send_if_modified(|current| {
        if current.is_none() {
            *current = Some(reason);
            true
        } else {
            false
        }
    });
}

pub struct SupervisorConfig {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub socket: PathBuf,
    pub log: PathBuf,
    pub stderr: PathBuf,
    pub secret_file: Option<PathBuf>,
    pub owner_file: Option<PathBuf>,
    pub relay: RelayConfig,
}

/// EOF here means the single bridge has finished, not an intentional half-close.
/// The generic relay's half-close behavior remains available to other callers.
struct AgentRead<R> {
    inner: R,
    close: watch::Sender<Option<CloseReason>>,
}
impl<R: AsyncRead + Unpin> AsyncRead for AgentRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let available = buffer.remaining();
        let result = Pin::new(&mut self.inner).poll_read(cx, buffer);
        match &result {
            Poll::Ready(Ok(())) if available > 0 && before == buffer.filled().len() => {
                request_close(&self.close, CloseReason::AgentFinished);
            }
            Poll::Ready(Err(_)) => {
                request_close(&self.close, CloseReason::Cancelled);
            }
            _ => {}
        }
        result
    }
}

#[derive(serde::Serialize)]
pub struct SupervisorOutcome {
    pub relay: RelayOutcome,
    pub upstream_exited_successfully: bool,
    pub upstream_forced_stop: bool,
}
impl SupervisorOutcome {
    /// RPC-only; a VM barrier is still required before normal export.
    pub fn verified_rpc_drain(&self) -> bool {
        self.relay.drain.is_some() && !self.relay.uncertain && self.upstream_exited_successfully
    }
}

pub struct Supervisor {
    close: watch::Sender<Option<CloseReason>>,
    task: Option<JoinHandle<io::Result<SupervisorOutcome>>>,
}
impl Supervisor {
    pub fn start(config: SupervisorConfig) -> io::Result<Self> {
        let started = Instant::now();
        let secret_file = config
            .secret_file
            .as_deref()
            .map(crate::proxy_cli::secret_reference)
            .transpose()?;
        let cursor = secret_file
            .as_ref()
            .map(std::fs::File::try_clone)
            .transpose()?;
        let parent = config
            .socket
            .parent()
            .ok_or_else(|| io::Error::other("socket parent required"))?
            .canonicalize()?;
        let metadata = parent.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(io::Error::other(
                "socket parent must be owned with mode 0700",
            ));
        }
        let socket = parent.join(
            config
                .socket
                .file_name()
                .ok_or_else(|| io::Error::other("invalid socket"))?,
        );
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        let log = match private_new(&config.log) {
            Ok(log) => log,
            Err(error) => {
                let _ = fs::remove_file(&socket);
                return Err(error);
            }
        };
        let log_sync = log.try_clone()?;
        let stderr = match private_new(&config.stderr) {
            Ok(stderr) => stderr,
            Err(error) => {
                let _ = fs::remove_file(&socket);
                return Err(error);
            }
        };
        let mut command = Command::new(&config.executable);
        command
            .args(config.args)
            .current_dir(config.cwd)
            .env_clear();
        for name in ["HOME", "PATH", "TZ"] {
            if let Some(value) = env::var_os(name) {
                command.env(name, value);
            }
        }
        if let Some(path) = secret_file {
            crate::proxy_cli::inherit_secret(&mut command, path);
        }
        command
            .env("TERM", "dumb")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true);
        // The controller owns this group; terminating the agent group cannot kill it.
        command.process_group(0);
        if let Some(path) = &config.owner_file {
            crate::host_io::json_new(
                path,
                &serde_json::json!({"state":"launching","role":"mcp_upstream"}),
            )?;
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = fs::remove_file(&socket);
                return Err(error);
            }
        };
        if let Some(path) = &config.owner_file {
            crate::host_io::json_replace(
                path,
                &serde_json::json!({"state":"running","process_group":child.id(),"role":"mcp_upstream"}),
            )?;
        }
        let upstream_read = child.stdout.take().expect("piped");
        let upstream_write =
            crate::proxy_cli::SecretWriter::new(child.stdin.take().expect("piped"), cursor);
        let (close, mut rx) = watch::channel(None);
        let eof_close = close.clone();
        let task = tokio::spawn(async move {
            let result = async {
                let mut relay_config = config.relay;
                let connected = tokio::select! {
                    accepted = listener.accept() => Some(accepted?.0),
                    _ = rx.changed() => None,
                    _ = tokio::time::sleep(relay_config.timeout.saturating_sub(started.elapsed())) => {
                        request_close(&eof_close,CloseReason::Timeout);
                        None
                    },
                };
                relay_config.timeout = relay_config.timeout.saturating_sub(started.elapsed());
                drop(listener); // Only one bridge may ever join this supervisor.
                let result = if let Some(stream) = connected {
                    let (read, write) = stream.into_split();
                    relay(
                        AgentRead {
                            inner: read,
                            close: eof_close,
                        },
                        write,
                        upstream_read,
                        upstream_write,
                        tokio::fs::File::from_std(log),
                        relay_config,
                        rx,
                    )
                    .await
                } else {
                    relay(
                        tokio::io::empty(),
                        tokio::io::sink(),
                        upstream_read,
                        upstream_write,
                        tokio::fs::File::from_std(log),
                        relay_config,
                        rx,
                    )
                    .await
                };
                let (exited, forced) =
                    match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
                        Ok(status) => (status?.success(), false),
                        Err(_) => {
                            child.kill().await?;
                            (false, true)
                        }
                    };
                log_sync.sync_all()?;
                Ok(SupervisorOutcome {
                    relay: result?,
                    upstream_exited_successfully: exited,
                    upstream_forced_stop: forced,
                })
            }
            .await;
            let _ = fs::remove_file(socket);
            result
        });
        Ok(Self {
            close,
            task: Some(task),
        })
    }

    pub async fn finish(mut self, reason: CloseReason) -> io::Result<SupervisorOutcome> {
        request_close(&self.close, reason);
        self.task
            .take()
            .expect("one finish")
            .await
            .map_err(|_| io::Error::other("supervisor task failed"))?
    }

    pub async fn wait(mut self) -> io::Result<SupervisorOutcome> {
        self.task
            .take()
            .expect("one wait")
            .await
            .map_err(|_| io::Error::other("supervisor task failed"))?
    }
}
impl Drop for Supervisor {
    fn drop(&mut self) {
        // Dropping an owner still closes admission; the detached task may drain.
        // Without the returned receipt the caller must not export normally.
        request_close(&self.close, CloseReason::Cancelled);
    }
}

pub async fn connect(socket: &Path) -> io::Result<()> {
    let stream = UnixStream::connect(socket).await?;
    let (mut read, mut write) = stream.into_split();
    let incoming = async {
        tokio::io::copy(&mut tokio::io::stdin(), &mut write).await?;
        write.shutdown().await
    };
    let outgoing = async {
        tokio::io::copy(&mut read, &mut tokio::io::stdout()).await?;
        Ok::<_, io::Error>(())
    };
    tokio::pin!(incoming, outgoing);
    tokio::select! {
        result = &mut incoming => { result?; outgoing.await },
        result = &mut outgoing => result,
    }
}
pub fn connect_cli(args: &[OsString]) -> ExitCode {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("Usage: tempest mcp-connect SOCKET [--environment-policy POLICY]");
        return ExitCode::SUCCESS;
    }
    if !matches!(args.len(), 1 | 3)
        || (args.len() == 3
            && (args[1] != "--environment-policy"
                || args[2]
                    .to_str()
                    .is_none_or(|value| !matches!(value, "codex-v1" | "claude-code-v1"))))
    {
        eprintln!("Usage: tempest mcp-connect SOCKET [--environment-policy POLICY]");
        return ExitCode::from(2);
    }
    if args.len() == 3 {
        let environment = std::env::vars_os().collect::<std::collections::BTreeMap<_, _>>();
        let policy = args[2].to_string_lossy();
        if !bridge_environment_allowed(&policy, &environment) {
            if let Some(directory) = std::env::var_os("TMPDIR").map(PathBuf::from) {
                let names = environment
                    .keys()
                    .map(|name| name.to_string_lossy().into_owned())
                    .collect::<Vec<_>>();
                let _ = crate::host_io::json_new(
                    &directory.join("mcp-environment-rejected.json"),
                    &serde_json::json!({"policy":policy,"names":names}),
                );
            }
            eprintln!("MCP bridge environment mismatch");
            return ExitCode::FAILURE;
        }
    }
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(_) => return ExitCode::FAILURE,
    };
    let result = runtime.block_on(connect(Path::new(&args[0])));
    // A server EOF must not wait for an agent holding the stdin pipe open.
    runtime.shutdown_background();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("MCP bridge disconnected");
            ExitCode::FAILURE
        }
    }
}

fn bridge_environment_allowed(
    policy: &str,
    environment: &std::collections::BTreeMap<OsString, OsString>,
) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let expected = match policy {
        "codex-v1" => [
            "HOME",
            "LANG",
            "LC_ALL",
            "PATH",
            "TMPDIR",
            "__CF_USER_TEXT_ENCODING",
        ]
        .as_slice(),
        "claude-code-v1" => [
            "AI_AGENT",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_BASE_URL",
            "CLAUDECODE",
            "CLAUDE_CODE_ENTRYPOINT",
            "CLAUDE_CODE_SESSION_ID",
            "CLAUDE_CODE_SIMPLE",
            "CLAUDE_CODE_TMPDIR",
            "CLAUDE_PROJECT_DIR",
            "COREPACK_ENABLE_AUTO_PIN",
            "DISABLE_AUTOUPDATER",
            "HOME",
            "LANG",
            "LC_ALL",
            "NoDefaultCurrentDirectoryInExePath",
            "TMPDIR",
        ]
        .as_slice(),
        _ => return false,
    };
    let names = environment
        .keys()
        .filter_map(|name| name.to_str())
        .collect::<Vec<_>>();
    if names != expected
        || environment
            .get(std::ffi::OsStr::new("LANG"))
            .and_then(|value| value.to_str())
            != Some("C.UTF-8")
        || environment
            .get(std::ffi::OsStr::new("LC_ALL"))
            .and_then(|value| value.to_str())
            != Some("C.UTF-8")
    {
        return false;
    }
    if policy == "claude-code-v1"
        && (environment
            .get(std::ffi::OsStr::new("ANTHROPIC_API_KEY"))
            .and_then(|value| value.to_str())
            != Some("tempest-relay-placeholder")
            || environment
                .get(std::ffi::OsStr::new("ANTHROPIC_BASE_URL"))
                .and_then(|value| value.to_str())
                .is_none_or(|value| !value.starts_with("http://127.0.0.1:")))
    {
        return false;
    }
    let directories = ["HOME", "TMPDIR"].map(|name| {
        environment
            .get(std::ffi::OsStr::new(name))
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .and_then(|path| path.canonicalize().ok())
    });
    let [Some(home), Some(temporary)] = directories else {
        return false;
    };
    if policy == "claude-code-v1"
        && environment
            .get(std::ffi::OsStr::new("CLAUDE_CODE_TMPDIR"))
            .map(PathBuf::from)
            .and_then(|path| path.canonicalize().ok())
            .as_ref()
            != Some(&temporary)
    {
        return false;
    }
    if home.parent() != temporary.parent() || home == temporary {
        return false;
    }
    [home, temporary].iter().all(|path| {
        path.symlink_metadata().is_ok_and(|metadata| {
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o777 == 0o700
        })
    })
}

/// Standalone owner for integration and external controllers. Agent processes
/// launch mcp-connect; they do not own this process or the upstream child group.
pub fn session_cli(args: &[OsString]) -> ExitCode {
    const USAGE: &str = "Usage: tempest mcp-session SOCKET --log FILE --summary FILE --stderr FILE [--cwd DIR] [--secret-file FILE] [--max-calls N] [--timeout-ms N] [--drain-ms N] -- UPSTREAM [ARGS...]";
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let Some(socket) = args.first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let options = match crate::proxy_cli::options(&args[1..]) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let execute = async {
        use std::io::Write;
        let mut summary = private_new(&options.summary)?;
        let owner = Supervisor::start(SupervisorConfig {
            executable: PathBuf::from(&options.command[0]),
            args: options.command[1..].to_vec(),
            cwd: options.cwd,
            socket: PathBuf::from(socket),
            log: options.log,
            stderr: options.stderr,
            relay: options.config,
            secret_file: options.secret_file,
            owner_file: None,
        })?;
        let close = owner.close.clone();
        let mut termination =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let wait = owner.wait();
        tokio::pin!(wait);
        let result = tokio::select! {
            result = &mut wait => result,
            _ = tokio::signal::ctrl_c() => { request_close(&close,CloseReason::Cancelled); wait.await },
            _ = termination.recv() => { request_close(&close,CloseReason::Cancelled); wait.await },
        };
        let (value, success) = match result {
            Ok(outcome) => {
                let success = outcome.verified_rpc_drain();
                (
                    serde_json::json!({"scope":"rpc_transport_only","supervisor":outcome}),
                    success,
                )
            }
            Err(_) => (
                serde_json::json!({"scope":"rpc_transport_only","error":"supervisor_failed"}),
                false,
            ),
        };
        serde_json::to_writer(&mut summary, &value)?;
        summary.write_all(b"\n")?;
        summary.sync_all()?;
        Ok::<_, io::Error>(success)
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(_) => return ExitCode::FAILURE,
    };
    match runtime.block_on(execute) {
        Ok(true) => ExitCode::SUCCESS,
        _ => {
            eprintln!("MCP session failed; normal export is not permitted");
            ExitCode::FAILURE
        }
    }
}
