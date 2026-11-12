//! Operator entry point; run orchestration owns VM shutdown separately.
use crate::relay::{RelayConfig, relay};
use serde_json::json;
use std::{
    collections::HashSet,
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    pin::Pin,
    process::{ExitCode, Stdio},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{io::AsyncWrite, process::Command, sync::watch};

/// Darwin /dev/fd duplicates the shared file offset. The pinned MCP server
/// reads its HMAC once per request, so rewind before each serialized frame.
pub(crate) struct SecretWriter<W> {
    inner: W,
    cursor: Option<File>,
    start: bool,
}
impl<W> SecretWriter<W> {
    pub(crate) fn new(inner: W, cursor: Option<File>) -> Self {
        Self {
            inner,
            cursor,
            start: true,
        }
    }
}
impl<W: AsyncWrite + Unpin> AsyncWrite for SecretWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.start && !bytes.is_empty() {
            if let Some(file) = &mut this.cursor {
                if let Err(error) = file.seek(SeekFrom::Start(0)) {
                    return Poll::Ready(Err(error));
                }
            }
            this.start = false;
        }
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_flush(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            this.start = true;
        }
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

const USAGE: &str = "Usage: tempest mcp-proxy --log FILE --summary FILE --stderr FILE [--cwd DIR] [--secret-file FILE] [--max-calls N] [--timeout-ms N] [--drain-ms N] -- UPSTREAM [ARGS...]";
pub(crate) struct Options {
    pub log: PathBuf,
    pub summary: PathBuf,
    pub stderr: PathBuf,
    pub cwd: PathBuf,
    pub config: RelayConfig,
    pub command: Vec<OsString>,
    pub secret_file: Option<PathBuf>,
}
pub(crate) fn options(args: &[OsString]) -> Result<Options, &'static str> {
    let mut log = None;
    let mut summary = None;
    let mut stderr = None;
    let mut cwd = None;
    let mut secret_file = None;
    let mut config = RelayConfig::default();
    let mut i = 0;
    let mut seen = HashSet::new();
    while i < args.len() && args[i] != "--" {
        let flag = args[i].to_str().ok_or("invalid option")?;
        if !seen.insert(flag) {
            return Err("duplicate option");
        }
        let value = args.get(i + 1).ok_or("option value required")?;
        match flag {
            "--log" => {
                if log.replace(PathBuf::from(value)).is_some() {
                    return Err("duplicate --log");
                }
            }
            "--summary" => {
                if summary.replace(PathBuf::from(value)).is_some() {
                    return Err("duplicate --summary");
                }
            }
            "--stderr" => {
                if stderr.replace(PathBuf::from(value)).is_some() {
                    return Err("duplicate --stderr");
                }
            }
            "--cwd" => {
                if cwd.replace(PathBuf::from(value)).is_some() {
                    return Err("duplicate --cwd");
                }
            }
            "--secret-file" => secret_file = Some(PathBuf::from(value)),
            "--max-calls" | "--timeout-ms" | "--drain-ms" => {
                let n = value
                    .to_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .ok_or("expected nonnegative integer")?;
                match flag {
                    "--max-calls" => config.max_calls = n,
                    "--timeout-ms" => config.timeout = Duration::from_millis(n),
                    _ => config.drain_timeout = Duration::from_millis(n),
                }
            }
            _ => return Err("unknown option"),
        }
        i += 2;
    }
    if args.get(i).is_none_or(|a| a != "--") || i + 1 >= args.len() {
        return Err("upstream command required after --");
    }
    let cwd = cwd.unwrap_or(env::current_dir().map_err(|_| "cannot get cwd")?);
    Ok(Options {
        log: log.ok_or("--log required")?,
        summary: summary.ok_or("--summary required")?,
        stderr: stderr.ok_or("--stderr required")?,
        cwd,
        config,
        command: args[i + 1..].to_vec(),
        secret_file,
    })
}
pub(crate) fn private_new(path: &Path) -> io::Result<File> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent.canonicalize()?;
    let metadata = fs::metadata(&parent)?;
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "evidence parent must be owned by this user with mode 0700",
        ));
    }
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("invalid evidence filename"))?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(parent.join(name))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

pub(crate) fn secret_reference(path: &Path) -> io::Result<File> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?;
    let parent_metadata = parent.metadata()?;
    if parent_metadata.uid() != unsafe { libc::geteuid() }
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(io::Error::other("unsafe transport secret parent"));
    }
    let path = parent.join(
        path.file_name()
            .ok_or_else(|| io::Error::other("invalid secret reference"))?,
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > 4096
    {
        return Err(io::Error::other(
            "transport secret must be a nonempty private regular file",
        ));
    }
    Ok(file)
}
pub(crate) fn inherit_secret(command: &mut Command, file: File) {
    let descriptor = file.as_raw_fd();
    command.env("IZANAGI_SECRET_FILE", format!("/dev/fd/{descriptor}"));
    // Only this fork clears CLOEXEC, on the exact O_NOFOLLOW/fstat-verified FD.
    // The parent's FD remains CLOEXEC for independently launched agent children.
    unsafe {
        command.pre_exec(move || {
            let _keep_open = &file;
            let flags = libc::fcntl(descriptor, libc::F_GETFD);
            if flags < 0 || libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
async fn execute(options: Options) -> io::Result<bool> {
    let key_handle = options
        .secret_file
        .as_deref()
        .map(secret_reference)
        .transpose()?;
    let cursor = key_handle.as_ref().map(File::try_clone).transpose()?;
    // Reserve all evidence paths before creating an external process.
    let log = private_new(&options.log)?;
    let log_sync = log.try_clone()?;
    let mut summary = private_new(&options.summary)?;
    let stderr = private_new(&options.stderr)?;
    let mut command = Command::new(&options.command[0]);
    command
        .args(&options.command[1..])
        .current_dir(options.cwd)
        .env_clear();
    for name in ["HOME", "PATH", "TZ"] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    if let Some(file) = key_handle {
        inherit_secret(&mut command, file);
    }
    command
        .env("TERM", "dumb")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(stderr))
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            serde_json::to_writer(
                &mut summary,
                &json!({"scope":"rpc_transport_only","error":"upstream_spawn_failed"}),
            )?;
            summary.write_all(b"\n")?;
            summary.sync_all()?;
            return Err(error);
        }
    };
    let upstream_read = child.stdout.take().expect("configured piped stdout");
    let upstream_write =
        SecretWriter::new(child.stdin.take().expect("configured piped stdin"), cursor);
    let (_close, rx) = watch::channel(None);
    let result = relay(
        tokio::io::stdin(),
        tokio::io::stdout(),
        upstream_read,
        upstream_write,
        tokio::fs::File::from_std(log),
        options.config,
        rx,
    )
    .await;
    let mut forced = false;
    let exited = match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
        Ok(status) => status?.success(),
        Err(_) => {
            forced = true;
            child.kill().await?;
            false
        }
    };
    let success = match result {
        Ok(outcome) => {
            let success = !outcome.uncertain && outcome.drain.is_some() && exited;
            serde_json::to_writer(
                &mut summary,
                &json!({"scope":"rpc_transport_only","relay":outcome,
                "upstream_exited_successfully":exited,"upstream_forced_stop":forced}),
            )?;
            success
        }
        Err(_) => {
            serde_json::to_writer(
                &mut summary,
                &json!({"scope":"rpc_transport_only","error":"relay_io_failure",
                "upstream_exited_successfully":exited,"upstream_forced_stop":forced}),
            )?;
            false
        }
    };
    log_sync.sync_all()?;
    summary.write_all(b"\n")?;
    summary.sync_all()?;
    Ok(success)
}
pub fn run(args: &[OsString]) -> ExitCode {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        eprintln!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let options = match options(args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("MCP runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(execute(options));
    // A quota/timeout can close the server while the peer still holds stdin.
    runtime.shutdown_background();
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("MCP relay: {error}");
            ExitCode::FAILURE
        }
    }
}
