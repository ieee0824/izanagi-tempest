//! Fixed inputs for dedicated Linux Claude offline diagnostics.
use super::os::Fault;
mod host_login_diagnostic;
mod local_auth;
mod login_connect;
pub(super) use host_login_diagnostic::{
    run_host_login_diagnostic, run_host_login_publisher, run_host_login_responder,
};
mod login_handoff;
mod login_permit;
mod writable_config;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
};

struct Artifact<'a> {
    source: &'a str,
    bytes: u64,
    sha256: &'a str,
    targets: &'static [&'static str],
}

const ARTIFACTS: &[Artifact<'static>] = &[
    Artifact {
        source: "/var/lib/tempest-claude-offline/claude",
        bytes: 365842960,
        sha256: "0dc4f4a9a165fc60746d7ae8489712e5fc352f1e7ad4eb22e7141bd0812eb0cf",
        targets: &["bin/claude"],
    },
    Artifact {
        source: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        bytes: 236616,
        sha256: "5fc0940888e9d2e1a00e66d6b1a559c36364ee867683652e1074fa576952cc3f",
        targets: &[
            "lib64/ld-linux-x86-64.so.2",
            "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        ],
    },
    Artifact {
        source: "/usr/lib/x86_64-linux-gnu/libc.so.6",
        bytes: 2129424,
        sha256: "755a371e86cc9f564ab54f66140747700fb0a103f698f659f2060f707897e09a",
        targets: &["lib/x86_64-linux-gnu/libc.so.6"],
    },
    Artifact {
        source: "/usr/lib/x86_64-linux-gnu/libdl.so.2",
        bytes: 14408,
        sha256: "4dbcca3c01ca84d092b5b7b2610f5835b55fc70a0288dd9d766b40ac9386e2d9",
        targets: &["lib/x86_64-linux-gnu/libdl.so.2"],
    },
    Artifact {
        source: "/usr/lib/x86_64-linux-gnu/libm.so.6",
        bytes: 952616,
        sha256: "5dcc4d25466e29ca390ed6fabb371c69b65dff6fa4e91c34561057a020d6994a",
        targets: &["lib/x86_64-linux-gnu/libm.so.6"],
    },
    Artifact {
        source: "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
        bytes: 14408,
        sha256: "cd34f895c9d2aa669d5d2654bed6b71210fc9003c3a1e96bb5311a40feb86039",
        targets: &["lib/x86_64-linux-gnu/libpthread.so.0"],
    },
    Artifact {
        source: "/usr/lib/x86_64-linux-gnu/librt.so.1",
        bytes: 14624,
        sha256: "5a00236da5864e8d1123d74e616713110708d6e3e604188f4f256dab4c6941d4",
        targets: &["lib/x86_64-linux-gnu/librt.so.1"],
    },
];

fn copy_checked(
    input: impl Read,
    mut output: impl Write,
    bytes: u64,
    expected: &str,
) -> Result<(), Fault> {
    let mut input = input.take(bytes + 1);
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    let mut copied = 0;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        copied += count as u64;
        if copied > bytes {
            return Err(Fault::Identity);
        }
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    if copied != bytes || format!("{:x}", hash.finalize()) != expected {
        return Err(Fault::Identity);
    }
    Ok(())
}

fn open_input(artifact: &Artifact<'_>) -> Result<File, Fault> {
    let source = Path::new(artifact.source);
    for parent in source.parent().ok_or(Fault::Path)?.ancestors() {
        let metadata = parent.symlink_metadata()?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(Fault::Ownership);
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(source)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7022 != 0
        || metadata.nlink() != 1
        || metadata.len() != artifact.bytes
    {
        return Err(Fault::Identity);
    }
    Ok(file)
}

struct ArtifactReader<'a>(&'a File, u64);

impl Read for ArtifactReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        let count = self.0.read_at(buf, self.1)?;
        self.1 += count as u64;
        Ok(count)
    }
}

fn verify_artifact(file: &File, artifact: &Artifact<'_>) -> Result<(), Fault> {
    copy_checked(
        ArtifactReader(file, 0),
        io::sink(),
        artifact.bytes,
        artifact.sha256,
    )
}

fn verify_fixed_artifact(artifact: &Artifact<'_>) -> Result<File, Fault> {
    let file = open_input(artifact)?;
    verify_artifact(&file, artifact)?;
    Ok(file)
}

fn stage_failure(stage: &str, fault: &Fault) {
    if let Fault::Kernel(errno) = fault {
        eprintln!(
            "offline staging: stage={stage} reason={} errno={errno}",
            fault.reason()
        );
    } else {
        eprintln!("offline staging: stage={stage} reason={}", fault.reason());
    }
}

fn stage_artifact(artifact: &Artifact<'_>, destination: &Path) -> Result<File, Fault> {
    stage_pinned_artifact(&open_input(artifact)?, artifact, destination)
}

fn stage_pinned_artifact(
    input: &File,
    artifact: &Artifact<'_>,
    destination: &Path,
) -> Result<File, Fault> {
    use std::os::unix::fs::PermissionsExt;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    copy_checked(
        ArtifactReader(input, 0),
        &mut output,
        artifact.bytes,
        artifact.sha256,
    )?;
    output.set_permissions(fs::Permissions::from_mode(0o555))?;
    let written = output.metadata()?;
    drop(output);
    let snapshot = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(destination)?;
    let reopened = snapshot.metadata()?;
    if (written.dev(), written.ino()) != (reopened.dev(), reopened.ino()) {
        return Err(Fault::Identity);
    }
    verify_artifact(&snapshot, artifact)?;
    Ok(snapshot)
}

const BUSYBOX: Artifact<'static> = Artifact {
    source: "/usr/bin/busybox",
    bytes: 2124608,
    sha256: "dbac288c29ba568459550a2da9e7ae0ded6b1fc728ee9fad3044c44e62d6ac14",
    targets: &["bin/busybox"],
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Diagnostic {
    Version,
    ConfigControl,
    ConfigIsolated,
    Pty,
    PtyWithLoginArtifacts,
    PtyOtherUid,
}

const UID: u32 = 999;
const GID: u32 = 988;

fn audit_settings(root: &Path) -> Result<[u64; 6], Fault> {
    let directory = root.join("home/fixture/config");
    let info = directory.symlink_metadata()?;
    let file = directory.join("settings.json");
    let meta = file.symlink_metadata()?;
    if !info.is_dir()
        || info.uid() != UID
        || info.gid() != GID
        || info.mode() & 0o7777 != 0o700
        || !meta.is_file()
        || meta.uid() != UID
        || meta.gid() != GID
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
        || meta.len() != 3
        || fs::read(file)? != b"{}\n"
        || fs::read_dir(directory)?.count() != 1
    {
        return Err(Fault::Identity);
    }
    Ok([
        info.dev(),
        info.ino(),
        info.ctime() as u64,
        meta.dev(),
        meta.ino(),
        meta.ctime() as u64,
    ])
}

fn own(path: &Path, mode: u32) -> Result<(), Fault> {
    use std::os::unix::fs::{PermissionsExt, chown};
    chown(path, Some(UID), Some(GID))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn run_in_pid_namespace(
    command: std::process::Command,
    timeout: std::time::Duration,
    namespace_reaped: &mut bool,
) -> Result<(), Fault> {
    run_in_pid_namespace_expecting(
        command,
        timeout,
        namespace_reaped,
        0,
        None,
        ChildNetwork::NewOffline,
    )
}

enum ChildNetwork {
    NewOffline,
    Verified((u64, u64)),
}

impl ChildNetwork {
    fn create_namespace(&self) -> bool {
        match self {
            Self::NewOffline => true,
            Self::Verified(_) => false,
        }
    }

    fn verify_before_spawn(&self) -> io::Result<()> {
        match self {
            Self::NewOffline => Ok(()),
            Self::Verified(expected) => {
                let current = File::open("/proc/thread-self/ns/net")?;
                if fd_identity(&current)? != *expected {
                    return Err(io::Error::other("fixed child network namespace mismatch"));
                }
                Ok(())
            }
        }
    }
}

fn run_in_pid_namespace_expecting(
    command: std::process::Command,
    timeout: std::time::Duration,
    namespace_reaped: &mut bool,
    expected_code: i32,
    disconnect_fd: Option<i32>,
    network: ChildNetwork,
) -> Result<(), Fault> {
    supervise_pid_namespace(
        command,
        timeout,
        namespace_reaped,
        expected_code,
        disconnect_fd,
        network,
        || false,
    )
}

fn supervise_pid_namespace(
    mut command: std::process::Command,
    timeout: std::time::Duration,
    namespace_reaped: &mut bool,
    expected_code: i32,
    disconnect_fd: Option<i32>,
    network: ChildNetwork,
    administrator_stop: impl Fn() -> bool,
) -> Result<(), Fault> {
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + timeout;
    let init = super::os::clone_pid_and_mount(network.create_namespace())?;
    if init == 0 {
        let success = network.verify_before_spawn().is_ok()
            && command
                .status()
                .is_ok_and(|status| status.code() == Some(expected_code));
        // Linux kills and reaps remaining namespace members when PID 1 exits.
        unsafe { libc::_exit(if success { 0 } else { 1 }) };
    }

    let mut stop_reason = None;
    loop {
        let mut status = 0;
        let flags = if stop_reason.is_some() {
            0
        } else {
            libc::WNOHANG
        };
        match unsafe { libc::waitpid(init, &mut status, flags) } {
            pid if pid == init => {
                if !libc::WIFEXITED(status) && !libc::WIFSIGNALED(status) {
                    continue;
                }
                *namespace_reaped = true;
                return if let Some(reason) = stop_reason {
                    Err(reason)
                } else if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                    Ok(())
                } else {
                    Err(Fault::Identity)
                };
            }
            0 => {
                let reason = if administrator_stop() {
                    Some(Fault::AdministratorStop)
                } else if let Some(fd) = disconnect_fd {
                    let mut event = libc::pollfd {
                        fd,
                        events: 0,
                        revents: 0,
                    };
                    let result = unsafe { libc::poll(&mut event, 1, 0) };
                    if result < 0
                        || event.revents & (libc::POLLERR | libc::POLLNVAL) != 0
                            && event.revents & libc::POLLHUP == 0
                    {
                        Some(Fault::Identity)
                    } else if event.revents & libc::POLLHUP != 0 {
                        Some(Fault::ReportEof)
                    } else {
                        None
                    }
                } else {
                    None
                };
                if reason.is_none() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                // The direct child's PID cannot be reused before waitpid reaps it.
                if unsafe { libc::kill(init, libc::SIGKILL) } < 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        return Err(error.into());
                    }
                }
                stop_reason = Some(reason.unwrap_or(Fault::ReportTimeout));
            }
            _ => {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error.into());
                }
            }
        }
    }
}

fn isolated_command(
    root: &Path,
    executable: &str,
    stdout: File,
    stderr: File,
    diagnostic: Diagnostic,
) -> Result<std::process::Command, Fault> {
    use std::{
        ffi::CString,
        os::unix::process::CommandExt,
        process::{Command, Stdio},
    };
    let child_root = CString::new(root.as_os_str().as_bytes()).map_err(|_| Fault::Path)?;
    let proc_path =
        CString::new(root.join("proc").as_os_str().as_bytes()).map_err(|_| Fault::Path)?;
    let tmp_path =
        CString::new(root.join("tmp").as_os_str().as_bytes()).map_err(|_| Fault::Path)?;
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env("HOME", "/home/fixture")
        .env(
            "CLAUDE_CONFIG_DIR",
            if diagnostic == Diagnostic::ConfigControl {
                "/home/fixture/ordinary"
            } else {
                "/home/fixture/config"
            },
        )
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    let (uid, gid) = if diagnostic == Diagnostic::PtyOtherUid {
        (65534, 65534)
    } else {
        (UID, GID)
    };
    // The executable, environment and chroot are fixed, and the child drops
    // all host descriptors at exec apart from stdio.
    unsafe {
        command.pre_exec(move || {
            let limit = libc::rlimit {
                rlim_cur: 4096,
                rlim_max: 4096,
            };
            if matches!(
                diagnostic,
                Diagnostic::ConfigControl | Diagnostic::ConfigIsolated
            ) && libc::mount(
                c"proc".as_ptr(),
                proc_path.as_ptr(),
                c"proc".as_ptr(),
                libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                std::ptr::null(),
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if matches!(
                diagnostic,
                Diagnostic::ConfigControl | Diagnostic::ConfigIsolated
            ) && libc::mount(
                c"tmpfs".as_ptr(),
                tmp_path.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                c"size=1048576,nr_inodes=64,mode=1777".as_ptr().cast(),
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::chroot(child_root.as_ptr()) < 0
                || libc::chdir(
                    if matches!(
                        diagnostic,
                        Diagnostic::Version
                            | Diagnostic::Pty
                            | Diagnostic::PtyWithLoginArtifacts
                            | Diagnostic::PtyOtherUid
                    ) {
                        c"/home/fixture"
                    } else {
                        c"/work"
                    }
                    .as_ptr(),
                ) < 0
                || libc::setgroups(0, std::ptr::null()) < 0
                || libc::setresgid(gid, gid, gid) < 0
                || libc::setresuid(uid, uid, uid) < 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
                || libc::setrlimit(libc::RLIMIT_FSIZE, &limit) < 0
                || libc::syscall(
                    libc::SYS_close_range,
                    3_u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(command)
}

fn run_child(root: &Path, scratch: &Path, namespace_reaped: &mut bool) -> Result<(), Fault> {
    let stdout = scratch.join("stdout");
    let stderr = scratch.join("stderr");
    let mut command = isolated_command(
        root,
        "/bin/claude",
        File::create(&stdout)?,
        File::create(&stderr)?,
        Diagnostic::Version,
    )?;
    command.arg("--version");
    run_in_pid_namespace(
        command,
        std::time::Duration::from_secs(12),
        namespace_reaped,
    )?;
    if fs::read(stdout)? != b"2.1.325 (Claude Code)\n" || fs::metadata(stderr)?.len() != 0 {
        return Err(Fault::Identity);
    }
    Ok(())
}

const CONTROL_FILES: &[&str] = &[
    "home/fixture/ordinary/settings.json",
    "work/.claude/settings.json",
    "work/.claude/settings.local.json",
    "work/.mcp.json",
];
const MCP_CONFIG: &[u8] =
    br#"{"mcpServers":{"probe":{"command":"/bin/busybox","args":["sh","/probe/run"]}}}"#;
const MCP_PROBE: &[u8] = br#"exec 3>/probe/events
echo started >&3
while IFS= read -r line; do
    case "$line" in
        *'"method":"initialize"'*)
            echo initialize >&3
            printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"offline-probe","version":"1"}}}' ;;
        *'"method":"notifications/initialized"'*) echo initialized >&3 ;;
    esac
done
"#;

fn fixture_fifo(path: &Path) -> Result<File, Fault> {
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| Fault::Path)?;
    super::os::syscall(unsafe { libc::mkfifo(name.as_ptr(), 0o600) })?;
    own(path, 0o600)?;
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?)
}

struct ConfigFixture {
    events: File,
    opened: Option<(File, Vec<i32>)>,
}

impl ConfigFixture {
    fn prepare(root: &Path, diagnostic: Diagnostic) -> Result<Self, Fault> {
        use std::ffi::CString;
        for path in ["proc", "tmp", "work", "probe"] {
            fs::create_dir(root.join(path))?;
        }
        fs::write(root.join("probe/run"), MCP_PROBE)?;
        let events = fixture_fifo(&root.join("probe/events"))?;
        if diagnostic == Diagnostic::ConfigIsolated {
            fs::write(root.join("probe/mcp.json"), MCP_CONFIG)?;
            for path in CONTROL_FILES {
                if root.join(path).try_exists()? {
                    return Err(Fault::Identity);
                }
            }
            return Ok(Self {
                events,
                opened: None,
            });
        }
        fs::create_dir(root.join("home/fixture/ordinary"))?;
        fs::write(root.join(CONTROL_FILES[0]), b"{}\n")?;
        fs::create_dir(root.join("work/.claude"))?;
        fs::write(root.join(CONTROL_FILES[1]), b"{}\n")?;
        fs::write(root.join(CONTROL_FILES[2]), b"{}\n")?;
        fs::write(root.join(CONTROL_FILES[3]), MCP_CONFIG)?;
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        super::os::syscall(fd)?;
        let notify = unsafe { File::from_raw_fd(fd) };
        let mut watches = Vec::new();
        for path in CONTROL_FILES {
            let path =
                CString::new(root.join(path).as_os_str().as_bytes()).map_err(|_| Fault::Path)?;
            let watch = unsafe { libc::inotify_add_watch(fd, path.as_ptr(), libc::IN_OPEN) };
            super::os::syscall(watch)?;
            watches.push(watch);
        }
        Ok(Self {
            events,
            opened: Some((notify, watches)),
        })
    }

    fn run(
        mut self,
        root: &Path,
        scratch: &Path,
        namespace_reaped: &mut bool,
        diagnostic: Diagnostic,
    ) -> Result<(), Fault> {
        let stdout = scratch.join("stdout");
        let stderr = scratch.join("stderr");
        let mut command = isolated_command(
            root,
            "/bin/claude",
            File::create(&stdout)?,
            File::create(&stderr)?,
            diagnostic,
        )?;
        if diagnostic == Diagnostic::ConfigIsolated {
            command.args([
                "--setting-sources",
                "",
                "--strict-mcp-config",
                "--mcp-config",
                "/probe/mcp.json",
            ]);
        }
        command.args(["--print", "Offline diagnostic only"]);
        run_in_pid_namespace_expecting(
            command,
            std::time::Duration::from_secs(12),
            namespace_reaped,
            1,
            None,
            ChildNetwork::NewOffline,
        )?;
        let output = fs::read(stdout)?;
        let errors = fs::read(stderr)?;
        if output != "Not logged in · Please run /login\n".as_bytes() || !errors.is_empty() {
            return Err(Fault::Identity);
        }
        let mut buffer = [0; 128];
        let size = self.events.read(&mut buffer)?;
        let events = &buffer[..size];
        match self.opened {
            Some((mut notify, mut watches)) => {
                let mut buffer = [0; 4096];
                let size = notify.read(&mut buffer)?;
                if size == buffer.len() || size % 16 != 0 {
                    return Err(Fault::Identity);
                }
                for event in buffer[..size].chunks_exact(16) {
                    if event[12..16] != [0; 4] {
                        return Err(Fault::Identity);
                    }
                    let watch = i32::from_ne_bytes(event[..4].try_into().unwrap());
                    let mask = u32::from_ne_bytes(event[4..8].try_into().unwrap());
                    if mask & libc::IN_Q_OVERFLOW != 0 {
                        return Err(Fault::Identity);
                    }
                    if mask == libc::IN_OPEN {
                        watches.retain(|&pending| pending != watch);
                    }
                }
                if !watches.is_empty()
                    || !matches!(
                        events,
                        b"started\n"
                            | b"started\ninitialize\n"
                            | b"started\ninitialize\ninitialized\n"
                    )
                {
                    return Err(Fault::Identity);
                }
            }
            None if events == b"started\ninitialize\ninitialized\n" => {}
            None => return Err(Fault::Identity),
        }
        Ok(())
    }
}

fn artifacts_for(diagnostic: Diagnostic) -> &'static [Artifact<'static>] {
    if diagnostic == Diagnostic::Pty {
        &[]
    } else {
        ARTIFACTS
    }
}

const LOGIN_EXECUTABLE: &str = "/bin/claude";
const LOGIN_ARGS: [&str; 2] = ["auth", "login"];

#[derive(serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct FixtureStopTarget {
    permit_id: String,
    device: u64,
    inode: u64,
}

struct FixtureStop {
    request: std::path::PathBuf,
    target: FixtureStopTarget,
    signed: Option<FixtureRevocation>,
}

struct FixtureRevocation {
    key: [u8; 32],
    id: u128,
    target_id: String,
    manifest: String,
    revision: u64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRevocationNotice {
    payload: String,
    signature: Vec<u8>,
}

impl FixtureStop {
    fn requested(&self) -> bool {
        if let Some(signed) = &self.signed {
            let verified = (|| -> io::Result<()> {
                let notice: FixtureRevocationNotice =
                    serde_json::from_slice(&read_login_input(&self.request, 4096)?)
                        .map_err(io::Error::other)?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(io::Error::other)?
                    .as_secs();
                verify_revocation_state_with_disposition(
                    &signed.key,
                    notice.payload.as_bytes(),
                    &notice.signature,
                    (
                        signed.revision,
                        &signed.manifest,
                        signed.id,
                        &signed.target_id,
                    ),
                    now,
                    true,
                )?;
                Ok(())
            })();
            return verified.is_ok();
        }
        read_login_input(&self.request, 512)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<FixtureStopTarget>(&bytes).ok())
            .is_some_and(|request| request == self.target)
    }
}

struct FixtureGrant {
    id: u128,
    ledger: File,
    record: File,
}

impl FixtureGrant {
    // This descriptor comes only from consume, after it synced both objects.
    fn verify_consumed_record(&self) -> io::Result<()> {
        let current = open_login_child(
            &self.ledger,
            std::ffi::OsStr::new(&format!("{:032x}", self.id)),
            libc::O_PATH,
        )?;
        if fd_identity(&current)? != fd_identity(&self.record)? {
            return Err(io::Error::other(
                "synthetic consumed record identity mismatch",
            ));
        }
        Ok(())
    }

    fn claim(&self, stage: &File) -> io::Result<[u8; 48]> {
        let mut claim = [0; 48];
        claim[..16].copy_from_slice(&self.id.to_be_bytes());
        let ledger = fd_identity(&self.ledger)?;
        let stage = fd_identity(stage)?;
        for (chunk, value) in claim[16..]
            .chunks_exact_mut(8)
            .zip([ledger.0, ledger.1, stage.0, stage.1])
        {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        Ok(claim)
    }

    fn verify(&self, control: &mut UnixStream, work: &WorkArea) -> io::Result<()> {
        let mut claim = [0; 48];
        control.read_exact(&mut claim)?;
        self.verify_consumed_record()?;
        let stage = open_login_child(&work.pinned, std::ffi::OsStr::new("artifact-busybox"), 0)?;
        if claim != self.claim(&stage)? {
            return Err(io::Error::other("synthetic grant identity mismatch"));
        }
        if !stage.metadata()?.is_file() {
            return Err(io::Error::other(
                "synthetic grant stage is not a regular file",
            ));
        }
        let stage = File::open(format!("/proc/self/fd/{}", stage.as_raw_fd()))?;
        verify_artifact(&stage, &BUSYBOX).map_err(|fault| io::Error::other(fault.reason()))
    }
}

struct FixtureClosure {
    case: local_auth::Case,
    generation: [u8; 48],
    permit_id: Option<u128>,
    work_identity: (u64, u64),
    config_identity: (u64, u64),
}

impl FixtureClosure {
    fn new(
        case: local_auth::Case,
        work: &WorkArea,
        config: &writable_config::Generation,
        permit_id: Option<u128>,
    ) -> io::Result<Self> {
        let (work_device, work_inode) = fd_identity(&work.pinned)?;
        let (config_device, config_inode) = config.identity()?;
        let mut generation = [0; 48];
        generation[32..].copy_from_slice(&permit_id.unwrap_or_default().to_be_bytes());
        for (chunk, value) in generation[..32].chunks_exact_mut(8).zip([
            work_device,
            work_inode,
            config_device,
            config_inode,
        ]) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        Ok(Self {
            case,
            generation,
            permit_id,
            work_identity: (work_device, work_inode),
            config_identity: (config_device, config_inode),
        })
    }

    fn report(&self, control: &mut UnixStream) -> io::Result<()> {
        let mut generation = self.generation;
        match self.case {
            local_auth::Case::MissingClosure => return Ok(()),
            local_auth::Case::WrongClosureGeneration => generation[31] ^= 1,
            _ => {}
        }
        control.write_all(&generation)
    }

    fn verify(&self, control: &mut UnixStream, consumed: Option<&FixtureGrant>) -> io::Result<()> {
        let mut generation = [0; 48];
        control.read_exact(&mut generation).map_err(|error| {
            io::Error::other(format!("synthetic gateway closure unconfirmed: {error}"))
        })?;
        if generation != self.generation {
            return Err(io::Error::other(
                "synthetic gateway closure generation mismatch",
            ));
        }
        if let Some(id) = self.permit_id {
            let receipt = consumed.filter(|receipt| receipt.id == id);
            let ledger_present = receipt
                .map(|receipt| receipt.verify_consumed_record())
                .transpose()?
                .is_some();
            let ledger_synced = receipt
                .filter(|_| !matches!(self.case, local_auth::Case::MissingConsumptionSync))
                .map(|_| true);
            if matches!(
                self.case,
                local_auth::Case::SignedPermit
                    | local_auth::Case::SignedTls
                    | local_auth::Case::SignedTlsExpiry
                    | local_auth::Case::SignedTlsRevocation
                    | local_auth::Case::MissingConsumptionSync
            ) {
                eprintln!(
                    "synthetic recovery evidence: {}",
                    serde_json::json!({
                        "permit_id": format!("{id:032x}"),
                        "work_identity": self.work_identity,
                        "config_identity": self.config_identity,
                        "gateway_closure_confirmed": true,
                        "ledger_present": ledger_present,
                        "ledger_synced": ledger_synced,
                    })
                );
            }
            if ledger_synced != Some(true) {
                return Err(io::Error::other("synthetic consumption sync unconfirmed"));
            }
        }
        Ok(())
    }
}

struct FixturePermit {
    verified_executable: Option<File>,
    grant: Option<FixtureGrant>,
    closure: Option<FixtureClosure>,
    administrator_stop: Option<FixtureStop>,
    expires: std::time::Instant,
    executable_digest: &'static str,
    arguments: [&'static str; 2],
    authority: &'static str,
}

impl FixturePermit {
    fn validate(&self) -> io::Result<()> {
        if std::time::Instant::now() >= self.expires {
            return Err(io::Error::other("synthetic permit expired"));
        }
        if self.executable_digest != BUSYBOX.sha256
            || self.arguments != LOGIN_ARGS
            || self.authority != login_connect::AUTHORITY
        {
            return Err(io::Error::other("synthetic permit scope mismatch"));
        }
        Ok(())
    }
}

fn configure_login_command(command: &mut std::process::Command) {
    command
        .args(LOGIN_ARGS)
        .env("HTTPS_PROXY", local_auth::PROXY_URL)
        .env("HTTP_PROXY", local_auth::PROXY_URL)
        .env("NO_PROXY", "");
}

fn fixed_login_command(root: &Path) -> Result<std::process::Command, Fault> {
    use std::process::Stdio;
    // Send diagnostics to the same already-verified terminal as stdout.
    let diagnostic_fd = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if diagnostic_fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let diagnostic_output = unsafe { File::from_raw_fd(diagnostic_fd) };
    let mut command = isolated_command(
        root,
        LOGIN_EXECUTABLE,
        OpenOptions::new().write(true).open("/dev/null")?,
        diagnostic_output,
        Diagnostic::PtyWithLoginArtifacts,
    )?;
    configure_login_command(&mut command);
    command.stdin(Stdio::inherit()).stdout(Stdio::inherit());
    Ok(command)
}

fn run_pty_child(
    root: &Path,
    namespace_reaped: &mut bool,
    mut events: File,
    private_config: Option<&writable_config::Generation>,
    network: ChildNetwork,
    administrator_stop: Option<&FixtureStop>,
) -> Result<(), Fault> {
    use std::{process::Stdio, time::Duration};
    let mut command = isolated_command(
        root,
        "/bin/busybox",
        OpenOptions::new().write(true).open("/dev/null")?,
        OpenOptions::new().write(true).open("/dev/null")?,
        Diagnostic::Pty,
    )?;
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .args([
            "sh",
            "-eu",
            "-c",
            r#"
        test "$HOME" = /home/fixture
        test "$CLAUDE_CONFIG_DIR" = /home/fixture/config
        test -r "$CLAUDE_CONFIG_DIR/settings.json"
        test "$(/bin/busybox id -u)" = 999
        test "$(/bin/busybox id -g)" = 988
        if test "$1" = writable; then
            test ! -e /home/ubuntu
            test ! -e "$2/settings.json"
            test ! -e "$CLAUDE_CONFIG_DIR/write-probe"
            umask 077
            : > "$CLAUDE_CONFIG_DIR/write-probe"
            if (: > "$HOME/outside-probe"); then exit 1; fi
        fi
        if test "$3" = local-auth; then
            shift 3
            test "$#" = 2
            test "$1" = auth
            test "$2" = login
            test "$HTTPS_PROXY" = http://127.0.0.1:39271
            test "$HTTP_PROXY" = "$HTTPS_PROXY"
            test -z "$NO_PROXY"
            /bin/busybox nc -w 1 127.0.0.1 39271 -e /bin/busybox sh -eu -c '
                printf "CONNECT invalid.example:443 HTTP/1.1\r\n\r\n"
                IFS= read -r status
                test "$status" = "$(printf "HTTP/1.1 403 Forbidden\r")"
            '
            /bin/busybox nc -w 1 127.0.0.1 39271 -e /bin/busybox sh -eu -c '
                printf "CONNECT platform.claude.com:443 HTTP/1.1\r\nHost: platform.claude.com:443\r\n\r\nPING"
                IFS= read -r status
                test "$status" = "$(printf "HTTP/1.1 200 Connection Established\r")"
                IFS= read -r separator
                test "$separator" = "$(printf "\r")"
                IFS= read -r answer
                test "$answer" = ACK
                printf "ready\n" > /tunnel-ready
                IFS= read -r unexpected
                exit 1
            ' &
            tunnel=$!
            IFS= read -r established < /tunnel-ready
            test "$established" = ready
            kill -0 "$tunnel"
            for port in 39272 39273 39274; do
                if /bin/busybox nc -w 1 127.0.0.1 "$port" -e /bin/busybox true; then exit 1; fi
            done
        fi
        printf 'fixture-ready\n'
        IFS= read -r request
        test "$request" = probe
        if test -n "${tunnel:-}"; then kill -0 "$tunnel"; fi
        /bin/busybox sleep 60 &
        descendant=$!
        kill -0 "$descendant"
        printf 'R' > /pty-ready
        printf 'fixture-response\n'
        wait "$descendant"
        "#,
        ])
        .arg("fixed-pty")
        .arg(if private_config.is_some() {
            "writable"
        } else {
            "readonly"
        })
        .arg(private_config.map_or(Path::new("/"), |config| &config.path))
        .arg(match network {
            ChildNetwork::NewOffline => "offline",
            ChildNetwork::Verified(_) => "local-auth",
        });
    if matches!(network, ChildNetwork::Verified(_)) {
        configure_login_command(&mut command);
    }
    match supervise_pid_namespace(
        command,
        Duration::from_secs(12),
        namespace_reaped,
        0,
        Some(libc::STDIN_FILENO),
        network,
        || administrator_stop.is_some_and(FixtureStop::requested),
    ) {
        Err(reason @ (Fault::ReportEof | Fault::AdministratorStop)) => {
            let mut buffer = [0; 2];
            let size = events.read(&mut buffer)?;
            if &buffer[..size] != b"R" {
                return Err(Fault::Identity);
            }
            if matches!(reason, Fault::AdministratorStop) {
                eprintln!("synthetic administrator stop: PID namespace reaped");
            }
            Ok(())
        }
        Err(error) => Err(error),
        Ok(()) => Err(Fault::Identity),
    }
}

fn verify_other_uid_denied(root: &Path, namespace_reaped: &mut bool) -> Result<(), Fault> {
    let mut command = isolated_command(
        root,
        "/bin/busybox",
        OpenOptions::new().write(true).open("/dev/null")?,
        OpenOptions::new().write(true).open("/dev/null")?,
        Diagnostic::PtyOtherUid,
    )?;
    command.args([
        "sh",
        "-eu",
        "-c",
        r#"
        test "$(/bin/busybox id -u)" = 65534
        test -x "$HOME"
        test ! -x "$CLAUDE_CONFIG_DIR"
        test ! -r "$CLAUDE_CONFIG_DIR/settings.json"
        test ! -w "$CLAUDE_CONFIG_DIR"
        if /bin/busybox cat "$CLAUDE_CONFIG_DIR/settings.json"; then exit 1; fi
        if (: > "$CLAUDE_CONFIG_DIR/foreign-probe"); then exit 1; fi
    "#,
    ]);
    run_in_pid_namespace(command, std::time::Duration::from_secs(3), namespace_reaped)
}

fn verify_mount_table_for(
    root: &Path,
    diagnostic: Diagnostic,
    writable: bool,
) -> Result<(), Fault> {
    use std::collections::BTreeSet;
    let mut expected = BTreeSet::from([root.to_path_buf()]);
    expected.extend(
        artifacts_for(diagnostic)
            .iter()
            .flat_map(|entry| entry.targets)
            .map(|path| root.join(path)),
    );
    if diagnostic != Diagnostic::Version {
        expected.insert(root.join("bin/busybox"));
    }
    let config = root.join("home/fixture/config");
    if writable {
        expected.insert(config.clone());
    }
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let mut columns = line.split_whitespace().skip(4);
        let Some(target) = columns.next().map(Path::new) else {
            return Err(Fault::Identity);
        };
        if !target.starts_with(root) {
            continue;
        }
        let flags = columns.next().ok_or(Fault::Identity)?;
        let flags: BTreeSet<_> = flags.split(',').collect();
        let required = if writable && target == config {
            &["rw", "nosuid", "nodev", "noexec"][..]
        } else {
            &["ro", "nosuid", "nodev"][..]
        };
        if !expected.remove(target) || !required.iter().all(|flag| flags.contains(flag)) {
            return Err(Fault::Identity);
        }
    }
    if !expected.is_empty() {
        return Err(Fault::Identity);
    }
    Ok(())
}

fn mount_artifact(root: &Path, artifact: &Artifact<'_>, staged: &File) -> Result<(), Fault> {
    use super::capsule;
    let identity = capsule::library_identity(staged)?;
    for target in artifact.targets {
        let path = root.join(target);
        drop(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)?,
        );
        capsule::bind_read_only(staged, &path)?;
        if capsule::verify_bound_file(&path, |file| verify_artifact(file, artifact))? != identity {
            return Err(Fault::Identity);
        }
    }
    Ok(())
}

fn run_in_root(
    scratch: &Path,
    root: &Path,
    control: &mut UnixStream,
    namespace_reaped: &mut bool,
) -> Result<(u64, u64), Fault> {
    run_fixture(
        scratch,
        root,
        control,
        namespace_reaped,
        Diagnostic::Version,
    )
}

fn run_fixture(
    scratch: &Path,
    root: &Path,
    control: &mut UnixStream,
    namespace_reaped: &mut bool,
    diagnostic: Diagnostic,
) -> Result<(u64, u64), Fault> {
    run_fixture_with_config(
        scratch,
        root,
        control,
        namespace_reaped,
        diagnostic,
        FixtureStaging::default(),
        None,
    )
}

#[derive(Default)]
struct FixtureStaging<'a> {
    config: Option<&'a writable_config::Generation>,
    verified_artifacts: Option<&'a [File]>,
}

fn pin_artifacts(artifacts: &[Artifact<'_>]) -> Result<Vec<File>, Fault> {
    artifacts.iter().map(verify_fixed_artifact).collect()
}

fn stage_fixed_artifacts(
    scratch: &Path,
    root: &Path,
    artifacts: &[Artifact<'_>],
    verified: Option<&[File]>,
) -> Result<(), Fault> {
    if verified.is_some_and(|files| files.len() != artifacts.len()) {
        return Err(Fault::Identity);
    }
    for (index, artifact) in artifacts.iter().enumerate() {
        let destination = scratch.join(format!("artifact-{index}"));
        let staged = match verified {
            Some(files) => stage_pinned_artifact(&files[index], artifact, &destination),
            None => stage_artifact(artifact, &destination),
        }
        .inspect_err(|fault| stage_failure(artifact.source, fault))?;
        mount_artifact(root, artifact, &staged)
            .inspect_err(|fault| stage_failure("artifact_mount", fault))?;
    }
    Ok(())
}

fn run_fixture_with_config(
    scratch: &Path,
    root: &Path,
    control: &mut UnixStream,
    namespace_reaped: &mut bool,
    diagnostic: Diagnostic,
    staging: FixtureStaging<'_>,
    local_auth: Option<(local_auth::Case, &File, &FixturePermit)>,
) -> Result<(u64, u64), Fault> {
    use super::os;
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    for dir in [
        "bin",
        "lib",
        "lib/x86_64-linux-gnu",
        "lib64",
        "home",
        "home/fixture",
        "home/fixture/config",
    ] {
        fs::create_dir(root.join(dir))?;
    }
    stage_fixed_artifacts(
        scratch,
        root,
        artifacts_for(diagnostic),
        staging.verified_artifacts,
    )?;
    let private_config = staging.config;
    let staged_busybox = if diagnostic != Diagnostic::Version {
        let destination = scratch.join("artifact-busybox");
        let staged =
            match local_auth.and_then(|(_, _, permit)| permit.verified_executable.as_ref()) {
                Some(input) => stage_pinned_artifact(input, &BUSYBOX, &destination),
                None => stage_artifact(&BUSYBOX, &destination),
            }
            .inspect_err(|fault| stage_failure("busybox", fault))?;
        mount_artifact(root, &BUSYBOX, &staged)?;
        Some(staged)
    } else {
        None
    };
    if let Some(config) = private_config {
        own(&root.join("home/fixture"), 0o755)?;
        config.bind(root)?;
    } else {
        let settings = root.join("home/fixture/config/settings.json");
        fs::write(&settings, b"{}\n")?;
        own(&root.join("home/fixture"), 0o700)?;
        own(&root.join("home/fixture/config"), 0o700)?;
        own(&settings, 0o600)?;
    }
    let pty_events = if matches!(
        diagnostic,
        Diagnostic::Pty | Diagnostic::PtyWithLoginArtifacts
    ) {
        // BusyBox ash opens /dev/null for a background job's stdin.
        fs::create_dir(root.join("dev"))?;
        File::create(root.join("dev/null"))?;
        if local_auth.is_some() {
            fixture_fifo(&root.join("tunnel-ready"))?;
        }
        Some(fixture_fifo(&root.join("pty-ready"))?)
    } else {
        None
    };
    let config = if matches!(
        diagnostic,
        Diagnostic::Version | Diagnostic::Pty | Diagnostic::PtyWithLoginArtifacts
    ) {
        None
    } else {
        Some(ConfigFixture::prepare(root, diagnostic)?)
    };
    os::mount(
        None,
        root,
        None,
        libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        None,
    )?;
    verify_mount_table_for(root, diagnostic, private_config.is_some())?;
    if diagnostic == Diagnostic::PtyWithLoginArtifacts {
        // Build the production invocation after validating the mount table.
        // The fixture exercises the same arguments and environment with BusyBox.
        let command = fixed_login_command(root)?;
        if !root
            .join(
                Path::new(command.get_program())
                    .strip_prefix("/")
                    .map_err(|_| Fault::Path)?,
            )
            .is_file()
        {
            return Err(Fault::Identity);
        }
    }
    let before = if private_config.is_none() {
        Some(audit_settings(root)?)
    } else {
        None
    };
    let policy = local_auth
        .map(|(case, _, _)| local_auth::LocalPolicy::setup(case))
        .transpose()
        .map_err(Fault::from)
        .inspect_err(|fault| stage_failure("local_policy", fault))?;
    let launch = (|| {
        let gateway = match (&policy, local_auth) {
            (Some(policy), Some((case, upstream_network, permit))) if case.needs_gateway() => Some(
                policy
                    .start_gateway(
                        case,
                        upstream_network,
                        permit.expires,
                        permit.administrator_stop.as_ref(),
                    )
                    .map_err(|error| {
                        eprintln!("local auth gateway refused before grant: {error}");
                        error
                    })?,
            ),
            _ => None,
        };
        let network = if let Some((case, _, permit)) = local_auth {
            permit.validate().inspect_err(|error| {
                eprintln!("local auth refused before grant: {error}");
            })?;
            if matches!(case, local_auth::Case::PermitExpiresBeforeGrant) {
                // Exercise the final grant gate after successful staging.
                std::thread::sleep(
                    permit
                        .expires
                        .saturating_duration_since(std::time::Instant::now()),
                );
            }
            let mut claim = permit
                .grant
                .as_ref()
                .map(|grant| {
                    grant.claim(
                        staged_busybox
                            .as_ref()
                            .ok_or_else(|| io::Error::other("synthetic stage missing"))?,
                    )
                })
                .transpose()?;
            if let Some(claim) = claim.as_mut() {
                match case {
                    local_auth::Case::WrongGrantId => claim[0] ^= 1,
                    local_auth::Case::WrongGrantLedger => claim[16] ^= 1,
                    local_auth::Case::WrongGrantStage => claim[32] ^= 1,
                    _ => {}
                }
            }
            ChildNetwork::Verified(local_auth::request(control, case, claim.as_ref())?)
        } else {
            request_cli_start(control)?;
            ChildNetwork::NewOffline
        };
        if private_config.is_some() {
            verify_other_uid_denied(root, namespace_reaped)?;
            *namespace_reaped = false;
        }
        if let Some(config) = config {
            config.run(root, scratch, namespace_reaped, diagnostic)?;
        } else if let Some(events) = pty_events {
            run_pty_child(
                root,
                namespace_reaped,
                events,
                private_config,
                network,
                local_auth.and_then(|(_, _, permit)| permit.administrator_stop.as_ref()),
            )?;
            if let Some(gateway) = gateway {
                gateway
                    .finish()
                    .inspect_err(|error| eprintln!("synthetic gateway finish: {error}"))?;
            }
        } else {
            run_child(root, scratch, namespace_reaped)?;
        }
        Ok::<_, Fault>(())
    })();
    if let Some(policy) = policy {
        policy.finish(launch.is_ok())?;
        if launch.is_ok() {
            eprintln!(
                "local auth: tunnel accepted, other host refused, three direct ports denied; listeners and policy closed"
            );
        } else {
            eprintln!("local auth: accepts=0,0,0,0 denied=0; listeners and policy closed");
        }
    }
    launch?;
    if let Some(before) = before
        && audit_settings(root)? != before
    {
        return Err(Fault::Identity);
    }

    let path = CString::new(root.as_os_str().as_bytes()).map_err(|_| Fault::Path)?;
    let mut flags = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    os::syscall(unsafe { libc::statvfs(path.as_ptr(), flags.as_mut_ptr()) })?;
    let usage = unsafe { flags.assume_init() };
    if usage.f_blocks * usage.f_frsize != 16777216 || usage.f_files != 128 {
        return Err(Fault::Identity);
    }
    Ok((
        (usage.f_blocks - usage.f_bfree) * usage.f_frsize,
        usage.f_files - usage.f_ffree,
    ))
}

fn confirm_offline_network() -> Result<(), Fault> {
    use std::ffi::CStr;
    let mut interfaces = std::ptr::null_mut();
    super::os::syscall(unsafe { libc::getifaddrs(&mut interfaces) })?;
    let mut current = interfaces;
    let mut has_loopback = false;
    let mut offline = true;
    while let Some(interface) = unsafe { current.as_ref() } {
        let name = unsafe { CStr::from_ptr(interface.ifa_name) };
        let flags = interface.ifa_flags as libc::c_int;
        if name != c"lo" || flags & libc::IFF_LOOPBACK == 0 || flags & libc::IFF_UP != 0 {
            offline = false;
            break;
        }
        has_loopback = true;
        current = interface.ifa_next;
    }
    unsafe { libc::freeifaddrs(interfaces) };
    if !offline || !has_loopback {
        return Err(Fault::Identity);
    }
    Ok(())
}

fn trial_with_detach<T>(
    scratch: &Path,
    detached: &mut bool,
    execute: impl FnOnce(&Path, &Path) -> Result<T, Fault>,
) -> Result<T, Fault> {
    use super::{capsule, os};
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    os::syscall(unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWNET) })
        .inspect_err(|fault| stage_failure("namespace", fault))?;
    confirm_offline_network().inspect_err(|fault| stage_failure("offline_network", fault))?;
    capsule::make_mounts_private()
        .inspect_err(|fault| stage_failure("mount_propagation", fault))?;
    let root = scratch.join("root");
    fs::create_dir(&root)?;
    capsule::mount_root(&root).inspect_err(|fault| stage_failure("root_mount", fault))?;
    let result = execute(scratch, &root);
    // Detach the complete private mount tree before touching staging files.
    let path = CString::new(root.as_os_str().as_bytes()).map_err(|_| Fault::Path)?;
    os::syscall(unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) })?;
    *detached = true;
    result
}

#[cfg(test)]
fn trial<T>(
    scratch: &Path,
    execute: impl FnOnce(&Path, &Path) -> Result<T, Fault>,
) -> Result<T, Fault> {
    trial_with_detach(scratch, &mut false, execute)
}

#[cfg(test)]
fn cleanup_trial(scratch: &Path) -> io::Result<()> {
    // Retain a mounted tree on unmount failure. Its private namespace
    // vanishes at process exit, and an error cannot be reported as success.
    fs::read_to_string("/proc/thread-self/mountinfo").and_then(|table| {
        if table.lines().any(|row| {
            row.split_whitespace()
                .nth(4)
                .is_some_and(|p| p.starts_with(scratch.to_str().unwrap()))
        }) {
            return Err(io::Error::other("trial mounts remain"));
        }
        fs::remove_dir_all(scratch)
    })
}

const WORK_PARENT: &str = "/var/lib/tempest-claude-version-work";

fn directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

struct WorkArea {
    path: PathBuf,
    name: std::ffi::CString,
    pinned: File,
}

impl WorkArea {
    fn create(parent: &File, parent_path: &Path) -> io::Result<Self> {
        let name = format!("trial-{}", super::private_io::random_hex()?);
        let name = std::ffi::CString::new(name)?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let path = parent_path.join(std::ffi::OsStr::from_bytes(name.as_bytes()));
        Ok(Self {
            pinned: Self::open_at(parent, &name)?,
            path,
            name,
        })
    }

    fn open_at(parent: &File, name: &std::ffi::CStr) -> io::Result<File> {
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn remove(&self, parent: &File) -> io::Result<()> {
        let expected = self.pinned.metadata()?;
        let current = Self::open_at(parent, &self.name)?.metadata()?;
        if (expected.dev(), expected.ino()) != (current.dev(), current.ino())
            || current.uid() != 0
            || current.mode() & 0o7777 != 0o700
        {
            return Err(io::Error::other("offline work area identity changed"));
        }
        let path = self.path.as_os_str().as_bytes();
        for row in fs::read("/proc/thread-self/mountinfo")?.split(|&byte| byte == b'\n') {
            if let Some(mount) = row.split(|&byte| byte == b' ').nth(4)
                && (mount == path
                    || mount
                        .strip_prefix(path)
                        .is_some_and(|tail| tail.starts_with(b"/")))
            {
                return Err(io::Error::other("offline work mounts remain"));
            }
        }

        // The root-only parent lock spans identity validation and removal.
        // Other privileged writers must honor the same lock.
        let fd = self.pinned.as_raw_fd();
        let mut entries = Vec::new();
        for item in fs::read_dir(format!("/proc/self/fd/{fd}"))? {
            let item = item?;
            let name = item.file_name();
            let file_type = item.file_type()?;
            let flags = match name.as_bytes() {
                b"root" if file_type.is_dir() => {
                    if fs::read_dir(item.path())?.next().is_some() {
                        return Err(io::Error::other("offline root is not empty"));
                    }
                    libc::AT_REMOVEDIR
                }
                b"stdout" | b"stderr" | b"artifact-busybox" if file_type.is_file() => 0,
                name if file_type.is_file()
                    && (0..ARTIFACTS.len())
                        .any(|index| name == format!("artifact-{index}").as_bytes()) =>
                {
                    0
                }
                _ => return Err(io::Error::other("unexpected offline work entry")),
            };
            entries.push((std::ffi::CString::new(name.as_bytes())?, flags));
        }
        for (name, flags) in entries {
            unlink_at(fd, &name, flags)?;
        }
        unlink_at(parent.as_raw_fd(), &self.name, libc::AT_REMOVEDIR)
    }
}

fn unlink_at(fd: i32, name: &std::ffi::CStr, flags: i32) -> io::Result<()> {
    if unsafe { libc::unlinkat(fd, name.as_ptr(), flags) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn lock_parent(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::DirBuilderExt;
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let parent = directory(path)?;
    let metadata = parent.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
        return Err(io::Error::other("offline work parent must be root-private"));
    }
    if unsafe { libc::flock(parent.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(parent)
}

fn request_cli_start(control: &mut UnixStream) -> Result<(), Fault> {
    control.write_all(b"C")?;
    let mut grant = [0];
    control.read_exact(&mut grant)?;
    if grant != *b"G" {
        return Err(Fault::Identity);
    }
    Ok(())
}

fn fd_identity(namespace: &File) -> io::Result<(u64, u64)> {
    let metadata = namespace.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(test)]
fn verify_waiting_network(pid: libc::pid_t) -> io::Result<File> {
    verify_waiting_network_for(pid, false)
}
fn verify_waiting_network_for(pid: libc::pid_t, local_auth: bool) -> io::Result<File> {
    // The direct child is unreaped, so its PID cannot identify a replacement.
    let path = format!("/proc/{pid}/ns/net");
    let namespace = File::open(&path)?;
    let identity = fd_identity(&namespace)?;
    let original = File::open("/proc/thread-self/ns/net")?;
    if identity == fd_identity(&original)? {
        return Err(io::Error::other(
            "offline supervisor shares the grant issuer network",
        ));
    }

    let inspector = unsafe { libc::fork() };
    if inspector < 0 {
        return Err(io::Error::last_os_error());
    }
    if inspector == 0 {
        let entered = unsafe { libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET) } == 0;
        let verified = entered
            && if local_auth {
                local_auth::verify_policy().is_ok()
            } else {
                confirm_offline_network().is_ok()
            };
        unsafe { libc::_exit(i32::from(!verified)) };
    }
    let status = wait_for_supervisor(inspector)?;
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(io::Error::other(if local_auth {
            "fixed login policy or loopback inspection failed"
        } else {
            "offline network inspection failed"
        }));
    }
    if identity != fd_identity(&File::open(path)?)? {
        return Err(io::Error::other(
            "offline supervisor network changed during inspection",
        ));
    }
    Ok(namespace)
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineRecovery {
    RemovedBeforeGrant,
    RemovedAfterTermination,
    RetainedAfterGrant,
}

#[derive(Debug, serde::Serialize)]
pub struct OfflineObservation {
    pub expected_binary_sha256: &'static str,
    pub work_identity: (u64, u64),
    pub verified_network: Option<(u64, u64)>,
    pub grant_attempted: bool,
    pub supervisor_wait_status: i32,
    pub recovery: OfflineRecovery,
}

#[cfg(test)]
fn supervised(
    parent: &File,
    work: &WorkArea,
    execute: impl FnOnce(&Path, &Path, &mut UnixStream, &mut bool) -> Result<(u64, u64), Fault>,
) -> io::Result<(u64, u64)> {
    supervised_observed(parent, work, execute, &mut None)
}

fn supervised_observed(
    parent: &File,
    work: &WorkArea,
    execute: impl FnOnce(&Path, &Path, &mut UnixStream, &mut bool) -> Result<(u64, u64), Fault>,
    observation: &mut Option<OfflineObservation>,
) -> io::Result<(u64, u64)> {
    supervised_with_network(parent, work, execute, observation, None)
}

fn supervised_with_network(
    parent: &File,
    work: &WorkArea,
    execute: impl FnOnce(&Path, &Path, &mut UnixStream, &mut bool) -> Result<(u64, u64), Fault>,
    observation: &mut Option<OfflineObservation>,
    permit: Option<&FixturePermit>,
) -> io::Result<(u64, u64)> {
    const RECOVERABLE_FAILURE: i32 = 2;
    let local_auth = permit.is_some();
    let closure = permit.and_then(|permit| permit.closure.as_ref());
    let (mut outside, mut inside) = UnixStream::pair().or_else(|error| {
        work.remove(parent)?;
        Err(error)
    })?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let error = io::Error::last_os_error();
        work.remove(parent)?;
        return Err(error);
    }
    if pid == 0 {
        drop(outside);
        let mut namespace_reaped = false;
        let mut detached = false;
        let result = trial_with_detach(&work.path, &mut detached, |scratch, root| {
            execute(scratch, root, &mut inside, &mut namespace_reaped)
        });
        if namespace_reaped
            && detached
            && let Ok((bytes, inodes)) = result
        {
            let mut report = [0; 16];
            report[..8].copy_from_slice(&bytes.to_ne_bytes());
            report[8..].copy_from_slice(&inodes.to_ne_bytes());
            // The fixture returns success only after the gateway has been waited
            // for and the listeners and policy have been closed.
            if inside.write_all(&report).is_ok()
                && closure.is_none_or(|closure| closure.report(&mut inside).is_ok())
            {
                unsafe { libc::_exit(0) };
            }
        }
        // This exit status attests only to termination and mount detach.
        let exit = if namespace_reaped && detached {
            RECOVERABLE_FAILURE
        } else {
            1
        };
        unsafe { libc::_exit(exit) };
    }
    drop(inside);
    let mut message = [0];
    let mut report = [0; 16];
    let mut cli_granted = false;
    let mut verified_network = None;
    let mut termination_reported = false;
    let received = (|| -> io::Result<()> {
        // Treat the grant as issued before attempting delivery.
        outside.read_exact(&mut message)?;
        if message != *b"C" {
            return Err(io::Error::other("invalid offline start request"));
        }
        let verified_namespace = verify_waiting_network_for(pid, local_auth)?;
        let identity = fd_identity(&verified_namespace)?;
        if local_auth {
            local_auth::read_claim(&mut outside, identity)?;
        }
        verified_network = Some(identity);
        if let Some(permit) = permit {
            if let Some(grant) = &permit.grant {
                grant.verify(&mut outside, work)?;
            }
            permit.validate()?;
        }
        cli_granted = true;
        outside.write_all(b"G")?;
        if local_auth {
            local_auth::grant(&mut outside, identity)?;
        }
        outside.read_exact(&mut report)?;
        termination_reported = true;
        if let Some(closure) = closure {
            closure.verify(
                &mut outside,
                permit.and_then(|permit| permit.grant.as_ref()),
            )?;
        }
        Ok(())
    })();
    drop(outside);
    let status = wait_for_supervisor(pid)?;
    let exit_status = libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status));
    let completed = received.is_ok() && exit_status == Some(0);
    // A PID/mount-only failure attestation cannot authorize local-auth recovery.
    let recoverable_failure = !local_auth && exit_status == Some(RECOVERABLE_FAILURE);
    if !cli_granted || completed || recoverable_failure {
        work.remove(parent)?;
    }
    if let Ok(work_identity) = fd_identity(&work.pinned) {
        *observation = Some(OfflineObservation {
            expected_binary_sha256: ARTIFACTS[0].sha256,
            work_identity,
            verified_network,
            grant_attempted: cli_granted,
            supervisor_wait_status: status,
            recovery: if !cli_granted {
                OfflineRecovery::RemovedBeforeGrant
            } else if completed || recoverable_failure {
                OfflineRecovery::RemovedAfterTermination
            } else {
                OfflineRecovery::RetainedAfterGrant
            },
        });
    }
    if !completed {
        let outcome = if recoverable_failure {
            "offline CLI diagnostic failed; work removed after verified termination"
        } else if cli_granted {
            "offline supervisor failed after CLI grant; work retained"
        } else {
            "offline supervisor failed during staging; work removed"
        };
        let signal = if libc::WIFSIGNALED(status) {
            libc::WTERMSIG(status)
        } else {
            0
        };
        if local_auth && let Err(cause) = received {
            let termination = if termination_reported && exit_status == Some(0) {
                "; child and mount termination confirmed"
            } else {
                ""
            };
            return Err(io::Error::other(format!(
                "{outcome}; {cause}{termination}; signal={signal}"
            )));
        }
        return Err(io::Error::other(format!("{outcome}; signal={signal}")));
    }
    Ok((
        u64::from_ne_bytes(report[..8].try_into().unwrap()),
        u64::from_ne_bytes(report[8..].try_into().unwrap()),
    ))
}

fn wait_for_supervisor(pid: libc::pid_t) -> io::Result<i32> {
    let mut status = 0;
    loop {
        if unsafe { libc::waitpid(pid, &mut status, 0) } == pid {
            return Ok(status);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

pub(super) fn run() -> (std::process::ExitCode, Option<OfflineObservation>) {
    use std::process::ExitCode;
    if std::env::args_os().len() != 1 || unsafe { libc::geteuid() } != 0 {
        return (ExitCode::FAILURE, None);
    }
    let mut observation = None;
    let parent_path = Path::new(WORK_PARENT);
    let result = (|| {
        let parent = lock_parent(parent_path)?;
        let work = WorkArea::create(&parent, parent_path)?;
        supervised_observed(&parent, &work, run_in_root, &mut observation)
    })();
    let exit = match result {
        Ok((bytes, inodes)) => {
            println!(
                "{{\"version\":\"2.1.325\",\"uid\":{UID},\"gid\":{GID},\"tmpfs_bytes\":{bytes},\"tmpfs_inodes\":{inodes},\"offline_network_verified\":true,\"cleanup\":true}}"
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("offline fixture failed: {error}");
            ExitCode::FAILURE
        }
    };
    (exit, observation)
}

pub(super) fn run_config() -> std::process::ExitCode {
    use std::process::ExitCode;
    if std::env::args_os().len() != 1 || unsafe { libc::geteuid() } != 0 {
        return ExitCode::FAILURE;
    }
    let parent_path = Path::new(WORK_PARENT);
    let result = (|| {
        let parent = lock_parent(parent_path)?;
        for diagnostic in [Diagnostic::ConfigControl, Diagnostic::ConfigIsolated] {
            let work = WorkArea::create(&parent, parent_path)?;
            supervised_observed(
                &parent,
                &work,
                |scratch, root, control, reaped| {
                    run_fixture(scratch, root, control, reaped, diagnostic)
                },
                &mut None,
            )?;
        }
        Ok::<_, io::Error>(())
    })();
    match result {
        Ok(()) => {
            println!(
                r#"{{"control_config_open":true,"control_stdio_started":true,"ordinary_config_absent":true,"explicit_stdio_initialized":true,"authentication":"not_logged_in","cleanup":true}}"#
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("offline config fixture failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn verify_shared_terminal(input: libc::c_int, output: libc::c_int) -> io::Result<()> {
    fn identity(fd: libc::c_int) -> io::Result<(libc::dev_t, libc::ino_t, libc::dev_t)> {
        if unsafe { libc::isatty(fd) } != 1 {
            return Err(io::Error::last_os_error());
        }
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(fd, filesystem.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        const DEVPTS_MAGIC: libc::c_long = 0x1cd1;
        let mut master_index: libc::c_uint = 0;
        if unsafe { filesystem.assume_init() }.f_type != DEVPTS_MAGIC
            || unsafe { libc::ioctl(fd, libc::TIOCGPTN, &mut master_index) } == 0
        {
            return Err(io::Error::other("login requires a PTY slave"));
        }
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        Ok((stat.st_dev, stat.st_ino, stat.st_rdev))
    }

    if identity(input)? != identity(output)? {
        return Err(io::Error::other(
            "login input and output use different terminals",
        ));
    }
    Ok(())
}

const MANUAL_LOGIN_POLICY: &str = "/etc/tempest/claude-manual-login.json";

fn open_login_child(parent: &File, name: &std::ffi::OsStr, flags: libc::c_int) -> io::Result<File> {
    let name = std::ffi::CString::new(name.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn pin_login_path(path: &Path, flags: libc::c_int) -> io::Result<File> {
    let mut components = path.components();
    if components.next() != Some(std::path::Component::RootDir) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut directory = File::open("/")?;
    let mut components = components.peekable();
    loop {
        let Some(std::path::Component::Normal(name)) = components.next() else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        if components.peek().is_none() {
            return open_login_child(&directory, name, flags);
        }
        let next = open_login_child(&directory, name, libc::O_DIRECTORY)?;
        let metadata = next.metadata()?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        directory = next;
    }
}

fn open_manual_login_policy(path: &Path) -> io::Result<File> {
    open_pinned_login_policy(pin_login_path(path, 0)?)
}

fn open_pinned_login_policy(pinned: File) -> io::Result<File> {
    let metadata = pinned.metadata()?;
    if !metadata.is_file()
        || (
            metadata.uid(),
            metadata.gid(),
            metadata.mode() & 0o7777,
            metadata.nlink(),
        ) != (0, 0, 0o600, 1)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "manual login policy metadata is invalid",
        ));
    }
    let input = File::open(format!("/proc/self/fd/{}", pinned.as_raw_fd()))?;
    if fd_identity(&input)? != fd_identity(&pinned)? {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(input)
}

fn open_login_ledger(parent: &File) -> io::Result<File> {
    let ledger = open_login_child(
        parent,
        std::ffi::OsStr::new("claude-login-diagnostic-ledger"),
        libc::O_DIRECTORY,
    )?;
    let metadata = ledger.metadata()?;
    if (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777) != (0, 0, 0o700) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid ledger ownership or mode",
        ));
    }
    Ok(ledger)
}

fn check_unused_login_permit(ledger: &File, permit_id: u128) -> io::Result<()> {
    let name = format!("{permit_id:032x}");
    match open_login_child(ledger, std::ffi::OsStr::new(&name), 0) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "permit already consumed or revoked",
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

const LOGIN_GENERATION_INPUTS: [(&str, u64); 5] = [
    ("claude-manual-login.json", 4096),
    ("claude-login-diagnostic-handoff", 4096),
    ("claude-login-diagnostic-signature", 64),
    ("claude-login-diagnostic-trust-key", 32),
    ("claude-login-diagnostic-target-registration", 4096),
];

fn open_private_login_directory(parent: &File, name: &str) -> io::Result<File> {
    let fd = open_login_child(parent, std::ffi::OsStr::new(name), libc::O_DIRECTORY)?;
    let metadata = fd.metadata()?;
    if (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777) != (0, 0, 0o700) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(fd)
}

fn verify_approved_login_manifest(
    approved: &[u8],
    revision: u64,
    manifest: &[u8],
) -> io::Result<()> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ApprovedGeneration {
        revision: u64,
        manifest_sha256: String,
    }

    let approved: ApprovedGeneration =
        serde_json::from_slice(approved).map_err(io::Error::other)?;
    if approved.revision != revision
        || approved.manifest_sha256 != format!("{:x}", Sha256::digest(manifest))
    {
        return Err(io::Error::other(
            "publication does not match approved generation",
        ));
    }
    Ok(())
}

const REVOCATION_DOMAIN: &[u8] = b"izanagi-tempest:manual-login-revocation:fixture-v1\0";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRevocationState {
    revision: u64,
    revocation_revision: u64,
    manifest_sha256: String,
    permit_id: String,
    target_id: String,
    issued_unix_seconds: u64,
    expires_unix_seconds: u64,
    revoked: bool,
}

fn verify_revocation_commit(
    minimum: u64,
    committed: &[u8],
    revision: u64,
    payload: &[u8],
    sync_authority: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CommittedState {
        revision: u64,
        state_sha256: String,
    }

    let committed: CommittedState = serde_json::from_slice(committed).map_err(io::Error::other)?;
    if revision < minimum
        || revision != committed.revision
        || committed.state_sha256 != format!("{:x}", Sha256::digest(payload))
    {
        return Err(io::Error::other(
            "revocation state does not match independent commit",
        ));
    }
    sync_authority()
        .map_err(|error| io::Error::other(format!("revocation authority sync failed: {error}")))
}

fn read_login_revision(directory: &File, name: &str) -> io::Result<u64> {
    let bytes = read_login_child(directory, name, 20)?;
    let value = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
    let number: u64 = value.parse().map_err(io::Error::other)?;
    if number == 0 || number.to_string() != value {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(number)
}

fn verify_login_revocation(
    authority: &File,
    revision: u64,
    manifest_sha256: &str,
    permit_id: u128,
    target_id: &str,
) -> io::Result<std::time::Instant> {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    match open_login_child(authority, std::ffi::OsStr::new("revocation-pending"), 0) {
        Ok(_) => return Err(io::Error::other("revocation update pending")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let minimum = read_login_revision(authority, "revocation-minimum")?;
    let committed = read_login_child(authority, "revocation-committed", 4096)?;
    let payload = read_login_child(authority, "revocation-state", 4096)?;
    let signature = read_login_child(authority, "revocation-signature", 64)?;
    let key: [u8; 32] = read_login_child(authority, "revocation-key", 32)?
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidData)?;
    let monotonic = Instant::now();
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    let (revocation_revision, expires) = verify_revocation_state(
        &key,
        &payload,
        &signature,
        (revision, manifest_sha256, permit_id, target_id),
        wall.as_secs(),
    )?;
    verify_revocation_commit(minimum, &committed, revocation_revision, &payload, || {
        let sync_fd = File::open(format!("/proc/self/fd/{}", authority.as_raw_fd()))?;
        if fd_identity(&sync_fd)? != fd_identity(authority)? {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        sync_fd.sync_all()
    })?;
    monotonic
        .checked_add(Duration::from_secs(expires) - wall)
        .ok_or(io::ErrorKind::InvalidData.into())
}

fn verify_revocation_state(
    key: &[u8; 32],
    payload: &[u8],
    signature: &[u8],
    expected: (u64, &str, u128, &str),
    now_unix_seconds: u64,
) -> io::Result<(u64, u64)> {
    verify_revocation_state_with_disposition(
        key,
        payload,
        signature,
        expected,
        now_unix_seconds,
        false,
    )
}

fn verify_revocation_state_with_disposition(
    key: &[u8; 32],
    payload: &[u8],
    signature: &[u8],
    expected: (u64, &str, u128, &str),
    now_unix_seconds: u64,
    revoked: bool,
) -> io::Result<(u64, u64)> {
    use ring::signature::{ED25519, UnparsedPublicKey};
    let (revision, manifest_sha256, permit_id, target_id) = expected;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(payload, signature)
        .map_err(|_| io::Error::other("invalid revocation signature"))?;
    let payload = payload
        .strip_prefix(REVOCATION_DOMAIN)
        .ok_or_else(|| io::Error::other("wrong revocation signature purpose"))?;
    let state: LoginRevocationState = serde_json::from_slice(payload).map_err(io::Error::other)?;
    if state.revocation_revision == 0
        || state.revision != revision
        || state.manifest_sha256 != manifest_sha256
        || state.permit_id != format!("{permit_id:032x}")
        || state.target_id != target_id
    {
        return Err(io::Error::other("revocation scope mismatch"));
    }
    if state.revoked != revoked {
        return Err(io::Error::other(if state.revoked {
            "permit revoked"
        } else {
            "permit is not revoked"
        }));
    }
    const MAX_FIXTURE_WINDOW: u64 = 30;
    if state.issued_unix_seconds > now_unix_seconds
        || !matches!(
            state
                .expires_unix_seconds
                .checked_sub(state.issued_unix_seconds),
            Some(1..=MAX_FIXTURE_WINDOW)
        )
        || state.expires_unix_seconds <= now_unix_seconds
    {
        return Err(io::Error::other("invalid or expired revocation window"));
    }
    Ok((state.revocation_revision, state.expires_unix_seconds))
}

// Carries the result of the read-only checks to the launch refusal boundary.
// There is no independently configured supervisor scope on this public route.
struct VerifiedSupervisorInputs {
    _publication_lock: File,
    _generation: File,
    _revision: u64,
    _manifest_sha256: String,
    _login: VerifiedLoginInputs,
}

fn verify_login_generation(
    parent: &File,
    publication: &File,
    report: bool,
) -> io::Result<VerifiedSupervisorInputs> {
    use sha2::{Digest, Sha256};

    let lock = open_pinned_login_policy(open_login_child(
        publication,
        std::ffi::OsStr::new("lock"),
        0,
    )?)?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    match open_login_child(publication, std::ffi::OsStr::new("pending"), 0) {
        Ok(_) => return Err(io::Error::other("publication unconfirmed")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let authority = open_private_login_directory(parent, "claude-login-authority")?;
    let floor = read_login_revision(&authority, "minimum")?;
    let current = read_login_revision(publication, "current")?;
    if current < floor {
        return Err(io::Error::other("publication below management floor"));
    }
    let generation = open_private_login_directory(publication, &current.to_string())?;
    let manifest_bytes = read_login_child(&generation, "manifest", 4096)?;
    let approved = read_login_child(&authority, "approved-generation", 4096)?;
    verify_approved_login_manifest(&approved, current, &manifest_bytes)?;
    let manifest: std::collections::BTreeMap<String, String> =
        serde_json::from_slice(&manifest_bytes).map_err(io::Error::other)?;
    if manifest.len() != LOGIN_GENERATION_INPUTS.len() {
        return Err(io::Error::other("incomplete publication manifest"));
    }
    let mut inputs = std::collections::BTreeMap::new();
    for (name, limit) in LOGIN_GENERATION_INPUTS {
        let bytes = read_login_child(&generation, name, limit)?;
        if manifest.get(name) != Some(&format!("{:x}", Sha256::digest(&bytes))) {
            return Err(io::Error::other("publication digest mismatch"));
        }
        inputs.insert(name, bytes);
    }
    // Check the independently provisioned key as well as the generation manifest.
    if inputs["claude-login-diagnostic-trust-key"] != read_login_child(&authority, "trust-key", 32)?
    {
        return Err(io::Error::other("publication trust key mismatch"));
    }
    let policy = &inputs["claude-manual-login.json"];
    let scope =
        validate_manual_login_policy(policy.as_slice())?.ok_or(io::ErrorKind::InvalidData)?;
    let manifest_sha256 = format!("{:x}", Sha256::digest(&manifest_bytes));
    let inputs = diagnose_manual_login_handoff_with(
        parent,
        &scope,
        |name, _| {
            inputs
                .get(name)
                .cloned()
                .ok_or(io::ErrorKind::InvalidData.into())
        },
        |id, target_id| {
            verify_login_revocation(&authority, current, &manifest_sha256, id, target_id).map(Some)
        },
        report,
    )?
    .ok_or_else(|| io::Error::other("publication handoff missing"))?;
    recheck_login_generation(
        publication,
        &authority,
        current,
        &generation,
        &manifest_bytes,
    )?;
    // The publication lock remains held through this final read-only check.
    let revocation = verify_login_revocation(
        &authority,
        current,
        &manifest_sha256,
        inputs.id,
        &inputs.target_id,
    )?;
    inputs.recheck(parent, &ARTIFACTS[0], revocation)?;
    if report {
        eprintln!("manual login final diagnostic verified");
    }
    Ok(VerifiedSupervisorInputs {
        _publication_lock: lock,
        _generation: generation,
        _revision: current,
        _manifest_sha256: manifest_sha256,
        _login: inputs,
    })
}

fn recheck_login_generation(
    publication: &File,
    authority: &File,
    revision: u64,
    generation: &File,
    manifest: &[u8],
) -> io::Result<()> {
    match open_login_child(publication, std::ffi::OsStr::new("pending"), 0) {
        Ok(_) => return Err(io::Error::other("publication unconfirmed")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    if read_login_revision(publication, "current")? != revision
        || read_login_revision(authority, "minimum")? > revision
        || fd_identity(&open_private_login_directory(
            publication,
            &revision.to_string(),
        )?)? != fd_identity(generation)?
        || read_login_child(generation, "manifest", 4096)? != manifest
    {
        return Err(io::Error::other(
            "publication changed during final diagnostic",
        ));
    }
    verify_approved_login_manifest(
        &read_login_child(authority, "approved-generation", 4096)?,
        revision,
        manifest,
    )
}

fn refuse_supervised_login(_verified: VerifiedSupervisorInputs) -> io::Result<()> {
    Err(manual_login_disabled())
}

fn manual_login_disabled() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "manual login policy acceptance is disabled",
    )
}

fn check_manual_login_policy(path: &Path) -> io::Result<()> {
    let parent = pin_login_path(
        path.parent().ok_or(io::ErrorKind::InvalidInput)?,
        libc::O_DIRECTORY,
    )?;
    let metadata = parent.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    match open_private_login_directory(&parent, "claude-login-publication") {
        Ok(publication) => {
            let verified =
                verify_login_generation(&parent, &publication, true).map_err(|error| {
                    eprintln!("manual login publication diagnostic refused: {error}");
                    io::Error::from(io::ErrorKind::InvalidData)
                })?;
            eprintln!("manual login publication diagnostic verified");
            eprintln!("manual login verified inputs handed off");
            return refuse_supervised_login(verified);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let name = path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
            let policy = open_pinned_login_policy(open_login_child(&parent, name, 0)?)?;
            let scope = validate_manual_login_policy(policy)?;
            if let Some(scope) = scope {
                diagnose_manual_login_handoff(&parent, &scope)?;
            }
        }
        Err(error) => return Err(error),
    }
    Err(manual_login_disabled())
}

fn read_login_input(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    read_bounded_login_input(open_manual_login_policy(path)?, limit)
}

fn read_login_child(parent: &File, name: &str, limit: u64) -> io::Result<Vec<u8>> {
    let pinned = open_login_child(parent, std::ffi::OsStr::new(name), 0)?;
    read_bounded_login_input(open_pinned_login_policy(pinned)?, limit)
}

fn read_bounded_login_input(input: File, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    input.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(bytes)
}

struct VerifiedLoginInputs {
    id: u128,
    target_id: String,
    expires: std::time::Instant,
    executable: File,
    ledger: File,
}

impl VerifiedLoginInputs {
    fn recheck(
        &self,
        parent: &File,
        artifact: &Artifact<'_>,
        revocation_deadline: std::time::Instant,
    ) -> io::Result<()> {
        let current = open_input(artifact).map_err(|fault| io::Error::other(fault.reason()))?;
        if fd_identity(&self.executable)? != fd_identity(&current)?
            || fd_identity(&self.ledger)? != fd_identity(&open_login_ledger(parent)?)?
        {
            return Err(io::Error::other(
                "pinned login input changed during final diagnostic",
            ));
        }
        verify_artifact(&self.executable, artifact)
            .map_err(|fault| io::Error::other(fault.reason()))?;
        check_unused_login_permit(&self.ledger, self.id)?;
        if std::time::Instant::now() >= self.expires.min(revocation_deadline) {
            return Err(io::Error::other("handoff expired during final diagnostic"));
        }
        Ok(())
    }
}

fn verify_login_handoff(
    key: &[u8; 32],
    payload: &[u8],
    signature: &[u8],
    scope: login_permit::Scope<'_>,
    policy_expires: u64,
) -> io::Result<(u128, std::time::Instant)> {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    let monotonic = Instant::now();
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    let (id, expires) = login_handoff::verify_handoff(
        key,
        payload,
        signature,
        scope,
        policy_expires,
        wall.as_secs(),
    )?;
    let remaining = Duration::from_secs(expires)
        .checked_sub(wall)
        .ok_or(io::ErrorKind::PermissionDenied)?;
    let deadline = monotonic
        .checked_add(remaining)
        .ok_or(io::ErrorKind::InvalidData)?;
    Ok((id, deadline))
}

fn diagnose_manual_login_handoff(parent: &File, scope: &LoginPolicyScope) -> io::Result<()> {
    diagnose_manual_login_handoff_with(
        parent,
        scope,
        |name, limit| read_login_child(parent, name, limit),
        |_, _| Ok(None),
        true,
    )
    .map(drop)
}

fn diagnose_manual_login_handoff_with(
    parent: &File,
    scope: &LoginPolicyScope,
    read: impl Fn(&str, u64) -> io::Result<Vec<u8>>,
    revocation_deadline: impl Fn(u128, &str) -> io::Result<Option<std::time::Instant>>,
    report: bool,
) -> io::Result<Option<VerifiedLoginInputs>> {
    let payload = match read("claude-login-diagnostic-handoff", 4096) {
        Ok(payload) => payload,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let result = (|| {
        let key = read("claude-login-diagnostic-trust-key", 32)?;
        let key = key
            .as_slice()
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?;
        let signature = read("claude-login-diagnostic-signature", 64)?;
        let record = read("claude-login-diagnostic-target-registration", 4096)?;
        let target_id = registered_diagnostic_target(&record, &scope.target_hostname)?;
        let expected = login_permit::Scope {
            executable_sha256: ARTIFACTS[0].sha256,
            arguments: &LOGIN_ARGS,
            authority: login_connect::AUTHORITY,
            target_id: &target_id,
            approved_ips_revision: scope.approved_ips_revision,
        };
        let (id, expires) = verify_login_handoff(
            key,
            &payload,
            &signature,
            expected,
            scope.expires_unix_seconds,
        )?;
        Ok::<_, io::Error>((id, expires, target_id))
    })();
    let (id, mut expires, target_id) = result.map_err(|error| {
        if report {
            eprintln!("manual login handoff diagnostic refused: {error}");
        }
        io::Error::from(io::ErrorKind::InvalidData)
    })?;
    if report {
        eprintln!("manual login handoff diagnostic verified");
    }
    if let Some(deadline) = revocation_deadline(id, &target_id)? {
        expires = expires.min(deadline);
        if report {
            eprintln!("manual login revocation diagnostic verified");
        }
    }
    let executable = verify_fixed_artifact(&ARTIFACTS[0]).map_err(|fault| {
        if report {
            stage_failure("manual_login_fixed_cli", &fault);
        }
        io::Error::new(io::ErrorKind::InvalidData, "manual login fixed CLI refused")
    })?;
    if report {
        eprintln!("manual login fixed CLI verified");
    }
    let ledger = open_login_ledger(parent);
    let ledger_result = (|| {
        let inputs = VerifiedLoginInputs {
            id,
            target_id,
            expires,
            executable,
            ledger: ledger?,
        };
        check_unused_login_permit(&inputs.ledger, inputs.id)?;
        if std::time::Instant::now() >= inputs.expires {
            return Err(io::Error::other("handoff expired during preflight"));
        }
        Ok::<_, io::Error>(inputs)
    })();
    let inputs = ledger_result.map_err(|error| {
        if report {
            eprintln!("manual login ledger diagnostic refused: {error}");
        }
        io::Error::from(io::ErrorKind::InvalidData)
    })?;
    if report {
        eprintln!("manual login ledger diagnostic verified");
    }
    Ok(Some(inputs))
}

fn registered_diagnostic_target(record: &[u8], hostname: &str) -> io::Result<String> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TargetRegistration {
        target_hostname: String,
        target_id: String,
    }

    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid diagnostic target registration",
        )
    };
    let record: TargetRegistration = serde_json::from_slice(record).map_err(|_| invalid())?;
    if record.target_hostname != hostname
        || record.target_id.is_empty()
        || record.target_id.len() > 128
        || !record
            .target_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid());
    }
    Ok(record.target_id)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualLoginPolicy {
    version: u32,
    authority: String,
}

impl ManualLoginPolicy {
    fn validate(&self) -> io::Result<()> {
        if self.version != 1 || self.authority != login_connect::AUTHORITY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid manual login policy",
            ));
        }
        Ok(())
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ManualLoginSettings {
    Scoped(ScopedManualLoginPolicy),
    Legacy(ManualLoginPolicy),
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopedManualLoginPolicy {
    version: u32,
    authority: String,
    approved_ips: ApprovedLoginIps,
    permit: LoginPolicyScope,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedLoginIps {
    revision: u64,
    addresses: Vec<std::net::IpAddr>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[derive(Debug)]
struct LoginPolicyScope {
    target_hostname: String,
    authority: String,
    approved_ips_revision: u64,
    expires_unix_seconds: u64,
}

fn validate_manual_login_policy(input: impl Read) -> io::Result<Option<LoginPolicyScope>> {
    let mut hostname = [0_u8; 256];
    if unsafe { libc::gethostname(hostname.as_mut_ptr().cast(), hostname.len()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let hostname = std::ffi::CStr::from_bytes_until_nul(&hostname)
        .ok()
        .and_then(|hostname| hostname.to_str().ok())
        .filter(|hostname| !hostname.is_empty())
        .ok_or(io::ErrorKind::InvalidData)?;
    validate_manual_login_policy_at(input, std::time::SystemTime::now(), hostname)
}

fn validate_manual_login_policy_at(
    input: impl Read,
    now: std::time::SystemTime,
    hostname: &str,
) -> io::Result<Option<LoginPolicyScope>> {
    use std::time::{Duration, UNIX_EPOCH};

    const MAX_POLICY_BYTES: u64 = 4096;
    // Diagnostic limit only. Production start timing is defined separately.
    const MAX_DIAGNOSTIC_REMAINING: Duration = Duration::from_secs(60);
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid manual login policy");
    let mut bytes = Vec::new();
    input.take(MAX_POLICY_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err(invalid());
    }
    let policy: ManualLoginSettings = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let policy = match policy {
        ManualLoginSettings::Legacy(policy) => return policy.validate().map(|()| None),
        ManualLoginSettings::Scoped(policy) => policy,
    };
    let ips = &policy.approved_ips;
    if policy.version != 2
        || policy.authority != login_connect::AUTHORITY
        || policy.permit.target_hostname != hostname
        || policy.permit.authority != policy.authority
        || ips.revision == 0
        || policy.permit.approved_ips_revision != ips.revision
        || ips.addresses.is_empty()
    {
        return Err(invalid());
    }
    let expires = UNIX_EPOCH
        .checked_add(Duration::from_secs(policy.permit.expires_unix_seconds))
        .ok_or_else(invalid)?;
    let remaining = expires.duration_since(now).map_err(|_| invalid())?;
    if remaining.is_zero() || remaining > MAX_DIAGNOSTIC_REMAINING {
        return Err(invalid());
    }
    Ok(Some(policy.permit))
}

fn verify_combined_login_inputs() -> io::Result<(VerifiedSupervisorInputs, File)> {
    let parent = pin_login_path(
        Path::new(MANUAL_LOGIN_POLICY)
            .parent()
            .ok_or(io::ErrorKind::InvalidInput)?,
        libc::O_DIRECTORY,
    )?;
    let metadata = parent.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let publication = open_private_login_directory(&parent, "claude-login-publication")?;
    let verified = verify_login_generation(&parent, &publication, false)?;
    let host_lock = host_login_diagnostic::verify_for_supervision(
        &verified._login.target_id,
        verified._login.id,
        verified._revision,
        verified._login.expires,
    )?;
    let authority = open_private_login_directory(&parent, "claude-login-authority")?;
    let revocation_deadline = verify_login_revocation(
        &authority,
        verified._revision,
        &verified._manifest_sha256,
        verified._login.id,
        &verified._login.target_id,
    )?;
    if std::time::Instant::now() >= verified._login.expires.min(revocation_deadline) {
        return Err(io::Error::other("manual login inputs expired"));
    }
    Ok((verified, host_lock))
}

pub(super) fn run_combined_login_diagnostic() -> std::process::ExitCode {
    use std::process::ExitCode;
    if std::env::args_os().len() != 1
        || unsafe { libc::geteuid() } != 0
        || verify_shared_terminal(libc::STDIN_FILENO, libc::STDOUT_FILENO).is_err()
        || verify_shared_terminal(libc::STDOUT_FILENO, libc::STDERR_FILENO).is_err()
    {
        eprintln!("combined login diagnostic refused: dedicated administrator PTY required");
        return ExitCode::FAILURE;
    }
    let (matched, result) = match verify_combined_login_inputs() {
        Ok((verified, _host_lock)) => (true, refuse_supervised_login(verified)),
        Err(error) => (false, Err(error)),
    };
    if matched {
        host_login_diagnostic::report_without_waiting(
            "combined login diagnostic: host and PTY inputs match",
        );
        host_login_diagnostic::report_without_waiting("manual login verified inputs handed off");
    }
    if let Err(error) = result {
        host_login_diagnostic::report_without_waiting(&format!(
            "combined login diagnostic refused: {error}"
        ));
    }
    ExitCode::FAILURE
}

pub(super) fn run_manual_login() -> std::process::ExitCode {
    use std::process::ExitCode;
    if std::env::args_os().len() != 1 {
        eprintln!("manual login refused: arguments are unsupported");
    } else if unsafe { libc::geteuid() } != 0
        || verify_shared_terminal(libc::STDIN_FILENO, libc::STDOUT_FILENO).is_err()
        || verify_shared_terminal(libc::STDOUT_FILENO, libc::STDERR_FILENO).is_err()
    {
        eprintln!("manual login refused: dedicated administrator PTY required");
    } else {
        let reason = match check_manual_login_policy(Path::new(MANUAL_LOGIN_POLICY)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => "administrator policy missing",
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                "administrator policy acceptance disabled"
            }
            _ => "administrator policy unavailable or invalid",
        };
        eprintln!("manual login refused: {reason}");
    }
    ExitCode::FAILURE
}

pub(super) fn run_pty() -> std::process::ExitCode {
    use std::process::ExitCode;
    if std::env::args_os().len() != 1
        || unsafe { libc::geteuid() } != 0
        || unsafe { libc::isatty(libc::STDIN_FILENO) } != 1
        || unsafe { libc::isatty(libc::STDOUT_FILENO) } != 1
    {
        return ExitCode::FAILURE;
    }
    let parent_path = Path::new(WORK_PARENT);
    let result = (|| {
        let parent = lock_parent(parent_path)?;
        let work = WorkArea::create(&parent, parent_path)?;
        supervised_observed(
            &parent,
            &work,
            |scratch, root, control, reaped| {
                run_fixture(scratch, root, control, reaped, Diagnostic::Pty)
            },
            &mut None,
        )
    })();
    match result {
        Ok(_) => {
            eprintln!("offline PTY: supervisor stopped and reaped namespace; cleanup complete");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("offline PTY fixture failed: {error}");
            ExitCode::FAILURE
        }
    }
}

pub(super) fn run_writable_pty() -> std::process::ExitCode {
    run_writable_pty_for(None, false)
}

pub(super) fn run_local_auth_pty() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1);
    let argument = args.next();
    let stage_login_artifacts =
        argument.as_deref() == Some(std::ffi::OsStr::new("signed-tls-staged"));
    let case = if stage_login_artifacts {
        Some(local_auth::Case::SignedTls)
    } else {
        argument.as_deref().and_then(local_auth::Case::parse)
    };
    let Some(case) = case else {
        return std::process::ExitCode::FAILURE;
    };
    if args.next().is_some() {
        return std::process::ExitCode::FAILURE;
    }
    run_writable_pty_for(Some(case), stage_login_artifacts)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureApproval {
    policy: ManualLoginPolicy,
    executable_sha256: String,
    arguments: [String; 2],
    target_id: String,
    approved_ips_revision: u64,
    expires_unix_seconds: u64,
}

fn read_fixture_permit(parent: &File) -> io::Result<(FixtureApproval, std::time::Instant)> {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    let bytes = read_login_child(parent, ".synthetic-login-policy.json", 4096)?;
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid synthetic login settings",
        )
    };
    let fixture: FixtureApproval = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    fixture.policy.validate()?;
    let now = Instant::now();
    let expires = UNIX_EPOCH
        .checked_add(Duration::from_secs(fixture.expires_unix_seconds))
        .ok_or_else(invalid)?;
    let remaining = expires
        .duration_since(SystemTime::now())
        .ok()
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::other("synthetic permit expired"))?;
    if remaining > Duration::from_secs(60) {
        return Err(invalid());
    }
    Ok((fixture, now.checked_add(remaining).ok_or_else(invalid)?))
}

fn run_writable_pty_for(
    local_auth_case: Option<local_auth::Case>,
    stage_login_artifacts: bool,
) -> std::process::ExitCode {
    use std::process::ExitCode;
    let mut args = std::env::args_os().skip(1);
    let retain = match if local_auth_case.is_none() {
        args.next()
    } else {
        None
    }
    .as_deref()
    {
        None => false,
        Some(flag) if flag == "--retain-fixture" && args.next().is_none() => true,
        _ => return ExitCode::FAILURE,
    };
    if unsafe { libc::geteuid() } != 0
        || verify_shared_terminal(libc::STDIN_FILENO, libc::STDOUT_FILENO).is_err()
    {
        return ExitCode::FAILURE;
    }
    let result = (|| {
        // Pin the upstream namespace before the supervisor enters the isolated client network.
        let upstream_network = local_auth_case
            .map(|_| File::open("/proc/thread-self/ns/net"))
            .transpose()?;
        let mut permit = local_auth_case.map(|case| {
            let now = std::time::Instant::now();
            FixturePermit {
                verified_executable: None,
                grant: None,
                closure: None,
                administrator_stop: None,
                expires: if matches!(case, local_auth::Case::ExpiredPermit) {
                    now
                } else {
                    now + std::time::Duration::from_secs(60)
                },
                executable_digest: if matches!(case, local_auth::Case::WrongPermitScope) {
                    ARTIFACTS[0].sha256
                } else {
                    BUSYBOX.sha256
                },
                arguments: if matches!(case, local_auth::Case::WrongPermitArguments) {
                    ["auth", "status"]
                } else {
                    LOGIN_ARGS
                },
                authority: if matches!(case, local_auth::Case::WrongPermitAuthority) {
                    "platform.claude.com:8443"
                } else {
                    login_connect::AUTHORITY
                },
            }
        });
        let work_path = Path::new(WORK_PARENT);
        let parent = lock_parent(work_path).map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                io::Error::other("dedicated PTY work area already in use")
            } else {
                error
            }
        })?;
        let config_path = Path::new("/var/lib/tempest-claude-config-fixture");
        let config_parent = lock_parent(config_path)?;
        let mut signed_permit_id = None;
        let mut signed_revocation_key = None;
        if matches!(
            local_auth_case,
            Some(
                local_auth::Case::SingleUsePermit
                    | local_auth::Case::SignedPermit
                    | local_auth::Case::SignedTls
                    | local_auth::Case::SignedTlsExpiry
                    | local_auth::Case::SignedTlsRevocation
                    | local_auth::Case::SignedAdministratorStop
                    | local_auth::Case::PermitExpiresBeforeGrant
                    | local_auth::Case::WrongGrantId
                    | local_auth::Case::WrongGrantLedger
                    | local_auth::Case::WrongGrantStage
                    | local_auth::Case::MissingClosure
                    | local_auth::Case::WrongClosureGeneration
                    | local_auth::Case::MissingConsumptionSync
                    | local_auth::Case::FailedConsumptionSync
            )
        ) {
            use std::time::Instant;

            let permit = permit
                .as_mut()
                .ok_or_else(|| io::Error::other("synthetic permit missing"))?;
            let (approval, policy_expiry) = read_fixture_permit(&config_parent)?;
            let expected = login_permit::Scope {
                executable_sha256: BUSYBOX.sha256,
                arguments: &LOGIN_ARGS,
                authority: login_connect::AUTHORITY,
                target_id: "synthetic-target",
                approved_ips_revision: 1,
            };
            let arguments = approval.arguments.each_ref().map(String::as_str);
            let configured = login_permit::Scope {
                executable_sha256: &approval.executable_sha256,
                arguments: &arguments,
                authority: &approval.policy.authority,
                target_id: &approval.target_id,
                approved_ips_revision: approval.approved_ips_revision,
            };
            let (id, expiry, ledger) =
                if matches!(local_auth_case, Some(local_auth::Case::SingleUsePermit)) {
                    // Preserve refusal of a permit consumed by an earlier fixture build.
                    match config_path
                        .join(".used-synthetic-login-permit")
                        .symlink_metadata()
                    {
                        Ok(_) => {
                            return Err(io::Error::other(
                                "manual login permit already consumed or revoked",
                            ));
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                    (1, policy_expiry, config_parent.try_clone()?)
                } else {
                    let read = |name, limit| read_login_child(&config_parent, name, limit);
                    let payload = read(".synthetic-handoff", 4096)?;
                    let signature = read(".synthetic-handoff-signature", 64)?;
                    let key: [u8; 32] = read(".synthetic-handoff-key", 32)?
                        .try_into()
                        .map_err(|_| io::ErrorKind::InvalidData)?;
                    if matches!(local_auth_case, Some(local_auth::Case::SignedTlsRevocation)) {
                        signed_revocation_key = Some(key);
                    }
                    let (id, expiry) = verify_login_handoff(
                        &key,
                        &payload,
                        &signature,
                        expected,
                        approval.expires_unix_seconds,
                    )?;
                    let inputs = VerifiedLoginInputs {
                        id,
                        target_id: configured.target_id.to_owned(),
                        expires: policy_expiry.min(expiry),
                        executable: verify_fixed_artifact(&BUSYBOX)
                            .map_err(|fault| io::Error::other(fault.reason()))?,
                        ledger: config_parent.try_clone()?,
                    };
                    check_unused_login_permit(&inputs.ledger, inputs.id)?;
                    permit.verified_executable = Some(inputs.executable);
                    (inputs.id, inputs.expires, inputs.ledger)
                };
            // O_PATH still allows openat on the pinned directory but cannot
            // fsync it. Exercise a real sync failure after record creation.
            let unsyncable = if matches!(
                local_auth_case,
                Some(local_auth::Case::FailedConsumptionSync)
            ) {
                Some(open_login_child(
                    &ledger,
                    std::ffi::OsStr::new("."),
                    libc::O_DIRECTORY,
                )?)
            } else {
                None
            };
            let record = login_permit::consume(
                unsyncable.as_ref().unwrap_or(&ledger),
                &login_permit::Permit {
                    id,
                    expires_at: expiry,
                    scope: configured,
                },
                expected,
                Instant::now(),
            )
            .map_err(|error| {
                if unsyncable.is_some() && error.raw_os_error() == Some(libc::EBADF) {
                    io::Error::other(format!("synthetic consumption sync failed: {error}"))
                } else {
                    error
                }
            })?;
            if permit.verified_executable.is_some() {
                permit.grant = Some(FixtureGrant { id, ledger, record });
            }
            permit.expires = expiry;
            if matches!(
                local_auth_case,
                Some(local_auth::Case::SignedAdministratorStop)
            ) {
                signed_permit_id = Some(id);
            }
        }
        let work = WorkArea::create(&parent, work_path)?;
        let config = (|| {
            if let Some((id, permit)) = signed_permit_id.zip(permit.as_mut()) {
                let (device, inode) = fd_identity(&work.pinned)?;
                let permit_id = format!("{id:032x}");
                eprintln!("synthetic stop target: {permit_id} {device} {inode}");
                permit.administrator_stop = Some(FixtureStop {
                    request: config_path.join(".synthetic-stop-request.json"),
                    signed: None,
                    target: FixtureStopTarget {
                        permit_id,
                        device,
                        inode,
                    },
                });
            }
            writable_config::Generation::create(&config_parent, config_path, &work)
        })()
        .map_err(|error| match work.remove(&parent) {
            Ok(()) => error,
            Err(cleanup) => io::Error::other(format!("{error}; work cleanup failed: {cleanup}")),
        })?;
        if let Some((case, permit)) = local_auth_case.zip(permit.as_mut()) {
            if matches!(case, local_auth::Case::SignedTlsRevocation) {
                use sha2::{Digest, Sha256};
                let id = permit.grant.as_ref().ok_or(io::ErrorKind::InvalidData)?.id;
                let (device, inode) = fd_identity(&work.pinned)?;
                let (config_dev, config_ino) = config.identity()?;
                let generation = format!("{device}:{inode}:{config_dev}:{config_ino}");
                permit.administrator_stop = Some(FixtureStop {
                    request: config_path.join(".synthetic-live-revocation.json"),
                    target: FixtureStopTarget {
                        permit_id: format!("{id:032x}"),
                        device,
                        inode,
                    },
                    signed: Some(FixtureRevocation {
                        key: signed_revocation_key.ok_or(io::ErrorKind::InvalidData)?,
                        id,
                        target_id: "synthetic-target".into(),
                        manifest: format!("{:x}", Sha256::digest(generation.as_bytes())),
                        revision: 1,
                    }),
                });
            }
            permit.closure = Some(FixtureClosure::new(
                case,
                &work,
                &config,
                permit.grant.as_ref().map(|grant| grant.id),
            )?);
        }
        let local_auth = local_auth_case
            .zip(upstream_network.as_ref())
            .zip(permit.as_ref())
            .map(|((case, namespace), permit)| (case, namespace, permit));
        let diagnostic =
            if stage_login_artifacts || matches!(local_auth_case, Some(local_auth::Case::Match)) {
                Diagnostic::PtyWithLoginArtifacts
            } else {
                Diagnostic::Pty
            };
        let verified_artifacts = if diagnostic == Diagnostic::PtyWithLoginArtifacts {
            match pin_artifacts(artifacts_for(diagnostic)) {
                Ok(artifacts) => Some(artifacts),
                Err(fault) => {
                    work.remove(&parent)?;
                    config.finish(&config_parent, writable_config::Disposition::Remove, false)?;
                    return Err(io::Error::other(fault.reason()));
                }
            }
        } else {
            None
        };
        let mut observation = None;
        let run = supervised_with_network(
            &parent,
            &work,
            |scratch, root, control, reaped| {
                run_fixture_with_config(
                    scratch,
                    root,
                    control,
                    reaped,
                    diagnostic,
                    FixtureStaging {
                        config: Some(&config),
                        verified_artifacts: verified_artifacts.as_deref(),
                    },
                    local_auth,
                )
            },
            &mut observation,
            permit.as_ref(),
        );
        let action = writable_config::disposition(
            observation.map(|item| item.recovery),
            run.is_ok(),
            retain,
        );
        if let Err(error) = config.finish(&config_parent, action, run.is_ok()) {
            return Err(match run {
                Ok(_) => error,
                Err(run_error) => io::Error::other(format!("{run_error}; {error}")),
            });
        }
        run?;
        Ok::<_, io::Error>(action)
    })();
    match result {
        Ok(writable_config::Disposition::Retain) => {
            eprintln!("offline writable PTY: recovered; synthetic configuration retained");
            ExitCode::SUCCESS
        }
        Ok(_) => {
            eprintln!("offline writable PTY: recovered; synthetic configuration removed");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("offline writable PTY fixture failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_revocation_state_rejects_signed_replay_and_failed_sync() {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let key = Ed25519KeyPair::from_seed_unchecked(&[31; 32]).unwrap();
        let public = key.public_key().as_ref().try_into().unwrap();
        let payload = |revision| {
            let mut bytes = REVOCATION_DOMAIN.to_vec();
            bytes.extend(
                serde_json::to_vec(&serde_json::json!({
                    "revision": 2,
                    "revocation_revision": revision,
                    "manifest_sha256": "manifest",
                    "permit_id": format!("{:032x}", 42),
                    "target_id": "fixture",
                    "issued_unix_seconds": 100,
                    "expires_unix_seconds": 120,
                    "revoked": false,
                }))
                .unwrap(),
            );
            bytes
        };
        let current = payload(7);
        let committed = serde_json::to_vec(&serde_json::json!({
            "revision": 7,
            "state_sha256": format!("{:x}", Sha256::digest(&current)),
        }))
        .unwrap();
        let verify = |payload: &[u8], sync: fn() -> io::Result<()>| {
            let signature = key.sign(payload);
            let (revision, _) = verify_revocation_state(
                public,
                payload,
                signature.as_ref(),
                (2, "manifest", 42, "fixture"),
                110,
            )?;
            verify_revocation_commit(7, &committed, revision, payload, sync)
        };
        assert_eq!(
            verify(&payload(6), || panic!("replay must fail before sync"))
                .unwrap_err()
                .to_string(),
            "revocation state does not match independent commit"
        );
        assert!(
            verify(&current, || Err(io::Error::from_raw_os_error(libc::EIO)))
                .unwrap_err()
                .to_string()
                .contains("sync failed")
        );
        verify(&current, || Ok(())).unwrap();
    }

    #[test]
    fn signed_revocation_state_checks_scope_and_fixed_time_boundaries() {
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let key = Ed25519KeyPair::from_seed_unchecked(&[23; 32]).unwrap();
        let public = key.public_key().as_ref().try_into().unwrap();
        let expected = (2, "manifest-2", 42, "target-2");
        let baseline = serde_json::json!({
            "revision": 2,
            "revocation_revision": 7,
            "manifest_sha256": "manifest-2",
            "permit_id": format!("{:032x}", 42),
            "target_id": "target-2",
            "issued_unix_seconds": 100,
            "expires_unix_seconds": 130,
            "revoked": false,
        });
        let verify = |state: &serde_json::Value, now| {
            let mut payload = REVOCATION_DOMAIN.to_vec();
            payload.extend(serde_json::to_vec(state).unwrap());
            let signature = key.sign(&payload);
            verify_revocation_state(public, &payload, signature.as_ref(), expected, now)
        };
        assert_eq!(verify(&baseline, 100).unwrap(), (7, 130));
        assert_eq!(verify(&baseline, 129).unwrap(), (7, 130));
        assert!(verify(&baseline, 130).is_err());
        assert!(verify(&baseline, 99).is_err());

        for (field, value) in [
            ("expires_unix_seconds", serde_json::json!(100)),
            ("expires_unix_seconds", serde_json::json!(131)),
            ("manifest_sha256", serde_json::json!("manifest-1")),
            ("permit_id", serde_json::json!(format!("{:032x}", 43))),
            ("target_id", serde_json::json!("target-1")),
        ] {
            let mut changed = baseline.clone();
            changed[field] = value;
            assert!(verify(&changed, 100).is_err(), "{field}");
        }
    }

    #[test]
    fn published_manifest_must_match_the_independently_approved_revision_and_digest() {
        let old_manifest = br#"{"settings":"old","signature":"valid-for-old-handoff"}"#;
        let new_manifest = br#"{"settings":"new","signature":"valid-for-new-handoff"}"#;
        let approval = |revision, manifest: &[u8]| {
            serde_json::to_vec(&serde_json::json!({
                "revision": revision,
                "manifest_sha256": format!("{:x}", Sha256::digest(manifest)),
            }))
            .unwrap()
        };
        let old_approval = approval(1, old_manifest);
        let new_approval = approval(2, new_manifest);
        verify_approved_login_manifest(&new_approval, 2, new_manifest).unwrap();
        assert!(verify_approved_login_manifest(&old_approval, 2, old_manifest).is_err());
        assert!(verify_approved_login_manifest(&new_approval, 2, old_manifest).is_err());
    }

    #[test]
    #[ignore = "requires a root-owned fixture under /var/lib"]
    fn final_login_diagnostic_rejects_replaced_inputs_and_expiry() {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};

        let path = Path::new("/var/lib").join(format!(
            "tempest-final-login-{}",
            crate::private_io::random_hex().unwrap()
        ));
        let parent = lock_parent(&path).unwrap();
        let ledger_path = path.join("claude-login-diagnostic-ledger");
        let publication_path = path.join("publication");
        let authority_path = path.join("authority");
        let generation_path = publication_path.join("1");
        for dir in [
            &ledger_path,
            &publication_path,
            &authority_path,
            &generation_path,
        ] {
            fs::create_dir(dir).unwrap();
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let write = |file: &Path, bytes: &[u8]| {
            let mut output = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(file)
                .unwrap();
            output.write_all(bytes).unwrap();
        };
        let artifact_path = path.join("artifact");
        write(&artifact_path, b"dummy");
        let artifact = Artifact {
            source: artifact_path.to_str().unwrap(),
            bytes: 5,
            sha256: "b5a2c96250612366ea272ffac6d9744aaf4b45aacd96aa7cfcb931ee3b558259",
            targets: &[],
        };
        let inputs = VerifiedLoginInputs {
            id: 7,
            target_id: "synthetic-final-diagnostic".into(),
            expires: Instant::now() + Duration::from_secs(10),
            executable: verify_fixed_artifact(&artifact).unwrap(),
            ledger: open_login_ledger(&parent).unwrap(),
        };
        let fresh = inputs.expires;
        inputs.recheck(&parent, &artifact, fresh).unwrap();
        assert!(inputs.recheck(&parent, &artifact, Instant::now()).is_err());
        fs::write(&artifact_path, b"wrong").unwrap();
        assert!(inputs.recheck(&parent, &artifact, fresh).is_err());
        fs::write(&artifact_path, b"dummy").unwrap();
        let saved_artifact = path.join("original-artifact");
        fs::rename(&artifact_path, &saved_artifact).unwrap();
        write(&artifact_path, b"dummy");
        assert!(inputs.recheck(&parent, &artifact, fresh).is_err());
        fs::rename(&saved_artifact, &artifact_path).unwrap();
        let saved_ledger = path.join("original-ledger");
        fs::rename(&ledger_path, &saved_ledger).unwrap();
        fs::create_dir(&ledger_path).unwrap();
        fs::set_permissions(&ledger_path, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(inputs.recheck(&parent, &artifact, fresh).is_err());
        fs::rename(&saved_ledger, &ledger_path).unwrap();
        let marker = ledger_path.join(format!("{:032x}", inputs.id));
        write(&marker, b"");
        assert!(inputs.recheck(&parent, &artifact, fresh).is_err());
        assert_eq!(fs::read_dir(&ledger_path).unwrap().count(), 1);

        let publication = File::open(&publication_path).unwrap();
        let authority = File::open(&authority_path).unwrap();
        let generation = File::open(&generation_path).unwrap();
        let manifest = b"dummy manifest";
        write(&publication_path.join("current"), b"1");
        write(&authority_path.join("minimum"), b"1");
        write(&generation_path.join("manifest"), manifest);
        write(
            &authority_path.join("approved-generation"),
            format!(
                r#"{{"revision":1,"manifest_sha256":"{:x}"}}"#,
                Sha256::digest(manifest)
            )
            .as_bytes(),
        );
        recheck_login_generation(&publication, &authority, 1, &generation, manifest).unwrap();
        fs::rename(&generation_path, publication_path.join("former")).unwrap();
        fs::create_dir(&generation_path).unwrap();
        fs::set_permissions(&generation_path, fs::Permissions::from_mode(0o700)).unwrap();
        write(&generation_path.join("manifest"), manifest);
        assert!(
            recheck_login_generation(&publication, &authority, 1, &generation, manifest).is_err()
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    #[ignore = "requires root-owned fixtures under /var/lib"]
    fn management_floor_is_durable_before_switch_and_reread_under_lock() {
        use std::time::{Duration, Instant};

        let path = Path::new("/var/lib").join(format!(
            "tempest-publication-floor-{}",
            crate::private_io::random_hex().unwrap()
        ));
        let _fixture = lock_parent(&path).unwrap();
        let authority = path.join("authority");
        let publication = path.join("publication");
        let ledger_path = path.join("ledger");
        for directory in [&authority, &publication, &ledger_path] {
            fs::create_dir(directory).unwrap();
        }
        let authority_fd = pin_login_path(&authority, libc::O_DIRECTORY).unwrap();
        let publication_fd = pin_login_path(&publication, libc::O_DIRECTORY).unwrap();
        let ledger = File::open(&ledger_path).unwrap();
        let lock = path.join("publication-lock");
        File::create(&lock).unwrap();
        let acquire = || {
            let fd = File::open(&lock).unwrap();
            assert_eq!(unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX) }, 0);
            fd
        };
        let replace_unsynced = |directory: &Path, name: &str, content: &[u8]| -> io::Result<()> {
            let staged = directory.join("next");
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&staged)?;
            file.write_all(content)?;
            file.sync_all()?;
            fs::rename(staged, directory.join(name))
        };
        let replace = |directory: &Path, name: &str, content: &[u8]| -> io::Result<()> {
            replace_unsynced(directory, name, content)?;
            File::open(directory)?.sync_all()
        };
        let read_revision = |parent: &File, name| -> io::Result<u64> {
            let bytes = read_login_child(parent, name, 20)?;
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|&revision| revision > 0)
                .ok_or(io::ErrorKind::InvalidData.into())
        };
        let consume = |revision, id| {
            let _lock = acquire();
            let floor = read_revision(&authority_fd, "minimum")?;
            let current = read_revision(&publication_fd, "current")?;
            if revision != current || current < floor {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            match open_login_child(&publication_fd, std::ffi::OsStr::new("pending"), 0) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "publication unconfirmed",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let now = Instant::now();
            let scope = login_permit::Scope {
                executable_sha256: BUSYBOX.sha256,
                arguments: &LOGIN_ARGS,
                authority: login_connect::AUTHORITY,
                target_id: "publication-fixture",
                approved_ips_revision: revision,
            };
            login_permit::consume(
                &ledger,
                &login_permit::Permit {
                    id,
                    expires_at: now + Duration::from_secs(10),
                    scope,
                },
                scope,
                now,
            )
        };

        replace(&authority, "minimum", b"1").unwrap();
        replace(&publication, "current", b"1").unwrap();
        consume(1, 1).unwrap();
        let publish = |fail_after_floor| -> io::Result<()> {
            let _lock = acquire();
            let current = read_revision(&publication_fd, "current")?;
            let floor = read_revision(&authority_fd, "minimum")?;
            if current > 2 || floor > 2 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let contender = File::open(&lock)?;
            assert_eq!(
                unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                -1
            );
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EWOULDBLOCK)
            );
            replace(&authority, "minimum", b"2")?;
            if fail_after_floor {
                return Err(io::Error::other("injected interruption after floor sync"));
            }
            replace(&publication, "pending", b"2")?;
            replace_unsynced(&publication, "current", b"2")?;
            // An O_PATH descriptor pins the correct directory but cannot sync it.
            // Inject a real fsync failure after current is already visible.
            publication_fd.sync_all()
        };
        assert!(publish(true).is_err());
        assert_eq!(read_revision(&authority_fd, "minimum").unwrap(), 2);
        assert_eq!(read_revision(&publication_fd, "current").unwrap(), 1);
        assert_eq!(
            consume(1, 2).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            consume(2, 2).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::read_dir(&ledger_path).unwrap().count(), 1);
        assert_eq!(
            publish(false).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
        assert_eq!(read_revision(&authority_fd, "minimum").unwrap(), 2);
        assert_eq!(read_revision(&publication_fd, "current").unwrap(), 2);
        assert_eq!(read_revision(&publication_fd, "pending").unwrap(), 2);
        assert_eq!(
            consume(2, 2).unwrap_err().to_string(),
            "publication unconfirmed"
        );
        assert_eq!(fs::read_dir(&ledger_path).unwrap().count(), 1);
        {
            let _lock = acquire();
            let floor = read_revision(&authority_fd, "minimum").unwrap();
            let current = read_revision(&publication_fd, "current").unwrap();
            assert_eq!(floor, current);
            assert_eq!(read_revision(&publication_fd, "pending").unwrap(), current);
            let sync_fd =
                File::open(format!("/proc/self/fd/{}", publication_fd.as_raw_fd())).unwrap();
            assert_eq!(
                fd_identity(&sync_fd).unwrap(),
                fd_identity(&publication_fd).unwrap()
            );
            sync_fd.sync_all().unwrap();
            let pending = c"pending";
            assert_eq!(
                unsafe { libc::unlinkat(publication_fd.as_raw_fd(), pending.as_ptr(), 0) },
                0
            );
            sync_fd.sync_all().unwrap();
        }
        assert_eq!(
            consume(1, 2).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        consume(2, 2).unwrap();

        fs::remove_file(authority.join("minimum")).unwrap();
        std::os::unix::fs::symlink(publication.join("current"), authority.join("minimum")).unwrap();
        assert_eq!(
            consume(2, 3).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::read_dir(&ledger_path).unwrap().count(), 2);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    #[ignore = "requires a root-owned fixture under /var/lib"]
    fn staged_verified_file_keeps_identity_and_rechecks_content() {
        let directory = Path::new("/var/lib").join(format!(
            "tempest-pinned-executable-{}",
            crate::private_io::random_hex().unwrap()
        ));
        let _parent = lock_parent(&directory).unwrap();
        let executable = directory.join("executable");
        let original = directory.join("original");
        fs::write(&executable, b"dummy").unwrap();
        let artifact = Artifact {
            source: executable.to_str().unwrap(),
            bytes: 5,
            sha256: "b5a2c96250612366ea272ffac6d9744aaf4b45aacd96aa7cfcb931ee3b558259",
            targets: &[],
        };
        let pinned = verify_fixed_artifact(&artifact).unwrap();
        fs::rename(&executable, &original).unwrap();
        fs::write(&executable, b"other").unwrap();
        let staged = directory.join("staged");
        stage_pinned_artifact(&pinned, &artifact, &staged).unwrap();
        assert_eq!(fs::read(staged).unwrap(), b"dummy");
        fs::write(original, b"other").unwrap();
        assert!(matches!(
            stage_pinned_artifact(&pinned, &artifact, &directory.join("modified")),
            Err(Fault::Identity)
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    struct DiagnosticArtifactSet {
        generation: u64,
        files: Vec<File>,
    }

    impl DiagnosticArtifactSet {
        fn new(verified: &VerifiedSupervisorInputs) -> io::Result<Self> {
            let mut files = vec![verified._login.executable.try_clone()?];
            files.extend(
                pin_artifacts(&ARTIFACTS[1..]).map_err(|fault| io::Error::other(fault.reason()))?,
            );
            Ok(Self {
                generation: verified._revision,
                files,
            })
        }

        fn stage(&self, generation: u64, scratch: &Path, root: &Path) -> Result<(), Fault> {
            if self.generation != generation {
                return Err(Fault::Identity);
            }
            stage_fixed_artifacts(scratch, root, ARTIFACTS, Some(&self.files))
        }
    }

    #[test]
    #[ignore = "run through the isolated combined diagnostic staging harness"]
    fn stage_combined_diagnostic_descriptors() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        verify_shared_terminal(libc::STDIN_FILENO, libc::STDOUT_FILENO).unwrap();
        verify_shared_terminal(libc::STDOUT_FILENO, libc::STDERR_FILENO).unwrap();
        let (verified, _host_lock) = verify_combined_login_inputs().unwrap();
        let mut files = DiagnosticArtifactSet::new(&verified).unwrap();
        if std::env::var("TEMPEST_STAGE_CASE").as_deref() == Ok("generation") {
            files.generation += 1;
        }
        let mode = std::env::var("TEMPEST_STAGE_CASE").unwrap();
        let work_path = Path::new(WORK_PARENT);
        let config_path = Path::new("/var/lib/tempest-claude-config-fixture");
        let parent = lock_parent(work_path).unwrap();
        let config_parent = lock_parent(config_path).unwrap();
        let work = WorkArea::create(&parent, work_path).unwrap();
        let config =
            writable_config::Generation::create(&config_parent, config_path, &work).unwrap();
        let mut detached = false;
        let result = trial_with_detach(&work.path, &mut detached, |scratch, root| {
            for path in [
                "bin",
                "lib64",
                "lib",
                "lib/x86_64-linux-gnu",
                "home",
                "home/fixture",
                "home/fixture/config",
            ] {
                fs::create_dir(root.join(path))?;
            }
            let source = std::ffi::CString::new(ARTIFACTS[0].source).unwrap();
            if mode == "replace" {
                super::super::os::syscall(unsafe {
                    libc::umount2(source.as_ptr(), libc::MNT_DETACH)
                })?;
                assert_ne!(fs::metadata(ARTIFACTS[0].source)?.len(), ARTIFACTS[0].bytes);
            }
            if mode == "modify" {
                use std::os::unix::fs::FileExt;
                let changed = OpenOptions::new()
                    .write(true)
                    .open(work_path.join("staging-source"))?;
                assert_eq!(fd_identity(&changed)?, fd_identity(&files.files[0])?);
                changed.write_at(b"\0", 0)?;
            }
            if mode == "missing" {
                files.files.pop();
            }
            files.stage(verified._revision, scratch, root)?;
            config.bind(root)?;
            assert_eq!(fs::read_dir(root.join("home/fixture/config"))?.count(), 1);
            Ok(())
        });
        assert!(detached);
        config
            .finish(&config_parent, writable_config::Disposition::Remove, false)
            .unwrap();
        work.remove(&parent).unwrap();
        match mode.as_str() {
            "replace" => result.unwrap(),
            "modify" | "missing" | "generation" => assert!(matches!(result, Err(Fault::Identity))),
            _ => panic!("unknown staging case"),
        }
        eprintln!("staging case {mode}: expected outcome, mounts detached and generation removed");
    }

    #[test]
    #[ignore = "requires fixed artifacts and disposable root-owned work and config mounts"]
    fn pinned_login_artifact_set_stages_without_executing() {
        let work_path = Path::new(WORK_PARENT);
        let config_path = Path::new("/var/lib/tempest-claude-config-fixture");
        let parent = lock_parent(work_path).unwrap();
        let config_parent = lock_parent(config_path).unwrap();
        let work = WorkArea::create(&parent, work_path).unwrap();
        let config =
            writable_config::Generation::create(&config_parent, config_path, &work).unwrap();
        let files = pin_artifacts(ARTIFACTS).unwrap();
        let mut detached = false;
        let result = trial_with_detach(&work.path, &mut detached, |scratch, root| {
            for path in [
                "bin",
                "lib64",
                "lib",
                "lib/x86_64-linux-gnu",
                "home",
                "home/fixture",
                "home/fixture/config",
            ] {
                fs::create_dir(root.join(path))?;
            }
            assert!(matches!(
                stage_fixed_artifacts(scratch, root, ARTIFACTS, Some(&files[..files.len() - 1])),
                Err(Fault::Identity)
            ));
            assert!(!scratch.join("artifact-0").exists());
            stage_fixed_artifacts(scratch, root, ARTIFACTS, Some(&files))?;
            config.bind(root)?;
            assert_eq!(fs::read_dir(root.join("home/fixture/config"))?.count(), 1);
            Ok(())
        });
        assert!(detached);
        config
            .finish(&config_parent, writable_config::Disposition::Remove, false)
            .unwrap();
        work.remove(&parent).unwrap();
        result.unwrap();
    }

    #[test]
    #[ignore = "requires a root-owned fixture under /var/lib"]
    fn unused_ledger_diagnostic_does_not_reserve_a_permit() {
        let directory = Path::new("/var/lib").join(format!(
            "tempest-ledger-race-{}",
            crate::private_io::random_hex().unwrap()
        ));
        let ledger = lock_parent(&directory).unwrap();
        let now = std::time::Instant::now();
        let scope = login_permit::Scope {
            executable_sha256: BUSYBOX.sha256,
            arguments: &LOGIN_ARGS,
            authority: login_connect::AUTHORITY,
            target_id: "fixture",
            approved_ips_revision: 1,
        };
        let permit = login_permit::Permit {
            id: 10,
            scope,
            expires_at: now + std::time::Duration::from_secs(10),
        };
        check_unused_login_permit(&ledger, permit.id).unwrap();
        let mut original = directory.clone();
        original.set_extension("original");
        let settings = "policy";
        let write_settings = |parent: &Path, data: &[u8]| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(parent.join(settings))
                .unwrap();
            file.write_all(data).unwrap();
        };
        write_settings(&directory, b"original");
        fs::rename(&directory, &original).unwrap();
        fs::create_dir(&directory).unwrap();
        write_settings(&directory, b"replacement");
        assert_eq!(
            read_login_child(&ledger, settings, 32).unwrap(),
            b"original"
        );
        let competitor = File::open(&original).unwrap();
        login_permit::consume(&competitor, &permit, scope, now).unwrap();
        assert_eq!(
            login_permit::consume(&ledger, &permit, scope, now)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(!directory.join(format!("{:032x}", permit.id)).exists());
        fs::remove_dir_all(original).unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[ignore = "requires a root-owned fixture under /var/lib"]
    fn fixed_cli_preflight_refuses_missing_wrong_and_linked_artifacts() {
        use std::os::unix::fs::symlink;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let directory = Path::new("/var/lib").join(format!(
            "tempest-cli-preflight-{}",
            crate::private_io::random_hex().unwrap()
        ));
        let _parent = lock_parent(&directory).unwrap();
        let path = directory.join("cli");
        let other = directory.join("other");
        let artifact = Artifact {
            source: path.to_str().unwrap(),
            bytes: 5,
            sha256: "b5a2c96250612366ea272ffac6d9744aaf4b45aacd96aa7cfcb931ee3b558259",
            targets: &[],
        };
        assert!(matches!(
            verify_fixed_artifact(&artifact),
            Err(Fault::Kernel(libc::ENOENT))
        ));
        fs::write(&path, b"dummy").unwrap();
        verify_fixed_artifact(&artifact).unwrap();
        fs::write(&path, b"other").unwrap();
        assert!(matches!(
            verify_fixed_artifact(&artifact),
            Err(Fault::Identity)
        ));
        fs::remove_file(&path).unwrap();
        fs::write(&other, b"dummy").unwrap();
        symlink(&other, &path).unwrap();
        assert!(matches!(
            verify_fixed_artifact(&artifact),
            Err(Fault::Kernel(libc::ELOOP))
        ));
        fs::remove_file(&path).unwrap();
        fs::hard_link(&other, &path).unwrap();
        assert!(matches!(
            verify_fixed_artifact(&artifact),
            Err(Fault::Identity)
        ));
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(matches!(
            verify_fixed_artifact(&artifact),
            Err(Fault::Identity)
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn manual_login_policy_accepts_only_fixed_authority_and_version() {
        assert!(
            validate_manual_login_policy(
                br#"{"version":1,"authority":"platform.claude.com:443"}"#.as_slice()
            )
            .is_ok()
        );
        for input in [
            br#"{"version":2,"authority":"platform.claude.com:443"}"#.as_slice(),
            br#"{"version":1,"authority":"platform.claude.com:8443"}"#,
            br#"{"version":1,"authority":"example.org:443"}"#,
            br#"{"version":1,"authority":"platform.claude.com:443","executable":"/bin/sh"}"#,
            br#"{"version":1,"version":1,"authority":"platform.claude.com:443"}"#,
            &[b' '; 4097],
        ] {
            assert_eq!(
                validate_manual_login_policy(input).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn diagnostic_registration_binds_id_to_the_validated_hostname() {
        let record = br#"{"target_hostname":"test-vm","target_id":"registered-test-23"}"#;
        assert_eq!(
            registered_diagnostic_target(record, "test-vm").unwrap(),
            "registered-test-23"
        );
        assert!(registered_diagnostic_target(record, "different-vm").is_err());
        let malformed = br#"{"target_hostname":"test-vm","target_id":"wrong id"}"#;
        assert!(registered_diagnostic_target(malformed, "test-vm").is_err());
    }

    #[test]
    fn scoped_manual_login_policy_binds_authority_allowlist_revision_and_expiry() {
        use std::time::{Duration, UNIX_EPOCH};

        let now = UNIX_EPOCH + Duration::from_secs(100);
        let settings = serde_json::json!({
            "version": 2,
            "authority": "platform.claude.com:443",
            "approved_ips": {"revision": 3, "addresses": ["192.0.2.10", "2001:db8::10"]},
            "permit": {
                "target_hostname": "tempest-test",
                "authority": "platform.claude.com:443",
                "approved_ips_revision": 3,
                "expires_unix_seconds": 160,
            },
        });
        let input = settings.to_string();
        assert!(validate_manual_login_policy_at(input.as_bytes(), now, "tempest-test").is_ok());
        assert_eq!(
            validate_manual_login_policy_at(input.as_bytes(), now, "other-host")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData,
            "the same policy must be rejected on a different Linux host",
        );

        for (path, value) in [
            ("/authority", serde_json::json!("example.invalid:443")),
            (
                "/permit/authority",
                serde_json::json!("platform.claude.com:8443"),
            ),
            ("/permit/approved_ips_revision", serde_json::json!(4)),
            ("/approved_ips/revision", serde_json::json!(0)),
            ("/approved_ips/addresses", serde_json::json!([])),
            ("/approved_ips/addresses", serde_json::json!(["not-an-ip"])),
            ("/permit/expires_unix_seconds", serde_json::json!(100)),
            ("/permit/expires_unix_seconds", serde_json::json!(161)),
        ] {
            let mut invalid = settings.clone();
            *invalid.pointer_mut(path).unwrap() = value;
            assert_eq!(
                validate_manual_login_policy_at(
                    invalid.to_string().as_bytes(),
                    now,
                    "tempest-test"
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::InvalidData,
                "{path}",
            );
        }
    }

    #[test]
    #[ignore = "requires a root-owned fixture under /var/lib"]
    fn manual_login_policy_valid_file_cannot_authorize_launch() {
        use std::os::unix::fs::DirBuilderExt;
        let directory = Path::new("/var/lib").join(format!(
            "tempest-manual-login-policy-{}",
            crate::private_io::random_hex().unwrap()
        ));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let path = directory.join("policy.json");
        let link = directory.join("link.json");
        let result = (|| -> io::Result<_> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(br#"{"version":1,"authority":"platform.claude.com:443"}"#)?;
            std::os::unix::fs::symlink(&path, &link)?;
            Ok((
                check_manual_login_policy(&path).unwrap_err().kind(),
                check_manual_login_policy(&link).unwrap_err().kind(),
            ))
        })();
        fs::remove_dir_all(directory).unwrap();
        assert_eq!(
            result.unwrap(),
            (io::ErrorKind::Unsupported, io::ErrorKind::PermissionDenied)
        );
    }

    #[test]
    fn manual_login_policy_rejects_untrusted_paths() {
        assert_eq!(
            check_manual_login_policy(Path::new("policy.json"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            check_manual_login_policy(Path::new("/tmp/policy.json"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            check_manual_login_policy(Path::new("/etc/passwd"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn fixed_login_invocation_uses_configured_artifact_and_proxy() {
        let command = fixed_login_command(Path::new("/unused")).unwrap();
        assert_eq!(command.get_program(), LOGIN_EXECUTABLE);
        assert_eq!(command.get_args().collect::<Vec<_>>(), LOGIN_ARGS);
        let environment = command
            .get_envs()
            .map(|(key, value)| (key.to_str().unwrap(), value.unwrap().to_str().unwrap()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            environment,
            std::collections::BTreeMap::from([
                ("CLAUDE_CONFIG_DIR", "/home/fixture/config"),
                ("HOME", "/home/fixture"),
                ("HTTPS_PROXY", local_auth::PROXY_URL),
                ("HTTP_PROXY", local_auth::PROXY_URL),
                ("NO_PROXY", ""),
            ])
        );
        assert_eq!(
            ARTIFACTS[0].targets[0],
            LOGIN_EXECUTABLE.trim_start_matches('/')
        );
    }

    #[test]
    fn dedicated_terminal_rejects_split_or_redirected_stdio() {
        fn terminals() -> (File, File) {
            let mut master = -1;
            let mut slave = -1;
            assert_eq!(
                unsafe {
                    libc::openpty(
                        &mut master,
                        &mut slave,
                        std::ptr::null_mut(),
                        std::ptr::null(),
                        std::ptr::null(),
                    )
                },
                0
            );
            unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) }
        }

        let (master, slave) = terminals();
        let identical = slave.try_clone().unwrap();
        let (_other_master, other_slave) = terminals();
        let redirected = File::open("/dev/null").unwrap();
        assert!(verify_shared_terminal(slave.as_raw_fd(), identical.as_raw_fd()).is_ok());
        assert!(verify_shared_terminal(slave.as_raw_fd(), other_slave.as_raw_fd()).is_err());
        assert!(verify_shared_terminal(slave.as_raw_fd(), redirected.as_raw_fd()).is_err());
        assert!(verify_shared_terminal(master.as_raw_fd(), master.as_raw_fd()).is_err());
    }

    #[test]
    #[ignore = "requires root and private mount and PID namespaces"]
    fn fixed_child_requires_verified_network_identity_before_spawn() {
        use std::{process::Command, time::Duration};
        let worker = unsafe { libc::fork() };
        assert!(worker >= 0);
        if worker == 0 {
            let current = File::open("/proc/thread-self/ns/net").unwrap();
            let identity = fd_identity(&current).unwrap();
            let mut good = Command::new("/usr/bin/true");
            good.env_clear();
            let mut good_reaped = false;
            let good = run_in_pid_namespace_expecting(
                good,
                Duration::from_secs(2),
                &mut good_reaped,
                0,
                None,
                ChildNetwork::Verified(identity),
            );
            let mut refused = Command::new("/usr/bin/true");
            refused.env_clear();
            let mut refused_reaped = false;
            let refused = run_in_pid_namespace_expecting(
                refused,
                Duration::from_secs(2),
                &mut refused_reaped,
                0,
                None,
                ChildNetwork::Verified((identity.0, identity.1 ^ 1)),
            );
            let success = good.is_ok() && good_reaped && refused.is_err() && refused_reaped;
            unsafe { libc::_exit(i32::from(!success)) };
        }
        let status = wait_for_supervisor(worker).unwrap();
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    }

    #[test]
    fn loader_aliases_share_one_artifact_and_all_targets_are_unique() {
        use std::collections::BTreeSet;
        let mut targets = BTreeSet::new();
        for artifact in ARTIFACTS {
            for target in artifact.targets {
                assert!(targets.insert(*target));
            }
        }
        assert_eq!(targets.len(), 8);
        assert_eq!(
            ARTIFACTS
                .iter()
                .filter(|entry| entry.targets.len() == 2)
                .count(),
            1
        );
        assert!(ARTIFACTS.iter().any(|entry| entry.targets
            == [
                "lib64/ld-linux-x86-64.so.2",
                "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            ]));
    }

    #[test]
    #[ignore = "requires root and private mount/network namespace support"]
    fn synthetic_loader_aliases_are_read_only_binds_of_the_same_inode() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let scratch = Path::new("/var/lib").join(format!(
            "tempest-claude-test-{}",
            super::super::private_io::random_hex().unwrap()
        ));
        fs::DirBuilder::new()
            .recursive(false)
            .create(&scratch)
            .unwrap();
        let result = trial(&scratch, |scratch, root| {
            let path = scratch.join("dummy");
            fs::write(&path, b"dummy")?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o555))?;
            let expected = "b5a2c96250612366ea272ffac6d9744aaf4b45aacd96aa7cfcb931ee3b558259";
            let artifact = Artifact {
                source: "/unused",
                bytes: 5,
                sha256: expected,
                targets: &["loader", "loader-alias"],
            };
            let snapshot = File::open(path)?;
            mount_artifact(root, &artifact, &snapshot)?;
            let first = fs::metadata(root.join("loader"))?;
            let second = fs::metadata(root.join("loader-alias"))?;
            assert_eq!((first.dev(), first.ino()), (second.dev(), second.ino()));
            let error = OpenOptions::new()
                .write(true)
                .open(root.join("loader"))
                .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EROFS));
            Ok(())
        });
        fs::remove_file(scratch.join("dummy")).unwrap();
        fs::remove_dir(scratch.join("root")).unwrap();
        fs::remove_dir(&scratch).unwrap();
        result.unwrap();
    }

    #[test]
    #[ignore = "requires root and private mount/network namespaces"]
    fn outer_recovery_is_limited_to_the_confirmed_staging_generation() {
        let path = Path::new("/var/lib").join(format!(
            "tempest-offline-recovery-test-{}",
            super::super::private_io::random_hex().unwrap()
        ));
        let parent = lock_parent(&path).unwrap();
        assert!(lock_parent(&path).is_err());
        let other = WorkArea::create(&parent, &path).unwrap();
        fs::write(other.path.join("artifact-0"), b"other").unwrap();

        let input = path.join("input");
        fs::write(&input, b"dummy").unwrap();
        let artifact = Artifact {
            source: input.to_str().unwrap(),
            bytes: 5,
            sha256: "b5a2c96250612366ea272ffac6d9744aaf4b45aacd96aa7cfcb931ee3b558259",
            targets: &["first"],
        };
        let stopped = WorkArea::create(&parent, &path).unwrap();
        let stopped_path = stopped.path.clone();
        let error = supervised(&parent, &stopped, |scratch, root, _, _| {
            let staged = stage_artifact(&artifact, &scratch.join("artifact-0"))?;
            mount_artifact(root, &artifact, &staged)?;
            if !fs::read_to_string("/proc/thread-self/mountinfo")?
                .lines()
                .any(|row| row.split_whitespace().nth(4) == root.join("first").to_str())
            {
                return Err(Fault::Identity);
            }
            fs::write(scratch.join("artifact-1"), b"second")?;
            unsafe { libc::raise(libc::SIGKILL) };
            unreachable!()
        })
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "offline supervisor failed during staging; work removed; signal=9"
        );
        assert!(!stopped_path.exists());
        assert_eq!(fs::read(other.path.join("artifact-0")).unwrap(), b"other");

        let replaced = WorkArea::create(&parent, &path).unwrap();
        let original = path.join("original");
        fs::rename(&replaced.path, &original).unwrap();
        fs::create_dir(&replaced.path).unwrap();
        fs::write(replaced.path.join("artifact-0"), b"replacement").unwrap();
        assert!(replaced.remove(&parent).is_err());
        assert!(original.is_dir());
        assert_eq!(
            fs::read(replaced.path.join("artifact-0")).unwrap(),
            b"replacement"
        );

        let scope = login_permit::Scope {
            executable_sha256: BUSYBOX.sha256,
            arguments: &LOGIN_ARGS,
            authority: login_connect::AUTHORITY,
            target_id: "synthetic-recovery",
            approved_ips_revision: 1,
        };
        use ring::signature::{Ed25519KeyPair, KeyPair};
        use std::time::{Duration, Instant};
        let key = Ed25519KeyPair::from_seed_unchecked(&[5; 32]).unwrap();
        let public_key = key.public_key().as_ref().try_into().unwrap();
        let consume_signed = |ledger: &File, signed: &[u8], signature: &[u8]| {
            let now = Instant::now();
            let (id, _) =
                login_handoff::verify_handoff(public_key, signed, signature, scope, 130, 100)?;
            login_permit::consume(
                ledger,
                &login_permit::Permit {
                    id,
                    expires_at: now + Duration::from_secs(30),
                    scope,
                },
                scope,
                now,
            )
        };
        let consume = |id| {
            let (signed, signature) = login_handoff::signed_fixture(&key, id, scope, 140);
            consume_signed(&parent, &signed, signature.as_ref())
        };
        let entries_before = fs::read_dir(&path).unwrap().count();
        let (mut altered, signature) = login_handoff::signed_fixture(&key, 5, scope, 140);
        altered.push(b' ');
        assert_eq!(
            consume_signed(&parent, &altered, signature.as_ref())
                .unwrap_err()
                .to_string(),
            "invalid handoff signature"
        );
        let wrong_target = login_permit::Scope {
            target_id: "different-target",
            ..scope
        };
        let (signed, signature) = login_handoff::signed_fixture(&key, 6, wrong_target, 140);
        assert_eq!(
            consume_signed(&parent, &signed, signature.as_ref())
                .unwrap_err()
                .to_string(),
            "handoff scope mismatch"
        );
        assert_eq!(fs::read_dir(&path).unwrap().count(), entries_before);
        let unsyncable = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(&path)
            .unwrap();
        let (signed, signature) = login_handoff::signed_fixture(&key, 7, scope, 140);
        assert_eq!(
            consume_signed(&unsyncable, &signed, signature.as_ref())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EBADF)
        );
        assert_eq!(
            consume(7).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let starts = std::cell::Cell::new(0);
        let start = |ledger: &File, id, signed: &[u8], signature: &[u8]| {
            consume_signed(ledger, signed, signature)?;
            starts.set(starts.get() + 1);
            let work = WorkArea::create(&parent, &path)?;
            let result = supervised(&parent, &work, |_, _, control, reaped| {
                request_cli_start(control)?;
                if !login_permit::revoke(&parent, id)
                    .is_err_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
                {
                    return Err(Fault::Identity);
                }
                let mut child = std::process::Command::new("/bin/sleep");
                child.arg("60");
                match run_in_pid_namespace(child, Duration::from_millis(200), reaped) {
                    Err(Fault::ReportTimeout) => Err(Fault::ReportTimeout),
                    _ => {
                        *reaped = false;
                        Err(Fault::Identity)
                    }
                }
            });
            assert!(
                !work.path.exists(),
                "verified stop must remove the generation"
            );
            result
        };

        // The handoff has already been signed when management closes its ID.
        let (published, signature) = login_handoff::signed_fixture(&key, 8, scope, 140);
        login_permit::revoke(&parent, 8).unwrap();
        let before_denials = fs::read_dir(&path).unwrap().count();
        assert_eq!(
            start(&parent, 8, &published, signature.as_ref())
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let unusable = File::open(&input).unwrap();
        let (published, signature) = login_handoff::signed_fixture(&key, 9, scope, 140);
        assert_eq!(
            start(&unusable, 9, &published, signature.as_ref())
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOTDIR)
        );
        assert_eq!(starts.get(), 0);
        assert_eq!(fs::read_dir(&path).unwrap().count(), before_denials);

        let error = start(&parent, 9, &published, signature.as_ref()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "offline CLI diagnostic failed; work removed after verified termination; signal=0"
        );
        assert_eq!(
            start(&parent, 9, &published, signature.as_ref())
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(starts.get(), 1);

        consume(1).unwrap();
        let retained = WorkArea::create(&parent, &path).unwrap();
        let error = supervised(&parent, &retained, |scratch, _, control, _| {
            fs::write(scratch.join("artifact-0"), b"retained")?;
            request_cli_start(control)?;
            unsafe { libc::raise(libc::SIGKILL) };
            unreachable!()
        })
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "offline supervisor failed after CLI grant; work retained; signal=9"
        );
        assert_eq!(
            fs::read(retained.path.join("artifact-0")).unwrap(),
            b"retained"
        );

        assert_eq!(
            consume(1).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        for (permit_id, timeout_case) in [(2, false), (3, true)] {
            use std::{process::Command, time::Duration};
            consume(permit_id).unwrap();
            let failed = WorkArea::create(&parent, &path).unwrap();
            let error = supervised(&parent, &failed, |scratch, _, control, reaped| {
                fs::write(scratch.join("artifact-0"), b"dummy-failure")?;
                request_cli_start(control)?;
                let mut command = Command::new(if timeout_case {
                    std::path::PathBuf::from("/bin/sleep")
                } else {
                    scratch.join("absent-executable")
                });
                let deadline = if timeout_case {
                    command.arg("60");
                    Duration::from_millis(200)
                } else {
                    Duration::from_secs(2)
                };
                let result = run_in_pid_namespace(command, deadline, reaped);
                match (timeout_case, result) {
                    (true, Err(Fault::ReportTimeout)) => Err(Fault::ReportTimeout),
                    (false, Err(Fault::Identity)) => Err(Fault::Identity),
                    _ => {
                        *reaped = false;
                        Err(Fault::Identity)
                    }
                }
            })
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                "offline CLI diagnostic failed; work removed after verified termination; signal=0"
            );
            assert!(!failed.path.exists());
            assert_eq!(
                consume(permit_id).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }

        consume(4).unwrap();
        let restarted = WorkArea::create(&parent, &path).unwrap();
        assert_ne!(retained.path, restarted.path);
        assert_eq!(
            supervised(&parent, &restarted, |scratch, _, control, reaped| {
                fs::write(scratch.join("artifact-0"), b"control")?;
                request_cli_start(control)?;
                run_in_pid_namespace(
                    std::process::Command::new("/bin/true"),
                    std::time::Duration::from_secs(2),
                    reaped,
                )?;
                Ok((1, 2))
            })
            .unwrap(),
            (1, 2)
        );
        assert!(!restarted.path.exists());
        assert_eq!(
            fs::read(retained.path.join("artifact-0")).unwrap(),
            b"retained"
        );
        fs::remove_dir_all(path).unwrap();
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct SyntheticStopTarget {
        run_id: u128,
        generation: (u64, u64),
    }

    fn request_synthetic_stop(
        active: &mut Option<(SyntheticStopTarget, &UnixStream)>,
        requested: SyntheticStopTarget,
    ) -> io::Result<bool> {
        let Some((target, sender)) = *active else {
            return Ok(false);
        };
        if target != requested {
            return Ok(false);
        }
        sender.shutdown(std::net::Shutdown::Both)?;
        *active = None;
        Ok(true)
    }

    #[test]
    #[ignore = "requires root and private mount/network namespaces"]
    fn synthetic_admin_stop_matches_generation_and_reaps_descendants() {
        use std::{
            process::Command,
            time::{Duration, Instant},
        };

        let path = Path::new("/var/lib").join(format!(
            "tempest-admin-stop-test-{}",
            crate::private_io::random_hex().unwrap()
        ));
        let parent = lock_parent(&path).unwrap();
        let unrelated = WorkArea::create(&parent, &path).unwrap();
        let work = WorkArea::create(&parent, &path).unwrap();
        let target = SyntheticStopTarget {
            run_id: 10,
            generation: fd_identity(&work.pinned).unwrap(),
        };
        let alternate = SyntheticStopTarget {
            run_id: 11,
            generation: fd_identity(&unrelated.pinned).unwrap(),
        };
        let mut observation = None;
        let result = supervised_observed(
            &parent,
            &work,
            |scratch, _, control, reaped| {
                request_cli_start(control)?;
                let ready = scratch.join("artifact-0");
                let alive_after_wrong_target = scratch.join("artifact-1");
                let (receiver, sender) = UnixStream::pair()?;
                let mut child = Command::new("/bin/sh");
                child.args(["-c", r#"sleep 60 & descendant=$!; printf '%s %s' "$$" "$descendant" > "$1"; while kill -0 "$descendant"; do : > "$2"; sleep 0.02; done"#, "fixture"])
                .arg(&ready)
                .arg(&alive_after_wrong_target);
                // Keep the namespace supervisor single-threaded. The synthetic
                // sender closes only the channel bound to this generation.
                let sender_pid = unsafe { libc::fork() };
                if sender_pid < 0 {
                    return Err(io::Error::last_os_error().into());
                }
                if sender_pid == 0 {
                    let stop = (|| -> io::Result<()> {
                        let wait_until = |condition: &dyn Fn() -> bool| {
                            let deadline = Instant::now() + Duration::from_secs(2);
                            while !condition() {
                                if Instant::now() >= deadline {
                                    return Err(io::ErrorKind::TimedOut.into());
                                }
                                std::thread::sleep(Duration::from_millis(10));
                            }
                            Ok::<_, io::Error>(())
                        };
                        let mut active = Some((target, &sender));
                        wait_until(&|| {
                            fs::read_to_string(&ready)
                                .is_ok_and(|text| text.split_whitespace().count() == 2)
                        })?;
                        let heartbeat = fs::metadata(&alive_after_wrong_target)
                            .and_then(|metadata| metadata.modified())
                            .ok();
                        for wrong in [
                            alternate,
                            SyntheticStopTarget {
                                run_id: 12,
                                ..target
                            },
                            SyntheticStopTarget {
                                generation: alternate.generation,
                                ..target
                            },
                        ] {
                            if request_synthetic_stop(&mut active, wrong)? {
                                return Err(io::Error::other(
                                    "stop accepted for a mismatched execution",
                                ));
                            }
                        }
                        wait_until(&|| {
                            fs::metadata(&alive_after_wrong_target)
                                .and_then(|metadata| metadata.modified())
                                .is_ok_and(|time| heartbeat.is_none_or(|before| time > before))
                        })?;
                        if !request_synthetic_stop(&mut active, target)? {
                            return Err(io::Error::other(
                                "stop rejected for the matching generation",
                            ));
                        }
                        if request_synthetic_stop(&mut active, target)? {
                            return Err(io::Error::other("duplicate stop accepted"));
                        }
                        Ok(())
                    })();
                    unsafe { libc::_exit(if stop.is_ok() { 0 } else { 1 }) };
                }
                let outcome = run_in_pid_namespace_expecting(
                    child,
                    Duration::from_secs(8),
                    reaped,
                    0,
                    Some(receiver.as_raw_fd()),
                    ChildNetwork::NewOffline,
                );
                let status = wait_for_supervisor(sender_pid)?;
                match outcome {
                    Err(Fault::ReportEof)
                        if *reaped && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 =>
                    {
                        Ok((1, 2))
                    }
                    _ => {
                        *reaped = false;
                        Err(Fault::Identity)
                    }
                }
            },
            &mut observation,
        );
        assert_eq!(result.unwrap(), (1, 2));
        assert!(matches!(
            observation.unwrap().recovery,
            OfflineRecovery::RemovedAfterTermination
        ));
        assert!(!work.path.exists());
        assert!(unrelated.path.is_dir());
        let (reader, sender) = UnixStream::pair().unwrap();
        let mut active = Some((alternate, &sender));
        assert!(!request_synthetic_stop(&mut active, target).unwrap());
        (&sender).write_all(b"still active").unwrap();
        let mut message = [0; 12];
        (&reader).read_exact(&mut message).unwrap();
        assert_eq!(&message, b"still active");
        unrelated.remove(&parent).unwrap();
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    #[ignore = "requires root and private mount/network namespaces"]
    fn offline_grant_requires_independent_network_verification() {
        use std::{process::Command, time::Duration};

        assert_eq!(unsafe { libc::geteuid() }, 0);
        let path = Path::new("/var/lib").join(format!(
            "tempest-offline-grant-test-{}",
            super::super::private_io::random_hex().unwrap()
        ));
        let parent = lock_parent(&path).unwrap();
        let original = File::open("/proc/thread-self/ns/net").unwrap();
        let issuer_identity = fd_identity(&original).unwrap();
        assert!(verify_waiting_network(0).is_err());

        for case in ["offline", "issuer-network", "loopback-up"] {
            let work = WorkArea::create(&parent, &path).unwrap();
            let marker = path.join(case);
            let ready = path.join("ready");
            let mut observation = None;
            let result = supervised_observed(
                &parent,
                &work,
                |scratch, _, control, reaped| {
                    fs::write(scratch.join("artifact-0"), b"fixed dummy")?;
                    if case == "issuer-network" {
                        super::super::os::syscall(unsafe {
                            libc::setns(original.as_raw_fd(), libc::CLONE_NEWNET)
                        })?;
                    }
                    if case == "loopback-up"
                        && !Command::new("/usr/sbin/ip")
                            .args(["link", "set", "lo", "up"])
                            .status()?
                            .success()
                    {
                        return Err(Fault::Identity);
                    }
                    fs::write(&ready, b"ready")?;
                    request_cli_start(control)?;
                    fs::write(&marker, b"G")?;
                    run_in_pid_namespace(
                        Command::new("/bin/true"),
                        Duration::from_secs(2),
                        reaped,
                    )?;
                    Ok((1, 2))
                },
                &mut observation,
            );
            let observation = observation.unwrap();
            assert_eq!(observation.grant_attempted, case == "offline");
            assert_eq!(observation.verified_network.is_some(), case == "offline");
            assert!(
                matches!(
                    observation.recovery,
                    OfflineRecovery::RemovedAfterTermination
                ) == (case == "offline")
            );
            assert_eq!(fs::read(&ready).unwrap(), b"ready");
            fs::remove_file(ready).unwrap();
            if case == "offline" {
                assert_eq!(result.unwrap(), (1, 2));
                assert_eq!(fs::read(&marker).unwrap(), b"G");
                fs::remove_file(marker).unwrap();
            } else {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "offline supervisor failed during staging; work removed; signal=0"
                );
                assert!(!marker.exists());
            }
            assert!(!work.path.exists());
            assert_eq!(
                fd_identity(&File::open("/proc/thread-self/ns/net").unwrap()).unwrap(),
                issuer_identity
            );
        }
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    #[ignore = "requires root and private mount/network namespaces"]
    fn staging_failure_cleans_up_before_next_trial() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let fixture = Path::new("/var/lib").join(format!(
            "tempest-claude-staging-test-{}",
            super::super::private_io::random_hex().unwrap()
        ));
        fs::create_dir(&fixture).unwrap();
        let input = fixture.join("input");
        fs::write(&input, b"dummy").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"dummy"));
        let artifact = Artifact {
            source: input.to_str().unwrap(),
            bytes: 5,
            sha256: &digest,
            targets: &["first"],
        };

        for valid in [false, true] {
            let scratch = fixture.join("trial");
            fs::create_dir(&scratch).unwrap();
            let result = trial(&scratch, |scratch, root| {
                let first = stage_artifact(&artifact, &scratch.join("artifact-0"))?;
                mount_artifact(root, &artifact, &first)?;
                assert_eq!(fs::read(root.join("first"))?, b"dummy");
                assert!(
                    fs::read_to_string("/proc/thread-self/mountinfo")?
                        .lines()
                        .any(|row| {
                            row.split_whitespace().nth(4) == root.join("first").to_str()
                        })
                );

                let second = Artifact {
                    sha256: if valid { &digest } else { "invalid-digest" },
                    targets: &["second"],
                    ..artifact
                };
                let path = scratch.join("artifact-1");
                let staged = stage_artifact(&second, &path);
                if !valid {
                    assert!(matches!(staged, Err(Fault::Identity)));
                    assert_eq!(fs::read(path)?, b"dummy");
                }
                mount_artifact(root, &second, &staged?)?;
                assert_eq!(fs::read(root.join("second"))?, b"dummy");
                Ok(())
            });
            assert!(if valid {
                result.is_ok()
            } else {
                matches!(result, Err(Fault::Identity))
            });
            cleanup_trial(&scratch).unwrap();
            assert!(!scratch.exists());
        }
        fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    #[ignore = "requires root and private mount, network and PID namespaces"]
    fn fixed_dummy_descendants_are_reaped_on_exit_and_timeout() {
        use std::{process::Command, time::Duration};

        assert_eq!(unsafe { libc::geteuid() }, 0);
        let scratch = Path::new("/var/lib").join(format!(
            "tempest-claude-pid-test-{}",
            super::super::private_io::random_hex().unwrap()
        ));
        fs::create_dir(&scratch).unwrap();
        for mode in ["success", "timeout"] {
            let case = scratch.join(mode);
            fs::create_dir(&case).unwrap();
            // The test harness has multiple threads. Run the trial in a
            // single-threaded child, matching the production entry point.
            let worker = unsafe { libc::fork() };
            assert!(worker >= 0);
            if worker == 0 {
                let result = trial(&case, |scratch, root| {
                    let mut command = Command::new("/usr/bin/python3");
                    command
                        .arg("-c")
                        .arg(
                            r#"
import os, pathlib, subprocess, sys, time
root, evidence, mode = sys.argv[1:]
child = subprocess.Popen(
    ['/bin/sh', '-c', 'cd "$1" && exec /bin/sleep 60', 'dummy', root],
    start_new_session=True,
)
host_children = pathlib.Path('/proc/thread-self/children').read_text().split()
pid = host_children[0]
while os.readlink('/proc/' + pid + '/cwd') != root:
    time.sleep(0.002)
pathlib.Path(evidence).write_text(pid)
if mode == 'timeout':
    time.sleep(60)
"#,
                        )
                        .arg(root)
                        .arg(scratch.join("descendant"))
                        .arg(mode);
                    let result = run_in_pid_namespace(command, Duration::from_secs(2), &mut false);
                    match (mode, result) {
                        ("success", Ok(())) | ("timeout", Err(Fault::ReportTimeout)) => Ok(()),
                        _ => Err(Fault::Identity),
                    }
                });
                unsafe { libc::_exit(if result.is_ok() { 0 } else { 1 }) };
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(worker, &mut status, 0) }, worker);
            assert_eq!(status, 0, "{mode}");
            let pid = fs::read_to_string(case.join("descendant")).unwrap();
            assert!(!Path::new("/proc").join(pid.trim()).exists(), "{mode}");
            assert_eq!(fs::read_dir(case.join("root")).unwrap().count(), 0);
            fs::remove_dir_all(&case).unwrap();
            assert!(!case.exists());
            assert!(
                !fs::read_to_string("/proc/self/mountinfo")
                    .unwrap()
                    .contains(case.to_str().unwrap())
            );
        }
        fs::remove_dir(scratch).unwrap();
    }

    #[test]
    fn copied_bytes_must_match_fixed_length_and_digest() {
        let value = b"dummy";
        let digest = format!("{:x}", Sha256::digest(value));
        let mut staged = Vec::new();
        copy_checked(value.as_slice(), &mut staged, 5, &digest).unwrap();
        assert_eq!(staged, value);
        for input in [b"dimmu".as_slice(), b"dum", b"dummy!"] {
            assert_eq!(
                copy_checked(input, io::sink(), 5, &digest),
                Err(Fault::Identity)
            );
        }
    }
}
