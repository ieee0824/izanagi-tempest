use super::{
    open_login_child, open_pinned_login_policy, open_private_login_directory, pin_login_path,
    read_login_child,
};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{self, KeyPair},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::Path,
    process::ExitCode,
    time::{Duration, Instant},
};

const MANAGEMENT_PARENT: &str = "/var/lib/izanagi-tempest";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CommittedCheckpoint {
    sequence: u64,
    digest: String,
}

#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Scope {
    generation: u64,
    permit_id: String,
    target_id: String,
}

// Declaration order matches the sorted JSON used by the existing fixture.
#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Commit {
    ledger_id: String,
    scope: Scope,
    sequence: u64,
    state: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    challenge: String,
    commit: Commit,
    signature: String,
}

#[derive(Serialize)]
struct SignedReceipt<'a> {
    challenge: &'a str,
    commit: &'a Commit,
}

struct HostInputs {
    key: [u8; 32],
    checkpoint: CommittedCheckpoint,
    scope: Scope,
}

fn open_management_parent() -> io::Result<std::fs::File> {
    let parent = pin_login_path(Path::new(MANAGEMENT_PARENT), libc::O_DIRECTORY)?;
    let metadata = parent.metadata()?;
    use std::os::unix::fs::MetadataExt;
    if (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777) != (0, 0, 0o700) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(parent)
}

fn read_inputs(parent: &std::fs::File) -> io::Result<HostInputs> {
    let authority = open_private_login_directory(parent, "host-login-authority")?;
    let recovery = open_private_login_directory(parent, "host-login-recovery")?;
    let key = read_login_child(&authority, "verification-key", 32)?
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidData)?;
    let checkpoint: CommittedCheckpoint =
        serde_json::from_slice(&read_login_child(&recovery, "checkpoint.json", 1024)?)
            .map_err(io::Error::other)?;
    if checkpoint.sequence == 0
        || checkpoint.digest.len() != 64
        || !checkpoint
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let scope: Scope = serde_json::from_slice(&read_login_child(&authority, "scope.json", 1024)?)
        .map_err(io::Error::other)?;
    if scope.generation == 0 || !valid_id(&scope.permit_id) || !valid_id(&scope.target_id) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(HostInputs {
        key,
        checkpoint,
        scope,
    })
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn verify_receipt(
    inputs: &HostInputs,
    reader: impl BufRead,
    mut output: impl Write,
) -> io::Result<Commit> {
    let mut random = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| io::Error::other("randomness unavailable"))?;
    let challenge: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    writeln!(output, "{challenge}")?;
    output.flush()?;

    let line = read_line(reader, 4096)?;
    let receipt: Receipt = serde_json::from_slice(&line).map_err(io::Error::other)?;
    let commit = &receipt.commit;
    check_commit(inputs, commit)?;
    if receipt.challenge != challenge || receipt.signature.len() != 128 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut signature_bytes = [0; 64];
    for (output, pair) in signature_bytes
        .iter_mut()
        .zip(receipt.signature.as_bytes().chunks_exact(2))
    {
        let digits = std::str::from_utf8(pair).map_err(io::Error::other)?;
        *output = u8::from_str_radix(digits, 16).map_err(io::Error::other)?;
    }
    signature::UnparsedPublicKey::new(&signature::ED25519, inputs.key)
        .verify(&signed_bytes(&challenge, commit)?, &signature_bytes)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok(receipt.commit)
}

fn signed_bytes(challenge: &str, commit: &Commit) -> io::Result<Vec<u8>> {
    let mut message = b"izanagi-tempest:host-permit-receipt:fixture-v1\0".to_vec();
    serde_json::to_writer(&mut message, &SignedReceipt { challenge, commit })
        .map_err(io::Error::other)?;
    Ok(message)
}

fn read_line(reader: impl BufRead, limit: u64) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    reader.take(limit + 1).read_until(b'\n', &mut line)?;
    if line.len() as u64 > limit || line.pop() != Some(b'\n') {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(line)
}

fn check_commit(inputs: &HostInputs, commit: &Commit) -> io::Result<()> {
    let digest = Sha256::digest(serde_json::to_vec(commit).map_err(io::Error::other)?);
    if commit.scope != inputs.scope
        || !valid_id(&commit.ledger_id)
        || commit.state != "consumed"
        || commit.sequence != inputs.checkpoint.sequence
        || format!("{digest:x}") != inputs.checkpoint.digest
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

fn lock_publication(parent: &File, mode: libc::c_int) -> io::Result<File> {
    let directory = open_private_login_directory(parent, "host-login-ledger")?;
    let lock = open_pinned_login_policy(open_login_child(&directory, OsStr::new("lock"), 0)?)?;
    if unsafe { libc::flock(lock.as_raw_fd(), mode | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(lock)
}

fn read_source(parent: &File, inputs: &HostInputs) -> io::Result<Commit> {
    let source = open_private_login_directory(parent, "host-login-ledger-source")?;
    let database = OsStr::new("ledger.sqlite3");
    let mut input = open_pinned_login_policy(open_login_child(&source, database, 0)?)?;
    let mut header = [0; 20];
    input.read_exact(&mut header)?;
    if &header[..16] != b"SQLite format 3\0" || header[18..] != [1, 1] {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // The managed parent is root-owned and the management lock prevents replacement.
    let path = Path::new(MANAGEMENT_PARENT)
        .join("host-login-ledger-source")
        .join(database);
    let mut db = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(io::Error::other)?;
    db.busy_timeout(std::time::Duration::ZERO)
        .map_err(io::Error::other)?;
    let transaction = db.transaction().map_err(io::Error::other)?;
    let version: u32 = transaction
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(io::Error::other)?;
    if version != 1 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let commit = transaction
        .query_row(
            "SELECT ledger_id, target_id, permit_id, generation, sequence, state
         FROM permit_commits WHERE permit_id = ? ORDER BY sequence DESC LIMIT 1",
            [&inputs.scope.permit_id],
            |row| {
                Ok(Commit {
                    ledger_id: row.get(0)?,
                    scope: Scope {
                        target_id: row.get(1)?,
                        permit_id: row.get(2)?,
                        generation: row.get(3)?,
                    },
                    sequence: row.get(4)?,
                    state: row.get(5)?,
                })
            },
        )
        .map_err(io::Error::other)?;
    check_commit(inputs, &commit)?;
    Ok(commit)
}

fn require_no_pending(directory: &File) -> io::Result<()> {
    match open_login_child(directory, OsStr::new("pending"), 0) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::other("publication pending")),
    }
}

fn publish() -> io::Result<()> {
    let parent = open_management_parent()?;
    let _lock = lock_publication(&parent, libc::LOCK_EX)?;
    let inputs = read_inputs(&parent)?;
    let commit = read_source(&parent, &inputs)?;
    let publication = open_private_login_directory(&parent, "host-login-ledger")?;
    require_no_pending(&publication)?;
    let directory_path = Path::new("/proc/self/fd").join(publication.as_raw_fd().to_string());
    let pending = directory_path.join("pending");
    let temporary = directory_path.join("record.new");
    let directory = File::open(&directory_path)?;
    let create = |path| {
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
    };
    create(&pending)?.sync_all()?;
    directory.sync_all()?;
    let mut file = create(&temporary)?;
    serde_json::to_writer(&mut file, &commit).map_err(io::Error::other)?;
    file.sync_all()?;
    std::fs::rename(&temporary, directory_path.join("record.json"))?;
    directory.sync_all()?;
    std::fs::remove_file(&pending)?;
    directory.sync_all()
}

pub(crate) fn run_host_login_publisher() -> ExitCode {
    if std::env::args_os().len() == 1 && unsafe { libc::geteuid() } == 0 && publish().is_ok() {
        ExitCode::SUCCESS
    } else {
        eprintln!("host login publication refused");
        ExitCode::FAILURE
    }
}

fn respond(reader: impl BufRead, mut output: impl Write) -> io::Result<()> {
    let challenge = String::from_utf8(read_line(reader, 65)?).map_err(io::Error::other)?;
    if challenge.len() != 64
        || !challenge
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let parent = open_management_parent()?;
    let _lock = lock_publication(&parent, libc::LOCK_SH)?;
    let inputs = read_inputs(&parent)?;
    let source = read_source(&parent, &inputs)?;
    let ledger = open_private_login_directory(&parent, "host-login-ledger")?;
    require_no_pending(&ledger)?;
    let commit = serde_json::from_slice(&read_login_child(&ledger, "record.json", 2048)?)
        .map_err(io::Error::other)?;
    check_commit(&inputs, &commit)?;
    if source != commit {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let signer_directory = open_private_login_directory(&parent, "host-login-signer")?;
    let seed = read_login_child(&signer_directory, "signing-seed", 32)?;
    let signer = signature::Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|_| io::ErrorKind::InvalidData)?;
    if signer.public_key().as_ref() != inputs.key {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let signature = signer.sign(&signed_bytes(&challenge, &commit)?);
    let receipt = Receipt {
        challenge,
        commit,
        signature: signature
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    };
    let mut line = serde_json::to_vec(&receipt).map_err(io::Error::other)?;
    line.push(b'\n');
    if line.len() > 4096 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    output.write_all(&line)?;
    output.flush()
}

pub(crate) fn run_host_login_responder() -> ExitCode {
    if std::env::args_os().len() == 1
        && unsafe { libc::geteuid() } == 0
        && respond(io::stdin().lock(), io::stdout().lock()).is_ok()
    {
        ExitCode::SUCCESS
    } else {
        eprintln!("host login responder refused");
        ExitCode::FAILURE
    }
}

pub(crate) fn run_host_login_diagnostic() -> ExitCode {
    if std::env::args_os().len() != 1 || unsafe { libc::geteuid() } != 0 {
        report_without_waiting(
            "host login diagnostic refused: dedicated administrator entry required",
        );
    } else {
        match open_management_parent().and_then(|parent| read_inputs(&parent)) {
            Err(_) => report_without_waiting(
                "host login diagnostic refused: management inputs unavailable or invalid",
            ),
            Ok(inputs) => match verify_receipt_from_stdio(
                &inputs,
                Instant::now() + Duration::from_secs(5),
                false,
            ) {
                Ok(_) => report_without_waiting(
                    "host login diagnostic: receipt verified; launch disabled",
                ),
                Err(_) => report_without_waiting(
                    "host login diagnostic refused: receipt unavailable or invalid",
                ),
            },
        }
    }
    ExitCode::FAILURE
}

struct DeadlineIo {
    file: File,
    deadline: Instant,
}

impl DeadlineIo {
    fn perform<T>(
        &mut self,
        events: libc::c_short,
        mut operation: impl FnMut(&mut File) -> io::Result<T>,
    ) -> io::Result<T> {
        loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "host receipt deadline expired",
                ));
            }
            let timeout = remaining
                .as_nanos()
                .div_ceil(1_000_000)
                .min(libc::c_int::MAX as u128) as libc::c_int;
            let mut descriptor = libc::pollfd {
                fd: self.file.as_raw_fd(),
                events,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut descriptor, 1, timeout) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if ready == 0 || Instant::now() >= self.deadline {
                continue;
            }
            match operation(&mut self.file) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
}

impl Read for DeadlineIo {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.perform(libc::POLLIN, |file| file.read(bytes))
    }
}

impl Write for DeadlineIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        self.perform(libc::POLLOUT, |file| file.write(bytes))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn open_nonblocking(fd: libc::c_int, write: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(!write)
        .write(write)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(format!("/proc/self/fd/{fd}"))
}

pub(super) fn report_without_waiting(message: &str) {
    if let Ok(mut output) = open_nonblocking(libc::STDERR_FILENO, true) {
        let _ = output.write(format!("{message}\n").as_bytes());
    }
}

fn verify_receipt_from_stdio(
    inputs: &HostInputs,
    deadline: Instant,
    same_pty: bool,
) -> io::Result<Commit> {
    let input = open_nonblocking(libc::STDIN_FILENO, false)?;
    let output = open_nonblocking(libc::STDOUT_FILENO, true)?;
    if same_pty {
        super::verify_shared_terminal(input.as_raw_fd(), libc::STDIN_FILENO)?;
        super::verify_shared_terminal(output.as_raw_fd(), libc::STDOUT_FILENO)?;
    }
    let reader = BufReader::new(DeadlineIo {
        file: input,
        deadline,
    });
    verify_receipt(
        inputs,
        reader,
        DeadlineIo {
            file: output,
            deadline,
        },
    )
}

pub(super) struct HostGuard {
    _local: Option<File>,
    _lease: Option<crate::host_channel::ReceiptLease>,
}

fn remote_client(
    target: &str,
    permit: u128,
    generation: u64,
) -> io::Result<Option<crate::host_channel::Client>> {
    let path = Path::new("/etc/tempest/host-channel.json");
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    let bytes = super::read_login_input(path, 4096)?;
    let registration: crate::host_channel::ChannelRegistration =
        serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if registration.target_id != target
        || registration.permit_id != format!("{permit:032x}")
        || registration.generation != generation
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let key = super::read_login_input(Path::new("/etc/tempest/host-channel-key"), 32)?
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidData)?;
    Ok(Some(crate::host_channel::Client { registration, key }))
}

pub(super) struct VerifiedHostCommit {
    key: [u8; 32],
    commit: Commit,
    remote: Option<Box<std::sync::Mutex<(crate::host_channel::Client, Instant)>>>,
}

impl VerifiedHostCommit {
    /// Recheck the same authorization without holding the publication lock
    /// during child supervision.
    pub(super) fn lock_current(&self) -> io::Result<HostGuard> {
        if let Some(remote) = &self.remote {
            let mut state = remote
                .lock()
                .map_err(|_| io::Error::other("channel state poisoned"))?;
            let expiry = state.1;
            if Instant::now() >= expiry {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let lease = state
                .0
                .query("query", expiry)
                .map_err(|error| io::Error::other(error.to_string()))?;
            state.1 = lease.expires_at;
            return Ok(HostGuard {
                _local: None,
                _lease: Some(lease),
            });
        }
        let parent = open_management_parent()?;
        let lock = lock_publication(&parent, libc::LOCK_SH)?;
        let publication = open_private_login_directory(&parent, "host-login-ledger")?;
        require_no_pending(&publication)?;
        let inputs = read_inputs(&parent)?;
        if inputs.key != self.key || read_source(&parent, &inputs)? != self.commit {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(HostGuard {
            _local: Some(lock),
            _lease: None,
        })
    }
}

pub(super) fn preflight_for_supervision(
    target_id: &str,
    permit_id: u128,
    generation: u64,
) -> io::Result<()> {
    if let Some(mut client) = remote_client(target_id, permit_id, generation)? {
        client
            .query("preflight", Instant::now() + Duration::from_secs(2))
            .map_err(|error| io::Error::other(error.to_string()))?;
        return Ok(());
    }
    let parent = open_management_parent()?;
    let _lock = lock_publication(&parent, libc::LOCK_SH)?;
    let publication = open_private_login_directory(&parent, "host-login-ledger")?;
    require_no_pending(&publication)?;
    let inputs = read_inputs(&parent)?;
    let source = read_source(&parent, &inputs)?;
    let record: Commit =
        serde_json::from_slice(&read_login_child(&publication, "record.json", 2048)?)
            .map_err(io::Error::other)?;
    if record != source
        || source.scope.target_id != target_id
        || source.scope.permit_id != format!("{permit_id:032x}")
        || source.scope.generation != generation
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

pub(super) fn verify_for_supervision(
    target_id: &str,
    permit_id: u128,
    generation: u64,
    deadline: Instant,
) -> io::Result<(VerifiedHostCommit, HostGuard)> {
    if let Some(mut client) = remote_client(target_id, permit_id, generation)? {
        let lease = client
            .query("consume", deadline)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let commit = Commit {
            ledger_id: client.registration.ledger_id.clone(),
            scope: Scope {
                target_id: target_id.to_owned(),
                permit_id: format!("{permit_id:032x}"),
                generation,
            },
            sequence: lease.sequence,
            state: "consumed".to_owned(),
        };
        let verified = VerifiedHostCommit {
            key: client.key,
            commit,
            remote: Some(Box::new(std::sync::Mutex::new((client, lease.expires_at)))),
        };
        return Ok((
            verified,
            HostGuard {
                _local: None,
                _lease: Some(lease),
            },
        ));
    }
    let parent = open_management_parent()?;
    let inputs = read_inputs(&parent)?;
    let receipt = verify_receipt_from_stdio(&inputs, deadline, true)?;
    let expected = Scope {
        target_id: target_id.to_owned(),
        permit_id: format!("{permit_id:032x}"),
        generation,
    };
    if receipt.scope != expected {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let verified = VerifiedHostCommit {
        key: inputs.key,
        commit: receipt,
        remote: None,
    };
    let lock = verified.lock_current()?;
    Ok((verified, lock))
}
