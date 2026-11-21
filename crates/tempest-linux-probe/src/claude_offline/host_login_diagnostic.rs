use super::{open_private_login_directory, pin_login_path, read_login_child};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{self, KeyPair},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, BufRead, Write},
    path::Path,
    process::ExitCode,
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
#[derive(Deserialize, Serialize)]
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
    inputs: HostInputs,
    reader: impl BufRead,
    mut output: impl Write,
) -> io::Result<()> {
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
    check_commit(&inputs, commit)?;
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
        .map_err(|_| io::ErrorKind::InvalidData.into())
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
    let inputs = read_inputs(&parent)?;
    let ledger = open_private_login_directory(&parent, "host-login-ledger")?;
    let commit = serde_json::from_slice(&read_login_child(&ledger, "record.json", 2048)?)
        .map_err(io::Error::other)?;
    check_commit(&inputs, &commit)?;
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
        eprintln!("host login diagnostic refused: dedicated administrator entry required");
    } else {
        match open_management_parent().and_then(|parent| read_inputs(&parent)) {
            Err(_) => {
                eprintln!("host login diagnostic refused: management inputs unavailable or invalid")
            }
            Ok(inputs) => match verify_receipt(inputs, io::stdin().lock(), io::stdout().lock()) {
                Ok(()) => eprintln!("host login diagnostic: receipt verified; launch disabled"),
                Err(_) => {
                    eprintln!("host login diagnostic refused: receipt unavailable or invalid")
                }
            },
        }
    }
    ExitCode::FAILURE
}
