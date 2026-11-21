use super::{open_private_login_directory, pin_login_path, read_login_child};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature,
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

#[derive(Deserialize)]
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

fn read_inputs() -> io::Result<HostInputs> {
    let parent = pin_login_path(Path::new(MANAGEMENT_PARENT), libc::O_DIRECTORY)?;
    let metadata = parent.metadata()?;
    use std::os::unix::fs::MetadataExt;
    if (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777) != (0, 0, 0o700) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let authority = open_private_login_directory(&parent, "host-login-authority")?;
    let recovery = open_private_login_directory(&parent, "host-login-recovery")?;
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

    let mut line = Vec::new();
    reader.take(4097).read_until(b'\n', &mut line)?;
    if line.len() > 4096 || line.last() != Some(&b'\n') {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let receipt: Receipt = serde_json::from_slice(&line).map_err(io::Error::other)?;
    let commit = &receipt.commit;
    let digest = Sha256::digest(serde_json::to_vec(commit).map_err(io::Error::other)?);
    if receipt.challenge != challenge
        || commit.scope != inputs.scope
        || !valid_id(&commit.ledger_id)
        || commit.state != "consumed"
        || commit.sequence != inputs.checkpoint.sequence
        || format!("{digest:x}") != inputs.checkpoint.digest
        || receipt.signature.len() != 128
    {
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
    let mut message = b"izanagi-tempest:host-permit-receipt:fixture-v1\0".to_vec();
    serde_json::to_writer(
        &mut message,
        &SignedReceipt {
            challenge: &challenge,
            commit,
        },
    )
    .map_err(io::Error::other)?;
    signature::UnparsedPublicKey::new(&signature::ED25519, inputs.key)
        .verify(&message, &signature_bytes)
        .map_err(|_| io::ErrorKind::InvalidData.into())
}

pub(crate) fn run_host_login_diagnostic() -> ExitCode {
    if std::env::args_os().len() != 1 || unsafe { libc::geteuid() } != 0 {
        eprintln!("host login diagnostic refused: dedicated administrator entry required");
    } else {
        match read_inputs() {
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
