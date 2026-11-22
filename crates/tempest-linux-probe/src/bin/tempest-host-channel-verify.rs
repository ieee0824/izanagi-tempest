//! Verify a bounded host-channel receipt for offline interoperability checks.
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::Value;
use std::{
    fs,
    io::{self, Read},
    process::ExitCode,
};

fn verify() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 4 {
        return Err("usage: tempest-host-channel-verify PUBLIC_KEY REQUEST NOW_UNIX_MS".into());
    }
    let key = fs::read(&args[1])?;
    if key.len() != 32 {
        return Err("invalid public key length".into());
    }
    let request_bytes = fs::read(&args[2])?;
    if request_bytes.len() > 1024 {
        return Err("request too large".into());
    }
    let request: Value = serde_json::from_slice(&request_bytes)?;
    let now: u64 = args[3].to_str().ok_or("invalid time")?.parse()?;
    let mut input = Vec::new();
    io::stdin().take(4097).read_to_end(&mut input)?;
    if input.len() > 4096 {
        return Err("response too large".into());
    }
    let response: Value = serde_json::from_slice(&input)?;
    let outer = response.as_object().ok_or("invalid response")?;
    if outer.len() != 2 || !outer.contains_key("payload") || !outer.contains_key("signature") {
        return Err("invalid response fields".into());
    }
    let body = response["payload"].as_object().ok_or("invalid payload")?;
    if body.len() != 4
        || !["request", "commit", "issued_unix_ms", "expires_unix_ms"]
            .iter()
            .all(|key| body.contains_key(*key))
    {
        return Err("invalid payload fields".into());
    }
    let signature = response["signature"].as_str().ok_or("invalid signature")?;
    if signature.len() != 128
        || !signature
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid signature encoding".into());
    }
    let mut decoded = [0u8; 64];
    for (output, pair) in decoded.iter_mut().zip(signature.as_bytes().chunks_exact(2)) {
        *output = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    let mut signed = b"izanagi-tempest:host-ledger-channel:v1\0".to_vec();
    signed.extend(serde_json::to_vec(&response["payload"])?);
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&signed, &decoded)
        .map_err(|_| "signature mismatch")?;
    if response["payload"]["request"] != request {
        return Err("request mismatch".into());
    }
    let issued = response["payload"]["issued_unix_ms"]
        .as_u64()
        .ok_or("invalid issued time")?;
    let expires = response["payload"]["expires_unix_ms"]
        .as_u64()
        .ok_or("invalid expiry")?;
    if issued > now
        || now >= expires
        || expires
            .checked_sub(issued)
            .is_none_or(|duration| duration == 0 || duration > 2000)
    {
        return Err("receipt expired or invalid".into());
    }
    let commit = response["payload"]["commit"]
        .as_object()
        .ok_or("invalid commit")?;
    if commit.len() != 4
        || !["ledger_id", "scope", "sequence", "state"]
            .iter()
            .all(|key| commit.contains_key(*key))
    {
        return Err("invalid commit fields".into());
    }
    let scope = commit["scope"].as_object().ok_or("invalid scope")?;
    if scope.len() != 3
        || !["target_id", "permit_id", "generation"]
            .iter()
            .all(|key| scope.get(*key) == request.get(*key))
        || commit["state"] != "consumed"
        || commit["sequence"].as_u64().is_none_or(|v| v == 0)
    {
        return Err("commit mismatch".into());
    }
    println!("host channel receipt verified");
    Ok(())
}

fn main() -> ExitCode {
    match verify() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("host channel receipt refused: {error}");
            ExitCode::FAILURE
        }
    }
}
