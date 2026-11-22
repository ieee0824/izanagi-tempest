//! Bounded native host-channel exchange and receipt verification.
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::Value;
use std::{
    fs,
    io::{self, Read},
};

pub fn exchange(request: &[u8]) -> io::Result<Vec<u8>> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(2);
    let descriptor = unsafe {
        libc::socket(
            libc::AF_VSOCK,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { fs::File::from_raw_fd(descriptor) };
    let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    address.svm_family = libc::AF_VSOCK as u16;
    address.svm_cid = 2;
    address.svm_port = 23100;
    let connected = unsafe {
        libc::connect(
            descriptor,
            (&address as *const libc::sockaddr_vm).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if connected < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
        return Err(io::Error::last_os_error());
    }
    let wait = |events| -> io::Result<()> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut item = libc::pollfd {
            fd: descriptor,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut item, 1, remaining.as_millis().max(1) as i32) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result == 0 || Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        Ok(())
    };
    wait(libc::POLLOUT)?;
    let mut error = 0i32;
    let mut length = std::mem::size_of_val(&error) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            file.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut error as *mut i32).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error));
    }
    let mut outbound = request.to_vec();
    outbound.push(b'\n');
    let mut remaining = outbound.as_slice();
    while !remaining.is_empty() {
        wait(libc::POLLOUT)?;
        match file.write(remaining) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => remaining = &remaining[count..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
    let mut response = Vec::new();
    loop {
        wait(libc::POLLIN)?;
        let mut byte = [0];
        match file.read(&mut byte) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(_) if byte[0] == b'\n' => return Ok(response),
            Ok(_) => response.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
        if response.len() > 4096 {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
}

pub fn verify_receipt(
    key: &[u8],
    request: &Value,
    input: &[u8],
    now: u64,
    expected_ledger: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    if key.len() != 32 || input.len() > 4096 {
        return Err("invalid receipt size".into());
    }
    let response: Value = serde_json::from_slice(input)?;
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
    if &response["payload"]["request"] != request {
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
    if expected_ledger.is_empty() || commit["ledger_id"].as_str() != Some(expected_ledger) {
        return Err("ledger identity mismatch".into());
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
    Ok(expires)
}

/// A verified receipt lifetime expressed on the receiver's monotonic clock.
pub struct ReceiptLease {
    pub expires_at: std::time::Instant,
    pub sequence: u64,
}

pub fn verify_lease(
    key: &[u8],
    request: &Value,
    input: &[u8],
    received_at: std::time::Instant,
    now_unix_ms: u64,
    expected_ledger: &str,
    minimum_sequence: u64,
) -> Result<ReceiptLease, Box<dyn std::error::Error>> {
    let expires = verify_receipt(key, request, input, now_unix_ms, expected_ledger)?;
    let response: Value = serde_json::from_slice(input)?;
    let sequence = response["payload"]["commit"]["sequence"]
        .as_u64()
        .ok_or("invalid sequence")?;
    if sequence < minimum_sequence {
        return Err("host ledger sequence rollback".into());
    }
    let expires_at = received_at
        .checked_add(std::time::Duration::from_millis(expires - now_unix_ms))
        .ok_or("invalid monotonic expiry")?;
    if std::time::Instant::now() >= expires_at {
        return Err("receipt expired during verification".into());
    }
    Ok(ReceiptLease {
        expires_at,
        sequence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;
    use std::time::Instant;

    #[test]
    fn lease_binds_ledger_sequence_and_monotonic_expiry() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let request = json!({"target_id":"vm", "permit_id":"a", "generation":1});
        let body = json!({"request": request, "commit": {
            "ledger_id":"ledger", "scope":request, "sequence":3, "state":"consumed"
        }, "issued_unix_ms":1000, "expires_unix_ms":2000});
        let mut message = b"izanagi-tempest:host-ledger-channel:v1\0".to_vec();
        message.extend(serde_json::to_vec(&body).unwrap());
        let signature: String = key
            .sign(&message)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let encoded = serde_json::to_vec(&json!({"payload":body, "signature":signature})).unwrap();
        let received = Instant::now();
        let lease = verify_lease(
            key.public_key().as_ref(),
            &request,
            &encoded,
            received,
            1500,
            "ledger",
            3,
        )
        .unwrap();
        assert_eq!(
            lease.expires_at,
            received + std::time::Duration::from_millis(500)
        );
        assert_eq!(lease.sequence, 3);
        assert!(
            verify_lease(
                key.public_key().as_ref(),
                &request,
                &encoded,
                received,
                1500,
                "other",
                3
            )
            .is_err()
        );
        assert!(
            verify_lease(
                key.public_key().as_ref(),
                &request,
                &encoded,
                received,
                1500,
                "ledger",
                4
            )
            .is_err()
        );
        assert!(
            verify_lease(
                key.public_key().as_ref(),
                &request,
                &encoded,
                received,
                2000,
                "ledger",
                3
            )
            .is_err()
        );
        // An accepted lease is an Instant, so later wall-clock changes cannot extend it.
        assert_eq!(
            lease.expires_at,
            received + std::time::Duration::from_millis(500)
        );
    }
}
