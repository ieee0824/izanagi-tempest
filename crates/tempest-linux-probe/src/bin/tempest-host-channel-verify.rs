//! Verify a bounded host-channel receipt for offline interoperability checks.
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::Value;
use std::{
    fs,
    io::{self, Read},
    process::ExitCode,
};

fn exchange(request: &[u8]) -> io::Result<Vec<u8>> {
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

fn verify() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 5 && args.len() != 6 {
        return Err(
            "usage: tempest-host-channel-verify PUBLIC_KEY REQUEST NOW_UNIX_MS LEDGER_ID [--vsock]"
                .into(),
        );
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
    let mut now: u64 = args[3].to_str().ok_or("invalid time")?.parse()?;
    let mut input = Vec::new();
    if args.len() == 6 {
        if args[5] != "--vsock" {
            return Err("invalid transport".into());
        }
        input = exchange(&serde_json::to_vec(&request)?)?;
        now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
            .try_into()?;
    } else {
        io::stdin().take(4097).read_to_end(&mut input)?;
    }
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
    let expected_ledger = args[4].to_str().ok_or("invalid expected ledger")?;
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
