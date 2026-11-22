//! Trusted gateway-only vsock transport. TLS bytes remain opaque.
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{ED25519, UnparsedPublicKey},
};
use serde_json::{Value, json};
use std::{
    io::{self, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

const DOMAIN: &[u8] = b"izanagi-tempest:login-egress:v1\0";
const PORT: u32 = 23105;

pub(super) struct Route {
    request: Value,
    peer: SocketAddr,
    key: [u8; 32],
    minimum_sequence: u64,
}

impl Route {
    pub(super) fn load(
        verified: &super::VerifiedSupervisorInputs,
        peer: SocketAddr,
    ) -> io::Result<Self> {
        let client = super::host_login_diagnostic::remote_client(
            &verified._login.target_id,
            verified._login.id,
            verified._revision,
        )?
        .ok_or(io::ErrorKind::InvalidData)?;
        let registration = client.registration;
        Ok(Self {
            request: json!({"version":1, "scope":{"target_id":registration.target_id, "permit_id":registration.permit_id, "generation":registration.generation},
                "boot_id":registration.boot_id, "manifest_sha256":verified._manifest_sha256,
                "approved_ips_revision":verified.approved_route.revision,
                "authority":super::login_connect::AUTHORITY}),
            peer,
            key: client.key,
            minimum_sequence: registration.minimum_sequence,
        })
    }

    fn open(&self, deadline: Instant, stop: &(dyn Fn() -> bool + Sync)) -> io::Result<VsockStream> {
        // Start before challenge generation or any transport processing.
        let started = Instant::now();
        let deadline = deadline.min(started + Duration::from_secs(2));
        let mut challenge = [0u8; 32];
        SystemRandom::new()
            .fill(&mut challenge)
            .map_err(|_| io::Error::other("egress challenge unavailable"))?;
        let mut request = self.request.clone();
        request["challenge"] =
            Value::String(challenge.iter().map(|b| format!("{b:02x}")).collect());
        let mut stream = VsockStream::connect(deadline, stop)?;
        let mut encoded = serde_json::to_vec(&request).map_err(io::Error::other)?;
        if encoded.len() > 1024 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        encoded.push(b'\n');
        stream.write_all(&encoded, deadline, stop)?;
        let mut response = Vec::new();
        loop {
            let mut byte = [0];
            if stream.read(&mut byte, deadline, stop)? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            if byte[0] == b'\n' {
                break;
            }
            response.push(byte[0]);
            if response.len() > 4096 {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        verify_ready(
            &self.key,
            &request,
            self.peer,
            self.minimum_sequence,
            &response,
            started,
        )?;
        active(stop, deadline)?;
        Ok(stream)
    }

    pub(super) fn serve(
        &self,
        listener: &TcpListener,
        expires: Instant,
        stop: &(dyn Fn() -> bool + Sync),
    ) -> io::Result<()> {
        while Instant::now() < expires && !stop() {
            match listener.accept() {
                Ok((mut client, _)) => {
                    // Keep the existing authority/header validator before any host dial.
                    super::login_connect::read_request(super::login_connect::ManagedHeader {
                        client: &mut client,
                        deadline: expires,
                        stop,
                    })?;
                    let upstream = self.open(expires, stop)?;
                    client.set_write_timeout(Some(
                        active(stop, expires)?.min(Duration::from_millis(20)),
                    ))?;
                    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
                    relay(client, upstream, expires, stop)?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

fn active(stop: &(dyn Fn() -> bool + Sync), deadline: Instant) -> io::Result<Duration> {
    if stop() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    Ok(remaining)
}

fn wait(
    fd: i32,
    events: i16,
    deadline: Instant,
    stop: &(dyn Fn() -> bool + Sync),
) -> io::Result<()> {
    loop {
        let remaining = active(stop, deadline)?;
        let mut item = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let status = unsafe { libc::poll(&mut item, 1, remaining.as_millis().clamp(1, 20) as i32) };
        active(stop, deadline)?;
        if status > 0 {
            return Ok(());
        }
        if status < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

/// A real AF_VSOCK descriptor, never represented as a TCP stream.
struct VsockStream(OwnedFd);
impl VsockStream {
    fn connect(deadline: Instant, stop: &(dyn Fn() -> bool + Sync)) -> io::Result<Self> {
        active(stop, deadline)?;
        let fd = unsafe {
            libc::socket(
                libc::AF_VSOCK,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let stream = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        address.svm_family = libc::AF_VSOCK as u16;
        address.svm_cid = 2;
        address.svm_port = PORT;
        let status = unsafe {
            libc::connect(
                fd,
                (&raw const address).cast(),
                size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if status < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(io::Error::last_os_error());
        }
        wait(fd, libc::POLLOUT, deadline, stop)?;
        let mut error = 0i32;
        let mut length = size_of_val(&error) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut error).cast(),
                &mut length,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        let mut peer: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        let mut length = size_of_val(&peer) as libc::socklen_t;
        if unsafe { libc::getpeername(fd, (&raw mut peer).cast(), &mut length) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize != size_of_val(&peer)
            || peer.svm_family != libc::AF_VSOCK as u16
            || peer.svm_cid != 2
            || peer.svm_port != PORT
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        active(stop, deadline)?;
        Ok(stream)
    }
    fn read(
        &mut self,
        bytes: &mut [u8],
        deadline: Instant,
        stop: &(dyn Fn() -> bool + Sync),
    ) -> io::Result<usize> {
        loop {
            wait(self.0.as_raw_fd(), libc::POLLIN, deadline, stop)?;
            let count = unsafe {
                libc::recv(
                    self.0.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    0,
                )
            };
            if count >= 0 {
                return Ok(count as usize);
            }
            let error = io::Error::last_os_error();
            if !matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Err(error);
            }
        }
    }
    fn write_all(
        &mut self,
        mut bytes: &[u8],
        deadline: Instant,
        stop: &(dyn Fn() -> bool + Sync),
    ) -> io::Result<()> {
        while !bytes.is_empty() {
            wait(self.0.as_raw_fd(), libc::POLLOUT, deadline, stop)?;
            let count = unsafe {
                libc::send(
                    self.0.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            if count > 0 {
                bytes = &bytes[count as usize..];
                continue;
            }
            if count == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            let error = io::Error::last_os_error();
            if !matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Err(error);
            }
        }
        Ok(())
    }
}
impl Drop for VsockStream {
    fn drop(&mut self) {
        unsafe {
            libc::shutdown(self.0.as_raw_fd(), libc::SHUT_RDWR);
        }
    }
}

fn verify_ready(
    key: &[u8],
    request: &Value,
    peer: SocketAddr,
    floor: u64,
    input: &[u8],
    started: Instant,
) -> io::Result<()> {
    let refused = || io::Error::new(io::ErrorKind::PermissionDenied, "egress ready refused");
    if input.len() > 4096 {
        return Err(refused());
    }
    let response: Value = serde_json::from_slice(input).map_err(|_| refused())?;
    let envelope = response.as_object().ok_or_else(refused)?;
    if envelope.len() != 2 {
        return Err(refused());
    }
    let signature = response["signature"].as_str().ok_or_else(refused)?;
    if signature.len() != 128
        || !signature
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(refused());
    }
    let signature: Vec<u8> = (0..128)
        .step_by(2)
        .map(|i| u8::from_str_radix(&signature[i..i + 2], 16).map_err(|_| refused()))
        .collect::<io::Result<_>>()?;
    let body = &response["payload"];
    let mut message = DOMAIN.to_vec();
    message.extend(serde_json::to_vec(body).map_err(|_| refused())?);
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&message, &signature)
        .map_err(|_| refused())?;
    if body.as_object().is_none_or(|v| v.len() != 5)
        || body["request"] != *request
        || body["peer"] != json!({"address":peer.ip().to_string(), "port":peer.port()})
        || body["sequence"]
            .as_u64()
            .is_none_or(|v| v == 0 || v < floor)
    {
        return Err(refused());
    }
    let issued = body["issued_unix_ms"].as_u64().ok_or_else(refused)?;
    let expires = body["expires_unix_ms"].as_u64().ok_or_else(refused)?;
    let lifetime = expires
        .checked_sub(issued)
        .filter(|v| (1..=2000).contains(v))
        .ok_or_else(refused)?;
    if Instant::now()
        >= started
            .checked_add(Duration::from_millis(lifetime))
            .ok_or_else(refused)?
    {
        return Err(refused());
    }
    Ok(())
}

fn relay(
    client: TcpStream,
    upstream: VsockStream,
    deadline: Instant,
    stop: &(dyn Fn() -> bool + Sync),
) -> io::Result<()> {
    client.set_nonblocking(true)?;
    let result = (|| {
        let mut to_host = Vec::new();
        let mut to_client = Vec::new();
        loop {
            active(stop, deadline)?;
            let mut events = [
                libc::pollfd {
                    fd: client.as_raw_fd(),
                    events: 0,
                    revents: 0,
                },
                libc::pollfd {
                    fd: upstream.0.as_raw_fd(),
                    events: 0,
                    revents: 0,
                },
            ];
            if to_host.len() < 65536 {
                events[0].events |= libc::POLLIN;
            }
            if !to_client.is_empty() {
                events[0].events |= libc::POLLOUT;
            }
            if to_client.len() < 65536 {
                events[1].events |= libc::POLLIN;
            }
            if !to_host.is_empty() {
                events[1].events |= libc::POLLOUT;
            }
            let ready = unsafe { libc::poll(events.as_mut_ptr(), 2, 20) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            for (index, event) in events.iter().enumerate() {
                active(stop, deadline)?;
                if event.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                    return Ok(());
                }
                if event.revents & libc::POLLIN != 0 {
                    let pending = if index == 0 {
                        &mut to_host
                    } else {
                        &mut to_client
                    };
                    let mut buffer = [0u8; 8192];
                    let limit = buffer.len().min(65536 - pending.len());
                    let count =
                        unsafe { libc::recv(event.fd, buffer.as_mut_ptr().cast(), limit, 0) };
                    if count == 0 {
                        return Ok(());
                    }
                    if count > 0 {
                        pending.extend_from_slice(&buffer[..count as usize]);
                    } else if !matches!(
                        io::Error::last_os_error().kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) {
                        return Err(io::Error::last_os_error());
                    }
                }
                if event.revents & libc::POLLOUT != 0 {
                    active(stop, deadline)?;
                    let pending = if index == 0 {
                        &mut to_client
                    } else {
                        &mut to_host
                    };
                    let count = unsafe {
                        libc::send(
                            event.fd,
                            pending.as_ptr().cast(),
                            pending.len(),
                            libc::MSG_NOSIGNAL,
                        )
                    };
                    if count > 0 {
                        pending.drain(..count as usize);
                    } else if count == 0 {
                        return Err(io::ErrorKind::WriteZero.into());
                    } else if !matches!(
                        io::Error::last_os_error().kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
        }
    })();
    let _ = client.shutdown(std::net::Shutdown::Both);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn signed(key: &Ed25519KeyPair, body: &Value) -> Vec<u8> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(serde_json::to_vec(body).unwrap());
        let signature: String = key
            .sign(&bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        serde_json::to_vec(&json!({"payload":body,"signature":signature})).unwrap()
    }

    #[test]
    fn ready_binds_challenge_peer_sequence_and_request_start() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let request = json!({"challenge":"a".repeat(64),"scope":{"target_id":"vm"}});
        let peer: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let body = json!({"request":request,"peer":{"address":"127.0.0.1","port":443},
                          "sequence":3,"issued_unix_ms":1000,"expires_unix_ms":3000});
        let encoded = signed(&key, &body);
        assert!(
            verify_ready(
                key.public_key().as_ref(),
                &request,
                peer,
                3,
                &encoded,
                Instant::now()
            )
            .is_ok()
        );
        assert!(
            verify_ready(
                key.public_key().as_ref(),
                &request,
                peer,
                4,
                &encoded,
                Instant::now()
            )
            .is_err()
        );
        assert!(
            verify_ready(
                key.public_key().as_ref(),
                &request,
                peer,
                3,
                &encoded,
                Instant::now() - Duration::from_secs(3)
            )
            .is_err()
        );
        let mut other = request.clone();
        other["challenge"] = json!("b".repeat(64));
        assert!(
            verify_ready(
                key.public_key().as_ref(),
                &other,
                peer,
                3,
                &encoded,
                Instant::now()
            )
            .is_err()
        );
        for (field, value) in [
            ("sequence", json!(true)),
            ("peer", json!({"address":"127.0.0.2","port":443})),
            ("expires_unix_ms", json!(1000)),
            ("expires_unix_ms", json!(3001)),
            ("extra", json!(1)),
        ] {
            let mut invalid = body.clone();
            invalid[field] = value;
            assert!(
                verify_ready(
                    key.public_key().as_ref(),
                    &request,
                    peer,
                    3,
                    &signed(&key, &invalid),
                    Instant::now()
                )
                .is_err()
            );
        }
        let other_key = Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap();
        assert!(
            verify_ready(
                other_key.public_key().as_ref(),
                &request,
                peer,
                3,
                &encoded,
                Instant::now()
            )
            .is_err()
        );
    }

    #[test]
    fn control_receipt_domain_cannot_be_used_as_ready() {
        let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
        let body = json!({"request":{},"peer":{"address":"127.0.0.1","port":443},"sequence":1,"issued_unix_ms":1,"expires_unix_ms":2001});
        let mut bytes = b"izanagi-tempest:host-ledger-channel:v1\0".to_vec();
        bytes.extend(serde_json::to_vec(&body).unwrap());
        let signature: String = key
            .sign(&bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let encoded = serde_json::to_vec(&json!({"payload":body,"signature":signature})).unwrap();
        assert!(
            verify_ready(
                key.public_key().as_ref(),
                &json!({}),
                "127.0.0.1:443".parse().unwrap(),
                1,
                &encoded,
                Instant::now()
            )
            .is_err()
        );
    }

    #[test]
    fn opaque_fd_relay_closes_both_ends_on_stop() {
        use std::{
            os::unix::net::UnixStream,
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let (gateway, _) = listener.accept().unwrap();
        // Unix socketpair exercises opaque FD I/O only; native vsock identity
        // checking remains in connect() and needs the real-VM acceptance test.
        let (transport, mut server) = UnixStream::pair().unwrap();
        transport.set_nonblocking(true).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let child_stop = stop.clone();
        let worker = std::thread::spawn(move || {
            relay(
                gateway,
                VsockStream(transport.into()),
                Instant::now() + Duration::from_secs(2),
                &|| child_stop.load(Ordering::Acquire),
            )
        });
        client.write_all(b"\x00opaque-TLS").unwrap();
        let mut bytes = [0; 11];
        std::io::Read::read_exact(&mut server, &mut bytes).unwrap();
        assert_eq!(&bytes, b"\x00opaque-TLS");
        server.write_all(b"reply").unwrap();
        let mut bytes = [0; 5];
        std::io::Read::read_exact(&mut client, &mut bytes).unwrap();
        assert_eq!(&bytes, b"reply");
        stop.store(true, Ordering::Release);
        assert_eq!(std::io::Read::read(&mut client, &mut [0]).unwrap(), 0);
        assert_eq!(std::io::Read::read(&mut server, &mut [0]).unwrap(), 0);
        assert!(worker.join().unwrap().is_err());
    }
}
