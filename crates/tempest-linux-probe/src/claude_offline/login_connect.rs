use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

pub(super) const AUTHORITY: &str = "platform.claude.com:443";
const MAX_REQUEST_BYTES: usize = 4096;

/// Read only through the header terminator so subsequent TLS bytes remain unread.
fn read_request(mut input: impl Read) -> io::Result<()> {
    let mut request = Vec::new();
    for _ in 0..MAX_REQUEST_BYTES {
        let mut byte = [0];
        input.read_exact(&mut byte)?;
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let rejected = || {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid login CONNECT request",
        )
    };
    let headers = std::str::from_utf8(&request).map_err(|_| rejected())?;
    let headers = headers.strip_suffix("\r\n\r\n").ok_or_else(rejected)?;
    let mut lines = headers.split("\r\n");
    let mut start = lines.next().unwrap_or_default().split(' ');
    let (method, authority, version) = (start.next(), start.next(), start.next());
    if method != Some("CONNECT")
        || authority != Some(AUTHORITY)
        || !matches!(version, Some("HTTP/1.0" | "HTTP/1.1"))
        || start.next().is_some()
    {
        return Err(rejected());
    }
    let mut host_seen = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(rejected)?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || !value
                .bytes()
                .all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
            || name.eq_ignore_ascii_case("Content-Length")
            || name.eq_ignore_ascii_case("Transfer-Encoding")
        {
            return Err(rejected());
        }
        if name.eq_ignore_ascii_case("Host") {
            if host_seen || value.trim() != AUTHORITY {
                return Err(rejected());
            }
            host_seen = true;
        }
    }
    if version == Some("HTTP/1.1") && !host_seen {
        return Err(rejected());
    }
    Ok(())
}

/// Open the fixed tunnel only after validating the entire CONNECT request.
/// The deadline covers slow headers, even when the peer sends one byte at a time.
fn open_tunnel(
    client: &mut TcpStream,
    deadline: Instant,
    expected_peer: SocketAddr,
    dial_fixed_upstream: impl FnOnce(SocketAddr, Duration) -> io::Result<TcpStream>,
) -> io::Result<TcpStream> {
    read_request(DeadlineReader { client, deadline })?;
    let upstream = dial_fixed_upstream(expected_peer, time_remaining(deadline)?)?;
    if upstream.peer_addr()? != expected_peer {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "login upstream peer does not match the approved address",
        ));
    }
    client.set_write_timeout(Some(time_remaining(deadline)?))?;
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    Ok(upstream)
}

/// Relay opaque bytes until either peer closes or the generation's deadline expires.
fn relay(client: TcpStream, upstream: TcpStream, deadline: Instant) -> io::Result<()> {
    fn forward(mut from: &TcpStream, mut to: &TcpStream, deadline: Instant) -> io::Result<()> {
        let mut buffer = [0; 8192];
        let result = (|| {
            loop {
                from.set_read_timeout(Some(time_remaining(deadline)?))?;
                let count = from.read(&mut buffer)?;
                if count == 0 {
                    return Ok(());
                }
                let mut pending = &buffer[..count];
                while !pending.is_empty() {
                    to.set_write_timeout(Some(time_remaining(deadline)?))?;
                    let written = to.write(pending)?;
                    if written == 0 {
                        return Err(io::ErrorKind::WriteZero.into());
                    }
                    pending = &pending[written..];
                }
            }
        })();
        // Wake the other direction even if its peer remains idle.
        let _ = from.shutdown(Shutdown::Both);
        let _ = to.shutdown(Shutdown::Both);
        result
    }

    std::thread::scope(|scope| {
        let upload = std::thread::Builder::new()
            .spawn_scoped(scope, || forward(&client, &upstream, deadline))?;
        let download = forward(&upstream, &client, deadline);
        let upload = upload
            .join()
            .map_err(|_| io::Error::other("login relay worker failed"))?;
        upload.and(download)
    })
}

struct DeadlineReader<'a> {
    client: &'a mut TcpStream,
    deadline: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.client
            .set_read_timeout(Some(time_remaining(self.deadline)?))?;
        self.client.read(output)
    }
}

fn time_remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "login CONNECT deadline expired"))
}

fn accept_before(listener: &TcpListener, deadline: Instant) -> io::Result<TcpStream> {
    let mut event = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout = time_remaining(deadline)?.as_millis().saturating_add(1);
    let ready = unsafe { libc::poll(&mut event, 1, timeout.min(i32::MAX as u128) as i32) };
    if ready != 1 || event.revents != libc::POLLIN {
        return Err(io::Error::other(
            "login fixture gateway did not receive a client",
        ));
    }
    listener.accept().map(|(client, _)| client)
}

/// Exercise destination refusal and a fixed exchange inside the isolated fixture network.
pub(super) fn serve_fixture(listener: &TcpListener) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut rejected = accept_before(listener, deadline)?;
    match read_request(DeadlineReader {
        client: &mut rejected,
        deadline,
    }) {
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            rejected.set_write_timeout(Some(time_remaining(deadline)?))?;
            rejected.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")?;
        }
        _ => {
            return Err(io::Error::other(
                "login fixture expected destination refusal",
            ));
        }
    }
    drop(rejected);

    let mut client = accept_before(listener, deadline)?;
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = upstream.local_addr()?;
    let tunnel = open_tunnel(&mut client, deadline, address, |address, timeout| {
        TcpStream::connect_timeout(&address, timeout)
    })?;
    let (mut server, peer) = upstream.accept()?;
    if peer != tunnel.local_addr()? {
        return Err(io::Error::other("login fixture upstream peer mismatch"));
    }
    std::thread::scope(|scope| {
        let exchange = std::thread::Builder::new().spawn_scoped(scope, move || {
            server.set_read_timeout(Some(time_remaining(deadline)?))?;
            let mut request = [0; 4];
            server.read_exact(&mut request)?;
            if &request != b"PING" {
                return Err(io::Error::other("login fixture received unexpected data"));
            }
            server.set_write_timeout(Some(time_remaining(deadline)?))?;
            server.write_all(b"ACK\n")?;
            if server.read(&mut request)? != 0 {
                return Err(io::Error::other("login fixture expected tunnel EOF"));
            }
            Ok(())
        })?;
        let relayed = relay(client, tunnel, deadline);
        let exchanged = exchange
            .join()
            .map_err(|_| io::Error::other("login fixture upstream failed"))?;
        relayed.and(exchanged)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_fixed_authority_without_consuming_tunnel_bytes() {
        let mut input = &b"CONNECT platform.claude.com:443 HTTP/1.1\r\nHost: platform.claude.com:443\r\n\r\nTLS"[..];
        read_request(&mut input).unwrap();
        assert_eq!(input, b"TLS");
    }

    #[test]
    fn rejects_other_destinations_and_ambiguous_requests() {
        for request in [
            "CONNECT platform.claude.com:80 HTTP/1.1\r\n\r\n",
            "CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n",
            "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n",
            "GET https://platform.claude.com HTTP/1.1\r\n\r\n",
            "CONNECT platform.claude.com:443 HTTP/1.1\r\nHost: example.org\r\n\r\n",
            "CONNECT platform.claude.com:443 HTTP/1.1\r\n\r\n",
            "CONNECT platform.claude.com:443 HTTP/1.1\r\nHost: platform.claude.com:443\r\nHost: platform.claude.com:443\r\n\r\n",
            "CONNECT platform.claude.com:443 HTTP/1.1\r\nContent-Length: 1\r\n\r\n",
        ] {
            assert!(read_request(request.as_bytes()).is_err(), "{request:?}");
        }
        assert!(read_request(&vec![b'A'; MAX_REQUEST_BYTES][..]).is_err());
    }

    #[test]
    fn only_valid_connect_dials_the_local_upstream() {
        use std::net::{Ipv4Addr, TcpListener};

        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let deadline = || Instant::now() + Duration::from_secs(2);

        let mut rejected = TcpStream::connect(proxy_address).unwrap();
        rejected
            .write_all(b"CONNECT other.example:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        let (mut client, _) = proxy.accept().unwrap();
        assert_eq!(
            open_tunnel(&mut client, deadline(), upstream_address, |_, _| panic!(
                "unexpected upstream dial"
            ))
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );

        let mut allowed = TcpStream::connect(proxy_address).unwrap();
        allowed
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        allowed
            .write_all(b"CONNECT platform.claude.com:443 HTTP/1.1\r\nHost: platform.claude.com:443\r\n\r\nTLS")
            .unwrap();
        let (mut client, _) = proxy.accept().unwrap();
        let tunnel = open_tunnel(
            &mut client,
            deadline(),
            upstream_address,
            |address, timeout| TcpStream::connect_timeout(&address, timeout),
        )
        .unwrap();
        let (mut server, _) = upstream.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        let mut received = vec![0; response.len()];
        allowed.read_exact(&mut received).unwrap();
        assert_eq!(received, response);
        std::thread::scope(|scope| {
            let forwarding = scope.spawn(move || relay(client, tunnel, deadline()));
            let mut tls = [0; 3];
            server.read_exact(&mut tls).unwrap();
            assert_eq!(&tls, b"TLS");
            server.write_all(b"ACK").unwrap();
            allowed.read_exact(&mut tls).unwrap();
            assert_eq!(&tls, b"ACK");
            drop(allowed);
            assert_eq!(server.read(&mut tls).unwrap(), 0);
            forwarding.join().unwrap().unwrap();
        });
    }

    #[test]
    fn expired_request_never_dials() {
        use std::net::{Ipv4Addr, TcpListener};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let _peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut client, _) = listener.accept().unwrap();
        assert_eq!(
            open_tunnel(
                &mut client,
                Instant::now(),
                listener.local_addr().unwrap(),
                |_, _| panic!("unexpected upstream dial")
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn fixed_fixture_serves_a_complete_local_exchange() {
        let gateway = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = gateway.local_addr().unwrap();
        std::thread::scope(|scope| {
            let responder = scope.spawn(|| serve_fixture(&gateway));
            let mut rejected = TcpStream::connect(address).unwrap();
            rejected
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            rejected
                .write_all(b"CONNECT invalid.example:443 HTTP/1.1\r\n\r\n")
                .unwrap();
            let mut response = Vec::new();
            rejected.read_to_end(&mut response).unwrap();
            assert_eq!(response, b"HTTP/1.1 403 Forbidden\r\n\r\n");

            let mut client = TcpStream::connect(address).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            client
                .write_all(b"CONNECT platform.claude.com:443 HTTP/1.1\r\nHost: platform.claude.com:443\r\n\r\nPING")
                .unwrap();
            let expected = b"HTTP/1.1 200 Connection Established\r\n\r\nACK\n";
            let mut response = vec![0; expected.len()];
            client.read_exact(&mut response).unwrap();
            assert_eq!(response, expected);
            drop(client);
            responder.join().unwrap().unwrap();
        });
    }

    #[test]
    fn unexpected_upstream_peer_is_closed_before_connect_success() {
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let allowed = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let wrong = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut caller = TcpStream::connect(proxy.local_addr().unwrap()).unwrap();
        caller
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        caller
            .write_all(b"CONNECT platform.claude.com:443 HTTP/1.0\r\n\r\n")
            .unwrap();
        let (mut client, _) = proxy.accept().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let refused = open_tunnel(
            &mut client,
            deadline,
            allowed.local_addr().unwrap(),
            |_, timeout| TcpStream::connect_timeout(&wrong.local_addr()?, timeout),
        )
        .unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        drop(client);
        assert_eq!(caller.read(&mut [0]).unwrap(), 0);
        let (mut wrong_peer, _) = wrong.accept().unwrap();
        wrong_peer
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(wrong_peer.read(&mut [0]).unwrap(), 0);
    }
}
