use super::local_auth::Case;
use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
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

fn approved_peer(resolved: &[IpAddr], approved: &[IpAddr], port: u16) -> io::Result<SocketAddr> {
    resolved
        .iter()
        .find(|address| approved.contains(address))
        .map(|address| SocketAddr::new(*address, port))
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "no approved login address"))
}

fn require_active(stop: &(dyn Fn() -> bool + Sync), deadline: Instant) -> io::Result<Duration> {
    if stop() {
        return Err(io::Error::other("managed login authorization ended"));
    }
    time_remaining(deadline)
}

fn connect_managed(
    peer: SocketAddr,
    deadline: Instant,
    stop: &(dyn Fn() -> bool + Sync),
) -> io::Result<TcpStream> {
    use std::os::fd::{FromRawFd, OwnedFd};

    require_active(stop, deadline)?;
    let domain = if peer.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let connect = |address, length| unsafe { libc::connect(fd.as_raw_fd(), address, length) };
    require_active(stop, deadline)?;
    let status = match peer {
        SocketAddr::V4(peer) => {
            let address = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: peer.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(peer.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            connect(
                (&raw const address).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(peer) => {
            let address = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: peer.port().to_be(),
                sin6_flowinfo: peer.flowinfo().to_be(),
                sin6_addr: libc::in6_addr {
                    s6_addr: peer.ip().octets(),
                },
                sin6_scope_id: peer.scope_id(),
            };
            connect(
                (&raw const address).cast(),
                size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    };
    if status != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
        loop {
            let remaining = require_active(stop, deadline)?;
            let mut event = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let wait_ms = remaining.as_millis().clamp(1, 20) as libc::c_int;
            let ready = unsafe { libc::poll(&mut event, 1, wait_ms) };
            match ready {
                1 => break,
                0 => {}
                _ => {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
        }
    }
    let stream = TcpStream::from(fd);
    if let Some(error) = stream.take_error()? {
        return Err(error);
    }
    require_active(stop, deadline)?;
    stream.set_nonblocking(false)?;
    Ok(stream)
}

struct ManagedHeader<'a> {
    client: &'a mut TcpStream,
    deadline: Instant,
    stop: &'a (dyn Fn() -> bool + Sync),
}

impl Read for ManagedHeader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            let remaining = require_active(self.stop, self.deadline)?;
            self.client
                .set_read_timeout(Some(remaining.min(Duration::from_millis(20))))?;
            match self.client.read(output) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
}

fn open_managed_tunnel(
    client: &mut TcpStream,
    peer: SocketAddr,
    deadline: Instant,
    stop: &(dyn Fn() -> bool + Sync),
) -> io::Result<TcpStream> {
    read_request(ManagedHeader {
        client,
        deadline,
        stop,
    })?;
    let upstream = connect_managed(peer, deadline, stop)?;
    if upstream.peer_addr()? != peer {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    client.set_write_timeout(Some(require_active(stop, deadline)?))?;
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    Ok(upstream)
}

/// Use a pinned numeric peer after validating the fixed CONNECT authority.
fn relay_fixed_request(
    mut client: TcpStream,
    peer: SocketAddr,
    deadline: Instant,
    stop: Option<&(dyn Fn() -> bool + Sync)>,
) -> io::Result<()> {
    let result = if let Some(stop) = stop {
        open_managed_tunnel(&mut client, peer, deadline, stop)
    } else {
        open_tunnel(&mut client, deadline, peer, |address, timeout| {
            TcpStream::connect_timeout(&address, timeout)
        })
    };
    let tunnel = match result {
        Ok(tunnel) => tunnel,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            client.set_write_timeout(Some(time_remaining(deadline)?))?;
            client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")?;
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    if let Some(stop) = stop {
        relay_until_revoked(client, tunnel, deadline, stop, true)
    } else {
        relay(client, tunnel, deadline)
    }
}

/// Serve the bounded owner-interactive route. Its socket address is pinned
/// before entering the client namespace and never comes from the CONNECT request.
pub(super) fn serve_managed(
    listener: &TcpListener,
    peer: SocketAddr,
    expires: Instant,
    stop: &(dyn Fn() -> bool + Sync),
) -> io::Result<()> {
    loop {
        if Instant::now() >= expires || stop() {
            return Ok(());
        }
        match listener.accept() {
            Ok((client, _)) => {
                if stop() {
                    return Ok(());
                }
                match relay_fixed_request(client, peer, expires, Some(stop)) {
                    Ok(()) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::PermissionDenied
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::BrokenPipe
                                | io::ErrorKind::UnexpectedEof
                        ) => {}
                    Err(_) if Instant::now() >= expires || stop() => return Ok(()),
                    Err(error) => return Err(error),
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) struct FixtureUpstream {
    listener: TcpListener,
    peer: SocketAddr,
}

impl FixtureUpstream {
    pub fn prepare(case: Case) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let resolved = match case {
            Case::EmptyResolution => None,
            Case::UnapprovedResolution => Some(IpAddr::from([127, 0, 0, 2])),
            _ => Some(address.ip()),
        };
        let peer = approved_peer(resolved.as_slice(), &[address.ip()], address.port())?;
        Ok(Self { listener, peer })
    }
}

/// Exercise destination refusal and a fixed exchange inside the isolated fixture network.
pub(super) fn serve_fixture(
    listener: &TcpListener,
    upstream: FixtureUpstream,
    case: Case,
    expires: Instant,
    stop: Option<&super::FixtureStop>,
) -> io::Result<()> {
    let host = matches!(stop, Some(super::FixtureStop::Host(..)));
    let deadline = fixture_authorization_deadline(Instant::now(), expires, host);
    let cleanup_deadline = if host {
        expires + Duration::from_secs(1)
    } else {
        deadline
    };
    let stopped = || stop.is_some_and(super::FixtureStop::requested);
    require_active(&stopped, deadline)?;
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
    let tunnel = open_managed_tunnel(&mut client, upstream.peer, deadline, &stopped)?;
    let (mut server, peer) = upstream.listener.accept()?;
    if peer != tunnel.local_addr()? {
        return Err(io::Error::other("login fixture upstream peer mismatch"));
    }
    std::thread::scope(|scope| {
        let exchange = std::thread::Builder::new().spawn_scoped(scope, move || {
            server.set_read_timeout(Some(time_remaining(cleanup_deadline)?))?;
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
        // The signed TLS exercise uses a separate local TLS probe while the
        // fixed PTY child keeps its ordinary ACK tunnel open.
        let tls = if matches!(case, Case::SignedTls) {
            Some(std::thread::Builder::new().spawn_scoped(scope, || {
                let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 39275));
                for expects_rejection in [false, true] {
                    let client = accept_before(listener, deadline)?;
                    match relay_fixed_request(
                        client,
                        peer,
                        deadline,
                        host.then_some(&stopped as &(dyn Fn() -> bool + Sync)),
                    ) {
                        // The client aborts the second handshake with a TLS alert.
                        Err(error)
                            if expects_rejection
                                && error.kind() == io::ErrorKind::ConnectionReset => {}
                        result => result?,
                    }
                }
                // A Host exercise may keep an additional TLS peer live until
                // management stop. Existing two-handshake fixtures need not
                // connect again: their stop ends this optional accept loop.
                if host {
                    while require_active(&stopped, deadline).is_ok() {
                        match listener.accept() {
                            Ok((client, _)) => {
                                let result =
                                    relay_fixed_request(client, peer, deadline, Some(&stopped));
                                if stopped() {
                                    return Ok(());
                                }
                                result?;
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(10));
                            }
                            Err(error) => return Err(error),
                        }
                    }
                }
                Ok::<_, io::Error>(())
            })?)
        } else if matches!(case, Case::SignedTlsExpiry | Case::SignedTlsRevocation) {
            Some(std::thread::Builder::new().spawn_scoped(scope, || {
                let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 39275));
                let mut client = accept_before(listener, expires)?;
                let tunnel = open_tunnel(&mut client, expires, peer, |address, timeout| {
                    TcpStream::connect_timeout(&address, timeout)
                })?;
                if let Some(stop) = stop {
                    relay_until_revoked(client, tunnel, deadline, &|| stop.requested(), false)?;
                } else {
                    finish_expiring_relay(relay(client, tunnel, expires), expires)?;
                }
                // The signed IP revision's freshness ended. Check the next
                // CONNECT but do not create another upstream socket.
                let mut denied = accept_before(listener, deadline)?;
                read_request(DeadlineReader {
                    client: &mut denied,
                    deadline,
                })?;
                denied.set_write_timeout(Some(time_remaining(deadline)?))?;
                denied.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")?;
                Ok(())
            })?)
        } else {
            None
        };
        let relayed = if let Some(stop @ super::FixtureStop::Host(..)) = stop {
            let result = relay_until_revoked_with_cleanup(
                client,
                tunnel,
                deadline,
                cleanup_deadline,
                &|| stop.requested(),
                true,
            );
            if Instant::now() >= deadline {
                finish_expiring_relay(result, deadline)
            } else {
                result
            }
        } else if matches!(case, Case::SignedTlsExpiry) {
            finish_expiring_relay(relay(client, tunnel, expires), expires)
        } else {
            relay(client, tunnel, deadline)
        };
        let exchanged = exchange
            .join()
            .map_err(|_| io::Error::other("login fixture upstream failed"))?;
        if let Some(tls) = tls {
            tls.join()
                .map_err(|_| io::Error::other("local TLS relay failed"))??;
        }
        relayed.and(exchanged)
    })
}

fn fixture_authorization_deadline(now: Instant, expires: Instant, host: bool) -> Instant {
    if host {
        expires
    } else {
        now + Duration::from_secs(8)
    }
}

fn relay_until_revoked(
    client: TcpStream,
    tunnel: TcpStream,
    deadline: Instant,
    stop: &(dyn Fn() -> bool + Sync),
    allow_peer_close: bool,
) -> io::Result<()> {
    relay_until_revoked_with_cleanup(client, tunnel, deadline, deadline, stop, allow_peer_close)
}

fn relay_until_revoked_with_cleanup(
    client: TcpStream,
    tunnel: TcpStream,
    authorization_deadline: Instant,
    deadline: Instant,
    stop: &(dyn Fn() -> bool + Sync),
    allow_peer_close: bool,
) -> io::Result<()> {
    let client_pin = client.try_clone()?;
    let upstream_pin = tunnel.try_clone()?;
    let (finished, finished_relay) = std::sync::mpsc::channel::<()>();
    std::thread::scope(|scope| {
        let watcher = std::thread::Builder::new().spawn_scoped(scope, move || {
            loop {
                if stop() {
                    let shutdown = |stream: &TcpStream| match stream.shutdown(Shutdown::Both) {
                        Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(()),
                        result => result,
                    };
                    let client_result = shutdown(&client_pin);
                    let upstream_result = shutdown(&upstream_pin);
                    return client_result.and(upstream_result);
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::other("signed revocation not observed"));
                }
                if allow_peer_close {
                    if finished_relay
                        .recv_timeout(Duration::from_millis(10))
                        .is_ok()
                    {
                        return Ok(());
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        })?;
        let relayed = relay(client, tunnel, authorization_deadline);
        let _ = finished.send(());
        watcher
            .join()
            .map_err(|_| io::Error::other("revocation watcher failed"))??;
        relayed
    })
}

fn finish_expiring_relay(result: io::Result<()>, expires: Instant) -> io::Result<()> {
    if Instant::now() < expires {
        return Err(io::Error::other(
            "local tunnel ended before signed freshness expired",
        ));
    }
    match result {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            Ok(())
        }
        result => result,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn non_host_fixture_still_times_out_after_eight_seconds() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream = super::FixtureUpstream::prepare(super::Case::Match).unwrap();
        let started = std::time::Instant::now();
        assert!(
            super::serve_fixture(
                &listener,
                upstream,
                super::Case::Match,
                started + std::time::Duration::from_secs(30),
                None
            )
            .is_err()
        );
        assert!(started.elapsed() >= std::time::Duration::from_millis(7900));
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
    }

    #[test]
    fn cleanup_grace_does_not_relay_or_open_a_new_tunnel() {
        use std::io::{Read, Write};
        use std::net::{Ipv4Addr, TcpListener, TcpStream};
        use std::time::{Duration, Instant};
        let pair = || {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            (client, listener.accept().unwrap().0)
        };
        let (mut client, gateway) = pair();
        let (upstream, mut server) = pair();
        let expires = Instant::now() + Duration::from_millis(150);
        let cleanup = expires + Duration::from_secs(1);
        let worker = std::thread::spawn(move || {
            super::relay_until_revoked_with_cleanup(
                gateway,
                upstream,
                expires,
                cleanup,
                &|| Instant::now() >= expires,
                true,
            )
        });
        client.write_all(b"before").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut before = [0; 6];
        server.read_exact(&mut before).unwrap();
        assert_eq!(&before, b"before");
        std::thread::sleep(
            expires.saturating_duration_since(Instant::now()) + Duration::from_millis(40),
        );
        assert!(Instant::now() < cleanup);
        let _ = client.write_all(b"forbidden");
        match server.read(&mut before) {
            Ok(0) => {}
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            result => panic!("relay survived authorization expiry: {result:?}"),
        }
        assert!(Instant::now() < cleanup);
        let _ = worker.join().unwrap();
        let (mut new_client, mut new_gateway) = pair();
        let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        target.set_nonblocking(true).unwrap();
        new_client
            .write_all(b"CONNECT platform.claude.com:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        assert!(
            super::open_managed_tunnel(
                &mut new_gateway,
                target.local_addr().unwrap(),
                expires,
                &|| false
            )
            .is_err()
        );
        assert_eq!(
            target.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    use super::*;

    #[test]
    fn managed_gateway_aborts_partial_headers_before_dialing() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let gateway = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        upstream.set_nonblocking(true).unwrap();
        gateway.set_nonblocking(true).unwrap();
        let revoke = AtomicBool::new(false);
        let checks = std::sync::atomic::AtomicUsize::new(0);
        let deadline = Instant::now() + Duration::from_secs(3);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                serve_managed(&gateway, upstream.local_addr().unwrap(), deadline, &|| {
                    checks.fetch_add(1, Ordering::Release);
                    revoke.load(Ordering::Acquire)
                })
                .unwrap();
            });
            let mut client = TcpStream::connect(gateway.local_addr().unwrap()).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            client
                .write_all(b"CONNECT platform.claude.com:443 HTTP/1.1\r\nHost: ")
                .unwrap();
            let start = Instant::now();
            while checks.load(Ordering::Acquire) < 10 {
                assert!(start.elapsed() < Duration::from_secs(1));
                std::thread::sleep(Duration::from_millis(1));
            }
            revoke.store(true, Ordering::Release);
            let mut byte = [0; 1];
            match client.read(&mut byte) {
                Ok(0) => {}
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
                result => panic!("partial request survived stop: {result:?}"),
            }
            let _ = client.write_all(b"platform.claude.com:443\r\n\r\n");
            worker.join().unwrap();
            assert_eq!(
                upstream.accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        });
    }

    #[test]
    fn managed_gateway_rejects_wrong_authority_and_closes_live_tunnel_on_stop() {
        use std::sync::atomic::{AtomicBool, Ordering};

        const REQUEST: &[u8] =
            b"CONNECT platform.claude.com:443 HTTP/1.1\r\nHost: platform.claude.com:443\r\n\r\n";
        const ACCEPTED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        const DENIED: &[u8] = b"HTTP/1.1 403 Forbidden\r\n\r\n";
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let gateway = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        upstream.set_nonblocking(true).unwrap();
        gateway.set_nonblocking(true).unwrap();
        let stop = AtomicBool::new(false);
        let timeout = Duration::from_secs(2);
        let deadline = Instant::now() + timeout;
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                serve_managed(&gateway, upstream.local_addr().unwrap(), deadline, &|| {
                    stop.load(Ordering::Acquire)
                })
                .unwrap();
            });
            let connect = || {
                let client = TcpStream::connect(gateway.local_addr().unwrap()).unwrap();
                client.set_read_timeout(Some(timeout)).unwrap();
                client
            };
            let mut denied = connect();
            denied
                .write_all(b"CONNECT other.invalid:443 HTTP/1.0\r\n\r\n")
                .unwrap();
            let mut refusal = [0; DENIED.len()];
            denied.read_exact(&mut refusal).unwrap();
            assert_eq!(refusal, DENIED);
            assert_eq!(
                upstream.accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );

            let mut client = connect();
            client.write_all(REQUEST).unwrap();
            let mut accepted = [0; ACCEPTED.len()];
            client.read_exact(&mut accepted).unwrap();
            assert_eq!(accepted, ACCEPTED);
            let mut server = accept_before(&upstream, deadline).unwrap();
            server.set_read_timeout(Some(timeout)).unwrap();
            client.write_all(b"PING").unwrap();
            let mut data = [0; 4];
            server.read_exact(&mut data).unwrap();
            assert_eq!(&data, b"PING");
            stop.store(true, Ordering::Release);
            assert_eq!(client.read(&mut data).unwrap(), 0);
            assert_eq!(server.read(&mut data).unwrap(), 0);
            worker.join().unwrap();
        });
    }

    #[test]
    #[ignore = "requires openssl, Python 3, and an isolated Linux loopback"]
    fn fixed_connect_relays_tls_certificate_for_client_validation() {
        use std::io::{BufRead, BufReader};
        use std::net::Ipv4Addr;
        use std::process::{Command, Stdio};

        let dir = std::env::temp_dir().join(format!(
            "tempest-local-tls-{}",
            crate::private_io::random_hex().unwrap()
        ));
        std::fs::create_dir(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let result = (|| -> io::Result<()> {
            let generated = Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "ed25519",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=platform.claude.com",
                    "-addext",
                    "subjectAltName=DNS:platform.claude.com",
                    "-keyout",
                ])
                .arg(&key)
                .arg("-out")
                .arg(&cert)
                .output()?;
            assert!(generated.status.success(), "{:?}", generated.stderr);
            let mut server = Command::new("timeout")
                .args([
                    "20",
                    "python3",
                    "-u",
                    "-c",
                    r#"
import socket, ssl, sys
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
with socket.create_server(("127.0.0.1", 0)) as listener:
    listener.settimeout(8)
    print(listener.getsockname()[1])
    for expected in (True, False):
        client, _ = listener.accept()
        with client:
            client.settimeout(5)
            try:
                with context.wrap_socket(client, server_side=True) as tls:
                    if not expected:
                        raise AssertionError("client accepted a mismatched certificate")
                    tls.recv(1)
            except ssl.SSLError:
                if expected:
                    raise
"#,
                ])
                .arg(&cert)
                .arg(&key)
                .stdout(Stdio::piped())
                .spawn()?;
            let mut port = String::new();
            BufReader::new(server.stdout.take().unwrap()).read_line(&mut port)?;
            let upstream =
                SocketAddr::from((Ipv4Addr::LOCALHOST, port.trim().parse::<u16>().unwrap()));
            let gateway = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            let proxy = gateway.local_addr()?;
            let mut wrong = TcpStream::connect(proxy)?;
            wrong.write_all(b"CONNECT invalid.example:443 HTTP/1.1\r\n\r\n")?;
            let (mut socket, _) = gateway.accept()?;
            let timeout = || Instant::now() + Duration::from_secs(8);
            assert_eq!(
                open_tunnel(&mut socket, timeout(), upstream, |_, _| panic!(
                    "wrong authority dialed upstream"
                ))
                .unwrap_err()
                .kind(),
                io::ErrorKind::PermissionDenied
            );
            std::thread::scope(|threads| -> io::Result<()> {
                let worker = threads.spawn(|| -> io::Result<()> {
                    gateway.set_nonblocking(true)?;
                    for _ in 0..2 {
                        let deadline = timeout();
                        let mut client = accept_before(&gateway, deadline)?;
                        let peer = open_tunnel(&mut client, deadline, upstream, |addr, left| {
                            TcpStream::connect_timeout(&addr, left)
                        })?;
                        match relay(client, peer, deadline) {
                            Ok(()) => {}
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
                                ) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    Ok(())
                });
                for name in ["platform.claude.com", "wrong.example"] {
                    let output = Command::new("timeout")
                        .args([
                            "8",
                            "openssl",
                            "s_client",
                            "-proxy",
                            &proxy.to_string(),
                            "-connect",
                            AUTHORITY,
                            "-verify_hostname",
                            name,
                            "-verify_return_error",
                            "-showcerts",
                            "-CAfile",
                        ])
                        .arg(&cert)
                        .stdin(Stdio::null())
                        .output()?;
                    if name == "platform.claude.com" {
                        assert!(output.status.success(), "{:?}", output.stderr);
                        let remote = String::from_utf8_lossy(&output.stdout);
                        let expected = std::fs::read_to_string(&cert)?;
                        assert!(
                            remote.contains(expected.trim_end()),
                            "relayed certificate differs"
                        );
                    } else {
                        assert!(!output.status.success());
                        assert!(
                            String::from_utf8_lossy(&output.stderr).contains("hostname mismatch")
                        );
                    }
                }
                worker.join().unwrap()
            })?;
            assert!(server.wait()?.success());
            Ok(())
        })();
        std::fs::remove_dir_all(dir).unwrap();
        result.unwrap();
    }

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
        let dns_answers = [IpAddr::from([127, 0, 0, 2]), upstream_address.ip()];
        let selected = approved_peer(
            &dns_answers,
            &[upstream_address.ip()],
            upstream_address.port(),
        )
        .unwrap();
        assert_eq!(selected, upstream_address);
        assert!(
            approved_peer(
                &dns_answers[..1],
                &[upstream_address.ip()],
                upstream_address.port()
            )
            .is_err()
        );
        let deadline = || Instant::now() + Duration::from_secs(2);

        let mut rejected = TcpStream::connect(proxy_address).unwrap();
        rejected
            .write_all(b"CONNECT other.example:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        let (mut client, _) = proxy.accept().unwrap();
        assert_eq!(
            open_tunnel(&mut client, deadline(), selected, |_, _| panic!(
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
        let tunnel = open_tunnel(&mut client, deadline(), selected, |address, timeout| {
            TcpStream::connect_timeout(&address, timeout)
        })
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
            let responder = scope.spawn(|| {
                serve_fixture(
                    &gateway,
                    FixtureUpstream::prepare(Case::Match).unwrap(),
                    Case::Match,
                    Instant::now() + Duration::from_secs(8),
                    None,
                )
            });
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

    #[test]
    fn approved_route_requires_an_address_in_both_sets() {
        let approved = "192.0.2.10".parse().unwrap();
        let other = "192.0.2.11".parse().unwrap();
        assert_eq!(
            approved_peer(&[other, approved], &[approved], 443).unwrap(),
            SocketAddr::new(approved, 443)
        );
        for (resolved, approvers) in [
            (&[][..], &[approved][..]),
            (&[other][..], &[approved][..]),
            (&[approved][..], &[][..]),
        ] {
            assert_eq!(
                approved_peer(resolved, approvers, 443).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }
}
