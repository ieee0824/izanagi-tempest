//! Fixed stdio-only handshake for the isolated Izanagi fixture.
use super::UniqueValue;
use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::{AsRawFd, OwnedFd},
    time::Instant,
};

const MAX_FRAME_BYTES: usize = 64 * 1024;
const INITIALIZE: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"tempest-fixture\",\"version\":\"1\"}}}\n";
const INITIALIZED: &[u8] = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
const TOOLS_LIST: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n";

/// The caller supplies the reviewed results and releases this code only
/// after checking the isolated child's executable and pipe ownership.
pub(crate) fn exchange(
    requests: OwnedFd,
    responses: OwnedFd,
    initialize_result: &serde_json::Value,
    catalog_result: &serde_json::Value,
    deadline: Instant,
) -> io::Result<()> {
    let mut requests = File::from(requests);
    let mut responses = File::from(responses);
    for file in [&requests, &responses] {
        let fd = file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }

    send(&mut requests, INITIALIZE, deadline)?;
    receive(&mut responses, 1, initialize_result, deadline)?;
    send(&mut requests, INITIALIZED, deadline)?;
    send(&mut requests, TOOLS_LIST, deadline)?;
    receive(&mut responses, 2, catalog_result, deadline)?;
    drop(requests);

    if read(&mut responses, &mut [0], deadline)? != 0 {
        return Err(invalid("unexpected bytes before stdout EOF"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn ready(file: &File, events: i16, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: file.as_raw_fd(),
            events,
            revents: 0,
        };
        match unsafe { libc::poll(&mut descriptor, 1, millis) } {
            1 if Instant::now() < deadline => return Ok(()),
            0 | 1 => continue,
            _ => {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }
}

fn send(file: &mut File, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        ready(file, libc::POLLOUT, deadline)?;
        match file.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if retryable(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn read(file: &mut File, buffer: &mut [u8], deadline: Instant) -> io::Result<usize> {
    loop {
        ready(file, libc::POLLIN, deadline)?;
        match file.read(buffer) {
            Err(error) if retryable(&error) => continue,
            result if Instant::now() < deadline => return result,
            _ => return Err(io::ErrorKind::TimedOut.into()),
        }
    }
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    )
}

fn receive(
    file: &mut File,
    id: u64,
    result: &serde_json::Value,
    deadline: Instant,
) -> io::Result<()> {
    let mut frame = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let count = read(file, &mut buffer, deadline)?;
        if count == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if frame.len() + count > MAX_FRAME_BYTES {
            return Err(invalid("oversize MCP response"));
        }
        let bytes = &buffer[..count];
        frame.extend_from_slice(bytes);
        if let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') {
            if newline + 1 != count {
                return Err(invalid("extra bytes after MCP response"));
            }
            break;
        }
    }

    let UniqueValue(actual) =
        serde_json::from_slice(&frame).map_err(|_| invalid("invalid MCP response JSON"))?;
    if actual != serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result}) {
        return Err(invalid("unexpected MCP response"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        time::Duration,
    };

    #[test]
    fn exchanges_only_fixed_frames_and_closes_request_pipe_before_eof() {
        let (read_request, write_request) = crate::os::pipe().unwrap();
        let (read_response, write_response) = crate::os::pipe().unwrap();
        let initialize = serde_json::json!({"protocolVersion":"2024-11-05"});
        let catalog = serde_json::json!({"tools":[]});
        let init_frame = serde_json::json!({"jsonrpc":"2.0","id":1,"result":initialize});
        let list_frame = serde_json::json!({"jsonrpc":"2.0","id":2,"result":catalog});
        let server = std::thread::spawn(move || {
            let mut requests = BufReader::new(File::from(read_request));
            let mut responses = File::from(write_response);
            let mut line = Vec::new();
            for (expected, reply) in [
                (INITIALIZE, Some(init_frame)),
                (INITIALIZED, None),
                (TOOLS_LIST, Some(list_frame)),
            ] {
                line.clear();
                requests.read_until(b'\n', &mut line).unwrap();
                assert_eq!(line, expected);
                if let Some(reply) = reply {
                    writeln!(responses, "{reply}").unwrap();
                }
            }
            assert_eq!(requests.read(&mut [0]).unwrap(), 0);
        });
        let result = exchange(
            write_request,
            read_response,
            &initialize,
            &catalog,
            Instant::now() + Duration::from_secs(2),
        );
        server.join().unwrap();
        result.unwrap();
    }
}
