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

/// Source-derived expectations for the pinned Izanagi build at 16d0b559.
pub(super) fn expected_results() -> [serde_json::Value; 2] {
    use serde_json::json;
    [
        json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "izanagi", "version": "0.2.7"}
        }),
        json!({"tools": [
            {
                "name": "sandbox_status",
                "description": "Returns the current sandbox status.",
                "inputSchema": {
                    "type": "object", "properties": {},
                    "required": [], "additionalProperties": false
                }
            },
            {
                "name": "sandbox_exec",
                "description": "Executes a command inside the sandbox and returns its output.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "The command to execute."},
                        "args": {
                            "type": "array", "items": {"type": "string"},
                            "description": "Arguments to pass to the command."
                        }
                    },
                    "required": ["command"], "additionalProperties": false
                }
            },
            {
                "name": "sandbox_shell",
                "description": "Executes a shell command inside the sandbox via /bin/sh -c and returns its output.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "The shell command to execute."}
                    },
                    "required": ["command"], "additionalProperties": false
                }
            }
        ]}),
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub(super) enum ExchangeStage {
    ReleaseMissing = 125,
    ReleaseRead = 136,
    ReleaseEofWait = 137,
    ReleaseExtra = 138,
    ReleaseWrongByte = 139,
    ReleaseReadTimeout = 140,
    ReleaseEofTimeout = 141,
    ReleaseReadDenied = 142,
    ReleaseEofDenied = 143,
    PipeSetup = 130,
    InitializeSend = 131,
    InitializeResponse = 132,
    ToolListSend = 133,
    ToolListResponse = 134,
    StdoutEof = 135,
}

/// The caller supplies the reviewed results and releases this code only
/// after checking the isolated child's executable and pipe ownership.
pub(super) fn exchange(
    requests: OwnedFd,
    responses: OwnedFd,
    initialize_result: &serde_json::Value,
    catalog_result: &serde_json::Value,
    deadline: Instant,
) -> Result<(), (ExchangeStage, io::Error)> {
    let mut requests = File::from(requests);
    let mut responses = File::from(responses);
    for file in [&requests, &responses] {
        let fd = file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err((ExchangeStage::PipeSetup, io::Error::last_os_error()));
        }
    }

    send(&mut requests, INITIALIZE, deadline)
        .map_err(|error| (ExchangeStage::InitializeSend, error))?;
    receive(&mut responses, 1, initialize_result, deadline)
        .map_err(|error| (ExchangeStage::InitializeResponse, error))?;
    send(&mut requests, INITIALIZED, deadline)
        .map_err(|error| (ExchangeStage::ToolListSend, error))?;
    send(&mut requests, TOOLS_LIST, deadline)
        .map_err(|error| (ExchangeStage::ToolListSend, error))?;
    receive(&mut responses, 2, catalog_result, deadline)
        .map_err(|error| (ExchangeStage::ToolListResponse, error))?;
    drop(requests);

    expect_stdout_eof(&mut responses, deadline).map_err(|error| (ExchangeStage::StdoutEof, error))
}

fn expect_stdout_eof(responses: &mut File, deadline: Instant) -> io::Result<()> {
    if read(responses, &mut [0], deadline)? != 0 {
        return Err(invalid("unexpected bytes before stdout EOF"));
    }
    Ok(())
}

#[derive(Debug)]
pub(super) enum ControlError {
    Missing,
    WrongByte,
    Read(io::Error),
    EofWait(io::Error),
    Extra,
}

impl ControlError {
    pub(super) fn into_io(self) -> io::Error {
        match self {
            Self::Missing => invalid("missing fixture control byte"),
            Self::WrongByte => invalid("incorrect fixture control byte"),
            Self::Read(error) | Self::EofWait(error) => error,
            Self::Extra => invalid("unexpected data after fixture control byte"),
        }
    }

    pub(super) fn stage(&self) -> ExchangeStage {
        match self {
            Self::Missing => ExchangeStage::ReleaseMissing,
            Self::WrongByte => ExchangeStage::ReleaseWrongByte,
            Self::Read(error) if error.kind() == io::ErrorKind::TimedOut => {
                ExchangeStage::ReleaseReadTimeout
            }
            Self::EofWait(error) if error.kind() == io::ErrorKind::TimedOut => {
                ExchangeStage::ReleaseEofTimeout
            }
            Self::Read(error) if error.raw_os_error() == Some(libc::EPERM) => {
                ExchangeStage::ReleaseReadDenied
            }
            Self::EofWait(error) if error.raw_os_error() == Some(libc::EPERM) => {
                ExchangeStage::ReleaseEofDenied
            }
            Self::Read(_) => ExchangeStage::ReleaseRead,
            Self::EofWait(_) => ExchangeStage::ReleaseEofWait,
            Self::Extra => ExchangeStage::ReleaseExtra,
        }
    }
}

pub(super) fn expect_control_byte(
    reader: OwnedFd,
    expected: u8,
    deadline: Instant,
) -> Result<(), ControlError> {
    let mut reader = File::from(reader);
    let mut byte = [0];
    if read(&mut reader, &mut byte, deadline).map_err(ControlError::Read)? == 0 {
        return Err(ControlError::Missing);
    }
    if byte != [expected] {
        return Err(ControlError::WrongByte);
    }
    if read(&mut reader, &mut byte, deadline).map_err(ControlError::EofWait)? != 0 {
        return Err(ControlError::Extra);
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
    fn control_byte_requires_eof_before_the_deadline() {
        let (reader, writer) = crate::os::pipe().unwrap();
        let mut writer = File::from(writer);
        writer.write_all(b"R").unwrap();
        let error = expect_control_byte(reader, b'R', Instant::now() + Duration::from_millis(20))
            .unwrap_err();
        assert!(
            matches!(error, ControlError::EofWait(error) if error.kind() == io::ErrorKind::TimedOut)
        );
        drop(writer);

        for frame in [&b"R"[..], &b"RR"[..]] {
            let (reader, writer) = crate::os::pipe().unwrap();
            File::from(writer).write_all(frame).unwrap();
            let result = expect_control_byte(reader, b'R', Instant::now() + Duration::from_secs(2));
            if frame.len() == 1 {
                result.unwrap();
            } else {
                assert!(matches!(result, Err(ControlError::Extra)));
            }
        }
    }

    #[test]
    fn rejects_mcp_responses_with_invalid_framing_or_identity() {
        for frame in [
            &b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n"[..],
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"id\":1,\"result\":{}}\n",
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\nextra",
        ] {
            let (read_end, write_end) = crate::os::pipe().unwrap();
            File::from(write_end).write_all(frame).unwrap();
            let error = receive(
                &mut File::from(read_end),
                1,
                &serde_json::json!({}),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn rejects_an_oversize_unterminated_response() {
        let (read_end, write_end) = crate::os::pipe().unwrap();
        let writer = std::thread::spawn(move || {
            File::from(write_end)
                .write_all(&vec![b' '; MAX_FRAME_BYTES + 1])
                .unwrap();
        });
        let error = receive(
            &mut File::from(read_end),
            1,
            &serde_json::json!({}),
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap_err();
        writer.join().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "oversize MCP response");
    }

    #[test]
    fn elapsed_deadline_sends_no_requests_and_closes_the_request_pipe() {
        let (read_request, write_request) = crate::os::pipe().unwrap();
        let (read_response, _write_response) = crate::os::pipe().unwrap();
        let expected = serde_json::json!({});
        let error = exchange(
            write_request,
            read_response,
            &expected,
            &expected,
            Instant::now(),
        )
        .unwrap_err();
        assert_eq!(error.0, ExchangeStage::InitializeSend);
        assert_eq!(error.1.kind(), io::ErrorKind::TimedOut);
        assert_eq!(File::from(read_request).read(&mut [0]).unwrap(), 0);
    }

    #[test]
    fn open_stdout_writer_times_out_while_waiting_for_eof() {
        let (read_response, write_response) = crate::os::pipe().unwrap();
        let mut responses = File::from(read_response);
        let deadline = Instant::now() + Duration::from_millis(20);
        let error = expect_stdout_eof(&mut responses, deadline).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(Instant::now() >= deadline);
        drop(write_response);
    }

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
