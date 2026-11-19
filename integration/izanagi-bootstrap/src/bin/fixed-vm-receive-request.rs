#![cfg(target_os = "linux")]

use izanagi::protocol::{Message, load_shared_secret_from_file};
use izanagi::protocol_client::ProtocolClient;
use std::io::{self, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::path::Path;
use std::time::Duration;
use tokio::net::unix::pipe::{Receiver, Sender};

fn fixed_request(nonce: &str, phase: &str) -> Option<Vec<String>> {
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        || !matches!(phase, "control_before" | "allow_same_run" | "control_after")
    {
        return None;
    }
    Some(vec![
        "/usr/bin/python3".into(),
        "-I".into(),
        "-B".into(),
        "/workspace/readonly-check/fixed-vm-receive.py".into(),
        "request".into(),
        nonce.into(),
        phase.into(),
        format!("tempest-dummy-v1:{nonce}:{phase}"),
    ])
}

fn take_pipe(fd: libc::c_int, direction: libc::c_int) -> Option<OwnedFd> {
    // The launcher transfers ownership at exec. Check before creating the
    // runtime, which could otherwise reuse an absent descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != direction {
        return None;
    }
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } != 0
        || unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFIFO
        || unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0
    {
        return None;
    }
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

async fn request(
    response: OwnedFd,
    command: OwnedFd,
    secret: Vec<u8>,
    argv: Vec<String>,
) -> Option<Vec<u8>> {
    let mut client = ProtocolClient::new(
        Receiver::from_owned_fd(response).ok()?,
        Sender::from_owned_fd(command).ok()?,
        Some(secret),
    );
    client.handshake_and_wait_ready(None).await.ok()?;
    client
        .send_message(&Message::Exec {
            cmd: argv,
            env: Default::default(),
        })
        .await
        .ok()?;
    match client.recv_message().await.ok()? {
        Some(Message::ExecResult {
            exit_code: 0,
            stdout,
            stderr,
        }) if stderr.is_empty() => Some(stdout),
        _ => None,
    }
}

fn run() -> Option<()> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let [nonce, phase] = args.as_slice() else {
        return None;
    };
    let argv = fixed_request(nonce.to_str()?, phase.to_str()?)?;
    let command = take_pipe(3, libc::O_WRONLY)?;
    let response = take_pipe(4, libc::O_RDONLY)?;
    let secret_file = std::env::var_os("IZANAGI_SECRET_FILE")?;
    let secret = load_shared_secret_from_file(Path::new(&secret_file)).ok()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    let stdout = runtime.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(10),
            request(response, command, secret, argv),
        )
        .await
        .ok()?
    })?;
    io::stdout().lock().write_all(&stdout).ok()
}

fn main() -> std::process::ExitCode {
    if run().is_some() {
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("fixed VM receiver request failed");
        std::process::ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_bound_to_fixed_receiver_and_allowed_phases() {
        let nonce = "00112233445566778899aabbccddeeff";
        let argv = fixed_request(nonce, "allow_same_run").unwrap();
        assert_eq!(
            argv,
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                "/workspace/readonly-check/fixed-vm-receive.py",
                "request",
                nonce,
                "allow_same_run",
                "tempest-dummy-v1:00112233445566778899aabbccddeeff:allow_same_run",
            ]
        );
        assert!(fixed_request(nonce, "deny_other").is_none());
        assert!(fixed_request("../", "control_before").is_none());
    }
    #[tokio::test]
    async fn sends_one_fixed_request_only_after_authenticated_ready() {
        use tokio::net::unix::pipe::pipe;

        let argv = fixed_request("00112233445566778899aabbccddeeff", "allow_same_run").unwrap();
        let (command, agent_input) = pipe().unwrap();
        let (agent_output, response) = pipe().unwrap();
        let secret = b"fixed test dummy key".to_vec();
        let mut agent = ProtocolClient::new(agent_input, agent_output, Some(secret.clone()));
        let host = request(
            response.into_nonblocking_fd().unwrap(),
            command.into_nonblocking_fd().unwrap(),
            secret,
            argv.clone(),
        );
        let guest = async {
            assert!(matches!(
                agent.recv_message().await.unwrap(),
                Some(Message::Hello {
                    authenticated: true,
                    token: None
                })
            ));
            agent
                .send_message(&Message::Hello {
                    authenticated: true,
                    token: None,
                })
                .await
                .unwrap();
            agent.send_message(&Message::Ready).await.unwrap();
            assert!(matches!(
                agent.recv_message().await.unwrap(),
                Some(Message::Exec { cmd, env }) if cmd == argv && env.is_empty()
            ));
            agent
                .send_message(&Message::ExecResult {
                    exit_code: 0,
                    stdout: b"dummy acknowledgement\n".to_vec(),
                    stderr: Vec::new(),
                })
                .await
                .unwrap();
            assert!(agent.recv_message().await.unwrap().is_none());
        };
        let (stdout, ()) =
            tokio::time::timeout(Duration::from_secs(2), async { tokio::join!(host, guest) })
                .await
                .unwrap();
        assert_eq!(stdout.unwrap(), b"dummy acknowledgement\n");
    }
}
