use super::{Fault, fd_identity, login_connect, wait_for_supervisor};
use std::{
    fs::File,
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    os::unix::net::UnixStream,
    process::{Command, Stdio},
};

const IP: &str = "/usr/sbin/ip";
const NFT: &str = "/usr/sbin/nft";
pub(super) const PROXY_URL: &str = "http://127.0.0.1:39271";
const PORTS: [u16; 4] = [39271, 39272, 39273, 39274];
const TABLE: &str = "tempest_local_auth";
const POLICY: &str = "
table inet tempest_local_auth {
    chain output {
        type filter hook output priority filter; policy accept;
        meta skuid 999 ip daddr 127.0.0.1 tcp dport 39271 counter accept
        meta skuid 999 meta l4proto tcp counter reject with tcp reset
        meta skuid 999 counter reject with icmpx type admin-prohibited
    }
}";

#[derive(Clone, Copy)]
pub(super) enum Case {
    Match,
    MissingNamespace,
    WrongNamespace,
    MissingPolicy,
    WrongPolicy,
}

impl Case {
    pub fn parse(case: &std::ffi::OsStr) -> Option<Self> {
        Some(match case.to_str()? {
            "match" => Self::Match,
            "missing-namespace" => Self::MissingNamespace,
            "wrong-namespace" => Self::WrongNamespace,
            "missing-policy" => Self::MissingPolicy,
            "wrong-policy" => Self::WrongPolicy,
            _ => return None,
        })
    }
}

fn command(path: &str) -> Command {
    let mut command = Command::new(path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn output(path: &str, args: &[&str]) -> io::Result<String> {
    let result = command(path).args(args).output()?;
    if !result.status.success() {
        return Err(io::Error::other("fixed network command failed"));
    }
    String::from_utf8(result.stdout).map_err(io::Error::other)
}

fn namespace() -> io::Result<(u64, u64)> {
    fd_identity(&File::open("/proc/thread-self/ns/net")?)
}

fn encode((dev, ino): (u64, u64)) -> [u8; 16] {
    let mut message = [0; 16];
    message[..8].copy_from_slice(&dev.to_ne_bytes());
    message[8..].copy_from_slice(&ino.to_ne_bytes());
    message
}

pub(super) fn verify_policy() -> io::Result<()> {
    let links = output(IP, &["-o", "link", "show"])?;
    if links.lines().count() != 1
        || links.split(':').nth(1).map(str::trim) != Some("lo")
        || !links.contains("LOOPBACK,UP")
        || !output(IP, &["-4", "route", "show"])?.trim().is_empty()
        || !output(IP, &["-6", "route", "show"])?.trim().is_empty()
    {
        return Err(io::Error::other(
            "fixed login network has non-loopback routing",
        ));
    }
    let actual = output(NFT, &["-s", "list", "ruleset"])?;
    let expected = POLICY.replace("icmpx type ", "icmpx ");
    if !actual.split_whitespace().eq(expected.split_whitespace()) {
        return Err(io::Error::other("fixed login policy missing or mismatched"));
    }
    Ok(())
}

pub(super) fn read_claim(control: &mut UnixStream, pinned: (u64, u64)) -> io::Result<()> {
    let mut claim = [0; 16];
    control.read_exact(&mut claim)?;
    if claim != encode(pinned) {
        return Err(io::Error::other(
            "fixed login namespace missing or mismatched",
        ));
    }
    Ok(())
}

pub(super) fn grant(control: &mut UnixStream, pinned: (u64, u64)) -> io::Result<()> {
    control.write_all(&encode(pinned))
}

pub(super) fn request(control: &mut UnixStream, case: Case) -> Result<(u64, u64), Fault> {
    let identity = namespace()?;
    let claimed = match case {
        Case::MissingNamespace => (0, 0),
        Case::WrongNamespace => (identity.0, identity.1 ^ 1),
        _ => identity,
    };
    control.write_all(b"C")?;
    control.write_all(&encode(claimed))?;
    let mut answer = [0; 17];
    control.read_exact(&mut answer)?;
    if answer[0] != b'G' || answer[1..] != encode(identity) {
        return Err(Fault::Identity);
    }
    Ok(identity)
}

pub(super) struct LocalPolicy {
    listeners: Vec<TcpListener>,
    installed: bool,
}

pub(super) struct Gateway(Option<libc::pid_t>);

impl Gateway {
    pub fn finish(mut self) -> io::Result<()> {
        let pid = self.0.unwrap();
        let status = wait_for_supervisor(pid)?;
        self.0 = None;
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(io::Error::other("fixed login gateway exchange failed"));
        }
        Ok(())
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let _ = wait_for_supervisor(pid);
        }
    }
}

impl LocalPolicy {
    pub fn setup(case: Case) -> io::Result<Self> {
        output(IP, &["link", "set", "lo", "up"])?;
        let mut listeners = Vec::new();
        for port in PORTS {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
            let control = TcpStream::connect((Ipv4Addr::LOCALHOST, port))?;
            let (accepted, _) = listener.accept()?;
            drop((control, accepted));
            listener.set_nonblocking(true)?;
            listeners.push(listener);
        }
        let installed = !matches!(case, Case::MissingPolicy);
        if installed {
            let policy = match case {
                Case::WrongPolicy => POLICY.replace("dport 39271", "dport 39272"),
                _ => POLICY.to_owned(),
            };
            let mut child = command(NFT)
                .args(["-f", "-"])
                .stdin(Stdio::piped())
                .spawn()?;
            let input = child.stdin.take().unwrap().write_all(policy.as_bytes());
            let status = child.wait()?;
            input?;
            if !status.success() {
                return Err(io::Error::other("fixed login policy install failed"));
            }
        }
        Ok(Self {
            listeners,
            installed,
        })
    }

    pub fn start_gateway(&self) -> io::Result<Gateway> {
        let supervisor = unsafe { libc::getpid() };
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            let guarded = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) }
                == 0
                && unsafe { libc::getppid() } == supervisor;
            let success = guarded && login_connect::serve_fixture(&self.listeners[0]).is_ok();
            unsafe { libc::_exit(i32::from(!success)) };
        }
        Ok(Gateway(Some(pid)))
    }

    pub fn finish(self, granted_and_completed: bool) -> io::Result<()> {
        let counters = if self.installed {
            output(NFT, &["-j", "list", "table", "inet", TABLE]).and_then(|report| {
                let report: serde_json::Value = serde_json::from_str(&report)?;
                let packets = report["nftables"]
                    .as_array()
                    .ok_or_else(|| io::Error::other("missing nftables report"))?
                    .iter()
                    .filter_map(|entry| entry["rule"]["expr"].as_array())
                    .flatten()
                    .filter_map(|expression| expression["counter"]["packets"].as_u64())
                    .collect::<Vec<_>>();
                Ok(packets)
            })
        } else {
            Ok(Vec::new())
        };
        let observed = self
            .listeners
            .iter()
            .map(|listener| {
                let mut count = 0;
                loop {
                    match listener.accept() {
                        Ok(_) => count += 1,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            return Ok(count);
                        }
                        Err(error) => return Err(error),
                    }
                }
            })
            .collect::<io::Result<Vec<_>>>();
        drop(self.listeners);
        if self.installed {
            output(NFT, &["delete", "table", "inet", TABLE])?;
        }
        let counters = counters?;
        let expected_counters = if granted_and_completed {
            matches!(counters.as_slice(), [allowed, 3, 0] if *allowed > 0)
        } else if self.installed {
            counters == [0, 0, 0]
        } else {
            counters.is_empty()
        };
        if !output(NFT, &["-s", "list", "ruleset"])?.trim().is_empty()
            || observed? != [0, 0, 0, 0]
            || !expected_counters
        {
            return Err(io::Error::other("fixed login traffic or cleanup mismatch"));
        }
        Ok(())
    }
}
