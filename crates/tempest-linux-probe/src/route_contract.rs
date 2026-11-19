//! Internal dummy route contract prototype. No launcher authority or OS backend.
use serde_json::Value;
use std::{
    collections::BTreeSet,
    os::fd::{AsRawFd, OwnedFd},
    time::{Duration, Instant},
};

// The reviewed build must be staged beneath a root-owned, non-writable path
// before Snapshot::trusted can consume it. The build output under /tmp is not
// an executable source for this fixture.
const IZANAGI_MCP_ARTIFACT: &str = "/usr/local/libexec/tempest/izanagi-mcp-fixture";
const IZANAGI_MCP_SHA256: &str = "088a5ca1fcf6f78501fabb329ff41a6318935e4971d86ef23e98626df5c3b0f8";

pub(super) struct FixedMcpArtifact {
    executable: super::os::Snapshot,
    libraries: Vec<super::os::Snapshot>,
}

impl FixedMcpArtifact {
    pub(super) fn open() -> Result<Self, super::os::Fault> {
        let snapshot = super::os::Snapshot::trusted(std::path::Path::new(IZANAGI_MCP_ARTIFACT))?;
        if snapshot.sha256 != IZANAGI_MCP_SHA256 {
            return Err(super::os::Fault::Identity);
        }
        Ok(Self {
            executable: snapshot,
            libraries: fixed_mcp_libraries()?,
        })
    }

    pub(super) fn executable_fd(&self) -> std::os::fd::RawFd {
        self.executable.fd()
    }

    pub(super) fn install_libraries(&self, root: &std::path::Path) -> Result<(), super::os::Fault> {
        super::capsule::install_libraries(root, &self.libraries, None)
    }

    pub(super) fn verify_stdio(
        &self,
        child: &super::identity::Process,
        stdin: &super::identity::Descriptor,
        stdout: &super::identity::Descriptor,
    ) -> Result<(), super::os::Fault> {
        verify_mcp_stdio(child, self.executable.identity()?, stdin, stdout)
    }
}

/// Verify the loader and recursively required libraries for the fixed ELF.
fn fixed_mcp_libraries() -> Result<Vec<super::os::Snapshot>, super::os::Fault> {
    use super::os::{Fault, Snapshot};
    use std::path::Path;

    // Require a pinned hash for every capsule destination at compile time.
    const EXPECTED: [&str; super::capsule::LIBRARIES.len()] = [
        "d93224d2b0dab4247598be683adca02f5cf00586f99c187579cd7e92058fb7cb",
        "5dcc4d25466e29ca390ed6fabb371c69b65dff6fa4e91c34561057a020d6994a",
        "755a371e86cc9f564ab54f66140747700fb0a103f698f659f2060f707897e09a",
        "5fc0940888e9d2e1a00e66d6b1a559c36364ee867683652e1074fa576952cc3f",
    ];
    super::capsule::LIBRARIES
        .into_iter()
        .zip(EXPECTED)
        .map(|((source, _), sha256)| {
            let snapshot = Snapshot::trusted(Path::new(source))?;
            if snapshot.sha256 != sha256 {
                return Err(Fault::Identity);
            }
            Ok(snapshot)
        })
        .collect()
}

/// A caller holds the original pidfd and keeps the worker frozen while
/// observing both standard streams. Release also requires the group-level
/// membership and pipe-holder checks.
fn verify_mcp_stdio(
    child: &super::identity::Process,
    executable: (u64, u64),
    stdin: &super::identity::Descriptor,
    stdout: &super::identity::Descriptor,
) -> Result<(), super::os::Fault> {
    use super::os::Fault;

    let identity = child.identity()?;
    if identity.code != executable
        || !stdin.matches(child.pid, libc::STDIN_FILENO)?
        || !stdout.matches(child.pid, libc::STDOUT_FILENO)?
        || child.identity()? != identity
    {
        return Err(Fault::Identity);
    }
    Ok(())
}

struct UniqueValue(serde_json::Value);

impl<'de> serde::Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(serde_json::Value::Number)
                    .map(UniqueValue)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(serde_json::Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(serde_json::Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(values.into()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut object: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((name, value)) = object.next_entry::<String, UniqueValue>()? {
                    if values.insert(name.clone(), value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(UniqueValue(values.into()))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Process {
    pub pid: u32,
    pub start_ticks: u64,
    pub cgroup_inode: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Binding {
    pub run_nonce: String,
    pub vm_nonce: String,
    pub session_sha256: String,
    pub executable_sha256: String,
    pub catalog_sha256: String,
    pub supervisor: Process,
}
fn hex(s: &str, length: usize) -> bool {
    s.len() == length
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Binding {
    fn valid(&self) -> bool {
        hex(&self.run_nonce, 32)
            && hex(&self.vm_nonce, 32)
            && [
                &self.session_sha256,
                &self.executable_sha256,
                &self.catalog_sha256,
            ]
            .iter()
            .all(|s| hex(s, 64))
            && self.supervisor.pid > 0
            && self.supervisor.start_ticks > 0
            && self.supervisor.cgroup_inode > 0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Rejection {
    Binding,
    Pipe,
    HoldersUnknown,
    Holders,
    Catalog,
    Schema,
    Frame,
    Id,
    Budget,
    Deadline,
    Response,
    OsIsolationUnavailable,
}

/// Owned ends stay with the parent until a future OS launcher performs the handoff.
/// No claim about peer credentials follows from the shared inode.
pub(super) struct ParentPipe {
    read: OwnedFd,
    write: OwnedFd,
    identity: (u64, u64),
}
impl ParentPipe {
    pub fn new(read: OwnedFd, write: OwnedFd) -> Result<Self, Rejection> {
        fn inspect(fd: &OwnedFd, access: i32) -> Result<(u64, u64), Rejection> {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
            if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0
                || st.st_mode & libc::S_IFMT != libc::S_IFIFO
                || flags < 0
                || flags & libc::O_PATH != 0
                || flags & libc::O_ACCMODE != access
            {
                return Err(Rejection::Pipe);
            }
            Ok((st.st_dev, st.st_ino))
        }
        let identity = inspect(&read, libc::O_RDONLY)?;
        if inspect(&write, libc::O_WRONLY)? != identity {
            return Err(Rejection::Pipe);
        }
        Ok(Self {
            read,
            write,
            identity,
        })
    }
    pub(super) fn into_ends(self) -> (OwnedFd, OwnedFd) {
        (self.read, self.write)
    }

    pub(super) fn identity(&self) -> (u64, u64) {
        self.identity
    }

    pub fn verify_parent_ends(&self) -> Result<(), Rejection> {
        let copy_read = self.read.try_clone().map_err(|_| Rejection::Pipe)?;
        let copy_write = self.write.try_clone().map_err(|_| Rejection::Pipe)?;
        let observed = Self::new(copy_read, copy_write)?;
        if observed.identity != self.identity {
            return Err(Rejection::Pipe);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Holder {
    pub process: Process,
    pub tid: u32,
    pub task_start_ticks: u64,
    pub fd: u32,
    pub writes: bool,
}
/// A future privileged scanner must supply complete host-side holders, including dup FDs.
/// B/G observations are separate and cannot stand in for this snapshot.
pub(super) fn verify_holders(
    expected: &[Holder],
    observed: Option<&[Holder]>,
) -> Result<(), Rejection> {
    let observed = observed.ok_or(Rejection::HoldersUnknown)?;
    let a: BTreeSet<_> = expected.iter().collect();
    let b: BTreeSet<_> = observed.iter().collect();
    if a.len() != expected.len()
        || b.len() != observed.len()
        || a != b
        || a.is_empty()
        || a.iter().any(|h| {
            h.process.pid == 0
                || h.process.start_ticks == 0
                || h.process.cgroup_inode == 0
                || h.tid == 0
                || h.task_start_ticks == 0
        })
    {
        return Err(Rejection::Holders);
    }
    Ok(())
}

/// Deliberately limited schema subset for reviewed dummy fixtures, not a generic
/// JSON Schema implementation. Production catalog compilation remains a gate.
#[derive(Clone, Debug)]
pub(super) enum Schema {
    String {
        max_chars: usize,
    },
    Strings {
        max_items: usize,
        max_item_chars: usize,
    },
    Object(Vec<(String, Schema)>),
}
impl Schema {
    fn valid_definition(&self, depth: usize) -> bool {
        if depth > 4 {
            return false;
        }
        match self {
            Self::String { max_chars } => (1..=4096).contains(max_chars),
            Self::Strings {
                max_items,
                max_item_chars,
            } => (1..=64).contains(max_items) && (1..=4096).contains(max_item_chars),
            Self::Object(fields) => {
                fields.len() <= 16
                    && fields.iter().map(|(k, _)| k).collect::<BTreeSet<_>>().len() == fields.len()
                    && fields.iter().all(|(k, v)| {
                        !k.is_empty() && k.len() <= 64 && v.valid_definition(depth + 1)
                    })
            }
        }
    }
    fn catalog_schema(&self) -> Value {
        use serde_json::json;
        match self {
            Self::String { max_chars } => json!({"type":"string","maxLength":max_chars}),
            Self::Strings {
                max_items,
                max_item_chars,
            } => {
                json!({"type":"array","maxItems":max_items,"items":{"type":"string","maxLength":max_item_chars}})
            }
            Self::Object(fields) => {
                let properties: serde_json::Map<String, Value> = fields
                    .iter()
                    .map(|(k, v)| (k.clone(), v.catalog_schema()))
                    .collect();
                json!({"type":"object","properties":properties,"required":fields.iter().map(|(k,_)|k).collect::<Vec<_>>(),"additionalProperties":false})
            }
        }
    }
    fn accepts(&self, value: &Value) -> bool {
        match self {
            Self::String { max_chars } => value
                .as_str()
                .is_some_and(|s| s.chars().count() <= *max_chars),
            Self::Strings {
                max_items,
                max_item_chars,
            } => value.as_array().is_some_and(|a| {
                a.len() <= *max_items
                    && a.iter().all(|v| {
                        v.as_str()
                            .is_some_and(|s| s.chars().count() <= *max_item_chars)
                    })
            }),
            Self::Object(fields) => value.as_object().is_some_and(|o| {
                o.len() == fields.len()
                    && fields
                        .iter()
                        .all(|(k, v)| o.get(k).is_some_and(|x| v.accepts(x)))
            }),
        }
    }
}
pub(super) struct Tool {
    pub name: String,
    pub catalog_entry: Value,
    pub schema: Schema,
}
#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub calls: u64,
    pub frame_bytes: usize,
    pub lifetime: Duration,
}
pub(super) struct Gate {
    binding: Binding,
    tools: Vec<Tool>,
    limits: Limits,
    deadline: Instant,
    used: u64,
    ids: BTreeSet<u64>,
    pending: Option<u64>,
    closed: bool,
}
impl Gate {
    pub fn new(
        binding: Binding,
        tools: Vec<Tool>,
        observed_catalog: &[Value],
        limits: Limits,
        now: Instant,
    ) -> Result<Self, Rejection> {
        if !binding.valid() {
            return Err(Rejection::Binding);
        }
        if tools.is_empty()
            || tools.len() > 16
            || tools.len() != observed_catalog.len()
            || tools.iter().map(|t| &t.name).collect::<BTreeSet<_>>().len() != tools.len()
            || tools.iter().zip(observed_catalog).any(|(t, o)| {
                !matches!(t.name.as_str(), "dummy_exec" | "dummy_http")
                    || t.catalog_entry != *o
                    || t.catalog_entry["name"] != t.name
                    || !t.schema.valid_definition(0)
                    || t.catalog_entry["inputSchema"] != t.schema.catalog_schema()
            })
        {
            return Err(Rejection::Catalog);
        }
        use sha2::{Digest, Sha256};
        let encoded = serde_json::to_vec(observed_catalog).map_err(|_| Rejection::Catalog)?;
        if encoded.len() > 65536
            || format!("{:x}", Sha256::digest(encoded)) != binding.catalog_sha256
        {
            return Err(Rejection::Catalog);
        }
        if !(1..=1000).contains(&limits.calls)
            || !(1..=65536).contains(&limits.frame_bytes)
            || limits.lifetime.is_zero()
            || limits.lifetime > Duration::from_secs(600)
        {
            return Err(Rejection::Budget);
        }
        let deadline = now
            .checked_add(limits.lifetime)
            .ok_or(Rejection::Deadline)?;
        Ok(Self {
            binding,
            tools,
            limits,
            deadline,
            used: 0,
            ids: BTreeSet::new(),
            pending: None,
            closed: false,
        })
    }
    fn current(&self, binding: &Binding, now: Instant) -> Result<(), Rejection> {
        if self.closed {
            return Err(Rejection::Response);
        }
        if &self.binding != binding {
            return Err(Rejection::Binding);
        }
        if now >= self.deadline {
            return Err(Rejection::Deadline);
        }
        Ok(())
    }
    pub fn admit(
        &mut self,
        binding: &Binding,
        frame: &[u8],
        now: Instant,
    ) -> Result<Value, Rejection> {
        let result = self.admit_checked(binding, frame, now);
        if result.is_err() {
            self.closed = true;
        }
        result
    }
    // Every rejected request closes this prototype route. Rejected requests
    // never dispatch, and an earlier pending response cannot reopen it.
    fn admit_checked(
        &mut self,
        binding: &Binding,
        frame: &[u8],
        now: Instant,
    ) -> Result<Value, Rejection> {
        self.current(binding, now)?;
        if frame.len() > self.limits.frame_bytes {
            return Err(Rejection::Frame);
        }
        let value = serde_json::from_slice::<UniqueValue>(frame)
            .map_err(|_| Rejection::Frame)?
            .0;
        let object = value.as_object().ok_or(Rejection::Frame)?;
        if object.len() != 4 || value["jsonrpc"] != "2.0" || value["method"] != "tools/call" {
            return Err(Rejection::Schema);
        }
        let id = value["id"]
            .as_u64()
            .filter(|v| *v > 0)
            .ok_or(Rejection::Id)?;
        if self.pending.is_some() || self.ids.contains(&id) {
            return Err(Rejection::Id);
        }
        let params = value["params"]
            .as_object()
            .filter(|p| p.len() == 2)
            .ok_or(Rejection::Schema)?;
        let tool = self
            .tools
            .iter()
            .find(|t| params.get("name") == Some(&Value::String(t.name.clone())))
            .ok_or(Rejection::Schema)?;
        if !params
            .get("arguments")
            .is_some_and(|v| tool.schema.accepts(v))
        {
            return Err(Rejection::Schema);
        }
        if self.used >= self.limits.calls {
            return Err(Rejection::Budget);
        }
        self.used += 1;
        self.ids.insert(id);
        self.pending = Some(id);
        Ok(value)
    }
    pub fn complete(
        &mut self,
        binding: &Binding,
        frame: &[u8],
        now: Instant,
    ) -> Result<(), Rejection> {
        let current = self.current(binding, now);
        self.closed = true;
        current?;
        if frame.len() > self.limits.frame_bytes {
            return Err(Rejection::Frame);
        }
        let v = serde_json::from_slice::<UniqueValue>(frame)
            .map_err(|_| Rejection::Frame)?
            .0;
        if v["jsonrpc"] != "2.0"
            || self.pending.is_none()
            || v["id"].as_u64() != self.pending
            || v.get("result").is_some() == v.get("error").is_some()
            || v.as_object().is_none_or(|o| o.len() != 3)
        {
            return Err(Rejection::Response);
        }
        if !v.get("result").is_some_and(Value::is_object) {
            let error = v
                .get("error")
                .and_then(Value::as_object)
                .ok_or(Rejection::Response)?;
            if error.get("code").and_then(Value::as_i64).is_none()
                || !error
                    .get("message")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.len() <= 4096)
                || error
                    .keys()
                    .any(|k| !matches!(k.as_str(), "code" | "message" | "data"))
            {
                return Err(Rejection::Response);
            }
        }
        self.pending = None;
        self.closed = false;
        Ok(())
    }
    /// Fixture connection point remains closed until an actual OS backend can
    /// constrain the trusted MCP child. Static argv/env and validators are not proof.
    pub fn connect_fixture(&self) -> Result<(), Rejection> {
        Err(Rejection::OsIsolationUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::fd::FromRawFd;

    fn process() -> Process {
        Process {
            pid: 42,
            start_ticks: 100,
            cgroup_inode: 7,
        }
    }
    fn fixture() -> (Binding, Vec<Tool>, Vec<Value>) {
        use sha2::{Digest, Sha256};
        let schema = Schema::Object(vec![
            ("command".into(), Schema::String { max_chars: 32 }),
            (
                "args".into(),
                Schema::Strings {
                    max_items: 4,
                    max_item_chars: 32,
                },
            ),
        ]);
        let entry = json!({"name":"dummy_exec","inputSchema":schema.catalog_schema()});
        let catalog = vec![entry.clone()];
        let binding = Binding {
            run_nonce: "1".repeat(32),
            vm_nonce: "2".repeat(32),
            session_sha256: "3".repeat(64),
            executable_sha256: "4".repeat(64),
            catalog_sha256: format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&catalog).unwrap())
            ),
            supervisor: process(),
        };
        (
            binding,
            vec![Tool {
                name: "dummy_exec".into(),
                catalog_entry: entry,
                schema,
            }],
            catalog,
        )
    }
    fn limits() -> Limits {
        Limits {
            calls: 2,
            frame_bytes: 1024,
            lifetime: Duration::from_secs(5),
        }
    }
    fn request(id: u64) -> Vec<u8> {
        serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"dummy_exec","arguments":{"command":"dummy","args":[]}}})).unwrap()
    }
    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }
    #[test]
    fn actual_pipe_owned_ends_are_checked_but_do_not_authorize_a_peer() {
        let (r, w) = pipe();
        let p = ParentPipe::new(r, w).unwrap();
        p.verify_parent_ends().unwrap();
        let (r, _) = pipe();
        let (_, w) = pipe();
        assert!(matches!(ParentPipe::new(r, w), Err(Rejection::Pipe)));
        let (r, w) = pipe();
        assert!(matches!(ParentPipe::new(w, r), Err(Rejection::Pipe)));
        let (binding, tools, catalog) = fixture();
        let gate = Gate::new(binding, tools, &catalog, limits(), Instant::now()).unwrap();
        assert_eq!(
            gate.connect_fixture(),
            Err(Rejection::OsIsolationUnavailable)
        );
    }
    #[test]
    fn stdio_observation_checks_exec_and_pipe_direction() {
        use crate::identity::{Descriptor, Process};
        use std::os::unix::fs::MetadataExt;
        use std::process::{Command, Stdio};

        let (request_read, request_write) = crate::os::pipe().unwrap();
        let (response_read, response_write) = crate::os::pipe().unwrap();
        let stdin = Descriptor::bind(request_read.as_raw_fd()).unwrap();
        let stdout = Descriptor::bind(response_write.as_raw_fd()).unwrap();
        let wrong_stdin = Descriptor::bind(request_write.as_raw_fd()).unwrap();
        let code = std::fs::metadata("/bin/cat").unwrap();
        let mut child = Command::new("/bin/cat")
            .env_clear()
            .stdin(Stdio::from(request_read))
            .stdout(Stdio::from(response_write))
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let observed = (|| {
            let process = Process::bind(child.id())?;
            let executable = (code.dev(), code.ino());
            Ok::<_, crate::os::Fault>([
                verify_mcp_stdio(&process, executable, &stdin, &stdout).is_ok(),
                verify_mcp_stdio(&process, (0, 0), &stdin, &stdout).is_err(),
                verify_mcp_stdio(&process, executable, &wrong_stdin, &stdout).is_err(),
            ])
        })();
        drop((request_write, response_read));
        assert!(child.wait().unwrap().success());
        assert_eq!(observed.unwrap(), [true; 3]);
    }

    #[test]
    fn path_only_alias_is_not_a_read_endpoint() {
        use std::os::unix::fs::OpenOptionsExt;

        let (read, write) = crate::os::pipe().unwrap();
        let path_only = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(format!("/proc/self/fd/{}", read.as_raw_fd()))
            .unwrap();
        assert!(matches!(
            ParentPipe::new(path_only.into(), write),
            Err(Rejection::Pipe)
        ));
    }

    #[test]
    fn duplicate_fd_unknown_scan_and_reused_pid_fail_holder_contract() {
        let expected = [Holder {
            process: process(),
            tid: process().pid,
            task_start_ticks: process().start_ticks,
            fd: 3,
            writes: true,
        }];
        verify_holders(&expected, Some(&expected)).unwrap();
        assert_eq!(
            verify_holders(&expected, None),
            Err(Rejection::HoldersUnknown)
        );
        let mut extra = expected.to_vec();
        extra.push(Holder {
            fd: 4,
            ..expected[0].clone()
        });
        assert_eq!(
            verify_holders(&expected, Some(&extra)),
            Err(Rejection::Holders)
        );
        extra[0].process.start_ticks += 1;
        assert_eq!(
            verify_holders(&expected, Some(&extra[..1])),
            Err(Rejection::Holders)
        );
        assert_eq!(
            verify_holders(&expected, Some(&[])),
            Err(Rejection::Holders)
        );
    }
    #[test]
    fn exact_catalog_schema_and_digest_are_all_required() {
        let (binding, tools, mut catalog) = fixture();
        catalog[0]["name"] = "other".into();
        assert!(matches!(
            Gate::new(binding, tools, &catalog, limits(), Instant::now()),
            Err(Rejection::Catalog)
        ));
        let (binding, mut tools, catalog) = fixture();
        tools[0].schema = Schema::Object(vec![]);
        assert!(matches!(
            Gate::new(binding, tools, &catalog, limits(), Instant::now()),
            Err(Rejection::Catalog)
        ));
        let (mut binding, tools, catalog) = fixture();
        binding.catalog_sha256 = "0".repeat(64);
        assert!(matches!(
            Gate::new(binding, tools, &catalog, limits(), Instant::now()),
            Err(Rejection::Catalog)
        ));
    }
    #[test]
    fn foreign_run_vm_session_binary_and_process_are_rejected_before_dispatch() {
        let (binding, _, _) = fixture();
        let now = Instant::now();
        for field in 0..6 {
            let (_, tools, catalog) = fixture();
            let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
            let mut foreign = binding.clone();
            match field {
                0 => foreign.run_nonce = "0".repeat(32),
                1 => foreign.vm_nonce = "0".repeat(32),
                2 => foreign.session_sha256 = "0".repeat(64),
                3 => foreign.executable_sha256 = "0".repeat(64),
                4 => foreign.supervisor.start_ticks += 1,
                _ => foreign.supervisor.cgroup_inode += 1,
            }
            assert_eq!(
                gate.admit(&foreign, &request(1), now),
                Err(Rejection::Binding)
            );
        }
    }
    #[test]
    fn arbitrary_upstream_management_tool_and_extra_arguments_are_rejected() {
        let (binding, tools, catalog) = fixture();
        let now = Instant::now();
        let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
        for method in ["sandbox_up", "exec", "initialize"] {
            let (_, tools, catalog) = fixture();
            let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
            let mut value: Value = serde_json::from_slice(&request(1)).unwrap();
            value["method"] = method.into();
            assert_eq!(
                gate.admit(&binding, &serde_json::to_vec(&value).unwrap(), now),
                Err(Rejection::Schema)
            );
        }
        for name in ["export", "claim", "other_run", "upstream_command"] {
            let (_, tools, catalog) = fixture();
            let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
            let mut value: Value = serde_json::from_slice(&request(1)).unwrap();
            value["params"]["name"] = name.into();
            assert_eq!(
                gate.admit(&binding, &serde_json::to_vec(&value).unwrap(), now),
                Err(Rejection::Schema)
            );
        }
        let mut value: Value = serde_json::from_slice(&request(1)).unwrap();
        value["params"]["arguments"]["host"] = "127.0.0.1".into();
        assert_eq!(
            gate.admit(&binding, &serde_json::to_vec(&value).unwrap(), now),
            Err(Rejection::Schema)
        );
        assert_eq!(gate.used, 0);
    }
    #[test]
    fn sequential_ids_pair_responses_and_budget_is_not_extended() {
        let (binding, tools, catalog) = fixture();
        let now = Instant::now();
        let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
        gate.admit(&binding, &request(1), now).unwrap();
        gate.complete(&binding, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#, now)
            .unwrap();
        gate.admit(&binding, &request(2), now).unwrap();
        gate.complete(&binding, br#"{"jsonrpc":"2.0","id":2,"result":{}}"#, now)
            .unwrap();
        assert_eq!(
            gate.admit(&binding, &request(3), now),
            Err(Rejection::Budget)
        );
        let (binding, tools, catalog) = fixture();
        let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
        assert_eq!(
            gate.admit(&binding, &request(4), now + Duration::from_secs(5)),
            Err(Rejection::Deadline)
        );
    }
    #[test]
    fn wrong_response_poisoning_prevents_fresh_id_or_late_recovery() {
        let (binding, tools, catalog) = fixture();
        let now = Instant::now();
        let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
        gate.admit(&binding, &request(1), now).unwrap();
        assert_eq!(
            gate.complete(&binding, br#"{"jsonrpc":"2.0","id":2,"result":{}}"#, now),
            Err(Rejection::Response)
        );
        assert_eq!(
            gate.admit(&binding, &request(2), now),
            Err(Rejection::Response)
        );
        assert_eq!(
            gate.complete(&binding, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#, now),
            Err(Rejection::Response)
        );
    }
    #[test]
    fn malformed_oversize_and_unbounded_configuration_are_refused() {
        let (binding, tools, catalog) = fixture();
        let now = Instant::now();
        let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
        assert_eq!(gate.admit(&binding, b"{", now), Err(Rejection::Frame));
        let (binding, tools, catalog) = fixture();
        let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
        assert_eq!(
            gate.admit(&binding, &vec![b' '; 1025], now),
            Err(Rejection::Frame)
        );
        let (binding, tools, catalog) = fixture();
        let mut invalid = limits();
        invalid.calls = u64::MAX;
        assert!(matches!(
            Gate::new(binding, tools, &catalog, invalid, now),
            Err(Rejection::Budget)
        ));
    }
    #[test]
    fn malformed_jsonrpc_error_closes_the_route_contract() {
        let (binding, tools, catalog) = fixture();
        let now = Instant::now();
        let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
        gate.admit(&binding, &request(1), now).unwrap();
        assert_eq!(
            gate.complete(&binding, br#"{"jsonrpc":"2.0","id":1,"error":3}"#, now),
            Err(Rejection::Response)
        );
        assert_eq!(
            gate.admit(&binding, &request(2), now),
            Err(Rejection::Response)
        );
    }

    #[test]
    fn rejected_requests_cannot_be_followed_by_valid_dispatch() {
        let now = Instant::now();
        for failure in 0..5 {
            let (binding, tools, catalog) = fixture();
            let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
            let result = match failure {
                0 => gate.admit(&binding, b"{", now),
                1 => {
                    let mut foreign = binding.clone();
                    foreign.vm_nonce = "0".repeat(32);
                    gate.admit(&foreign, &request(1), now)
                }
                2 => gate.admit(&binding, &request(1), now + Duration::from_secs(5)),
                3 => {
                    gate.admit(&binding, &request(1), now).unwrap();
                    gate.admit(&binding, &request(2), now)
                }
                _ => {
                    gate.admit(&binding, &request(1), now).unwrap();
                    gate.complete(&binding, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#, now)
                        .unwrap();
                    gate.admit(&binding, &request(1), now)
                }
            };
            assert!(result.is_err());
            assert_eq!(
                gate.admit(&binding, &request(3), now),
                Err(Rejection::Response)
            );
            assert_eq!(
                gate.complete(&binding, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#, now),
                Err(Rejection::Response)
            );
        }
    }

    #[test]
    fn duplicate_keys_at_any_depth_close_requests_and_responses() {
        let now = Instant::now();
        for frame in [
            br#"{"jsonrpc":"2.0","id":9,"id":1,"method":"tools/call","params":{"name":"dummy_exec","arguments":{"command":"dummy","args":[]}}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":9,"\u0069d":1,"method":"tools/call","params":{"name":"dummy_exec","arguments":{"command":"dummy","args":[]}}}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"other","method":"tools/call","params":{"name":"dummy_exec","arguments":{"command":"dummy","args":[]}}}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{},"params":{"name":"dummy_exec","arguments":{"command":"dummy","args":[]}}}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"dummy_exec","arguments":{"command":"other","command":"dummy","args":[]}}}"#,
        ] {
            let (binding, tools, catalog) = fixture();
            let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
            assert_eq!(gate.admit(&binding, frame, now), Err(Rejection::Frame));
            assert_eq!(gate.used, 0);
            assert_eq!(gate.admit(&binding, &request(2), now), Err(Rejection::Response));
        }
        for frame in [
            br#"{"jsonrpc":"2.0","id":2,"id":1,"result":{}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"a","text":"b"}]}}"#,
        ] {
            let (binding, tools, catalog) = fixture();
            let mut gate = Gate::new(binding.clone(), tools, &catalog, limits(), now).unwrap();
            gate.admit(&binding, &request(1), now).unwrap();
            assert_eq!(gate.complete(&binding, frame, now), Err(Rejection::Frame));
            assert_eq!(
                gate.admit(&binding, &request(2), now),
                Err(Rejection::Response)
            );
        }
    }

    #[test]
    fn schema_lengths_count_unicode_characters_while_frames_bound_bytes() {
        let schema = Schema::String { max_chars: 1 };
        assert_eq!(schema.catalog_schema()["maxLength"], 1);
        assert!(schema.accepts(&json!("あ")));
        assert!(!schema.accepts(&json!("あい")));
        let array = Schema::Strings {
            max_items: 1,
            max_item_chars: 1,
        };
        assert!(array.accepts(&json!(["あ"])));
        assert!(!array.accepts(&json!(["あい"])));
    }
}
