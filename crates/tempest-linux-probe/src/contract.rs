//! Fixed role/barrier/audit contracts. No arbitrary diagnostic strings.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Role {
    A,
    B,
    Guard,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Scenario {
    Baseline,
    StateRun1,
    StateRun2,
    ForeignReady,
    FdFileA,
    FdFileB,
    FdDirectoryA,
    FdDirectoryB,
    FdSocketA,
    FdSocketB,
    ControlTruncation,
    UnexpectedControl,
    FrameOversize,
    FrameMalformed,
    LibraryLateWrite,
    LibraryHardlink,
    LibrarySymlink,
    LibraryReplacement,
    PidsLimit,
    TmpfsFull,
    DetachedGrandchild,
    ReportTimeout,
    ReportEof,
    CgroupKillNoop,
    MemoryOom,
    StdoutFlood,
    StderrFlood,
    PeerStdoutFlood,
    ContinuousStdout,
}

impl Scenario {
    pub(super) const INJECTIONS: [Self; 10] = [
        Self::FdFileA,
        Self::FdFileB,
        Self::FdDirectoryA,
        Self::FdDirectoryB,
        Self::FdSocketA,
        Self::FdSocketB,
        Self::ControlTruncation,
        Self::UnexpectedControl,
        Self::FrameOversize,
        Self::FrameMalformed,
    ];
    pub(super) const LIBRARY_FAULTS: [Self; 4] = [
        Self::LibraryLateWrite,
        Self::LibraryHardlink,
        Self::LibrarySymlink,
        Self::LibraryReplacement,
    ];
    pub(super) const RESOURCES: [Self; 4] = [
        Self::PidsLimit,
        Self::TmpfsFull,
        Self::DetachedGrandchild,
        Self::MemoryOom,
    ];
    pub(super) const LIFECYCLE: [Self; 6] = [
        Self::ReportTimeout,
        Self::ReportEof,
        Self::StdoutFlood,
        Self::StderrFlood,
        Self::PeerStdoutFlood,
        Self::ContinuousStdout,
    ];
    pub(super) fn output_flood(self) -> bool {
        matches!(
            self,
            Self::StdoutFlood | Self::StderrFlood | Self::PeerStdoutFlood | Self::ContinuousStdout
        )
    }
    pub(super) fn output_target(self) -> (Role, u8) {
        if self == Self::PeerStdoutFlood {
            (Role::B, 1)
        } else if self == Self::StderrFlood {
            (Role::A, 2)
        } else {
            (Role::A, 1)
        }
    }
    pub(super) fn lifecycle(self) -> bool {
        Self::LIFECYCLE.contains(&self)
    }
    pub(super) fn resource(self) -> bool {
        Self::RESOURCES.contains(&self) || self == Self::CgroupKillNoop
    }
    pub(super) fn library_fault(self) -> bool {
        Self::LIBRARY_FAULTS.contains(&self)
    }
    pub(super) fn injection(self) -> bool {
        Self::INJECTIONS.contains(&self)
    }
    pub(super) fn reverse(self) -> bool {
        matches!(self, Self::FdFileB | Self::FdDirectoryB | Self::FdSocketB)
    }
}

impl Role {
    pub(super) const ALL: [Self; 3] = [Self::A, Self::B, Self::Guard];

    pub(super) fn uid(self) -> u32 {
        match self {
            Self::A => 62001,
            Self::B => 62002,
            Self::Guard => 62003,
        }
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
            Self::Guard => "guard",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Identity {
    pub(super) pid: u32,
    pub(super) start_ticks: u64,
    pub(super) namespaces: [u64; 3],
    pub(super) code: (u64, u64),
}

#[derive(Clone, Debug)]
pub(super) struct State {
    pub(super) identity: Identity,
    pub(super) uid: [u32; 4],
    pub(super) gid: [u32; 4],
    pub(super) capabilities: [u64; 5],
    pub(super) groups: Vec<u32>,
    pub(super) no_new_privs: bool,
    pub(super) seccomp: u32,
    pub(super) cgroup_bound: bool,
    pub(super) descriptors_bound: bool,
    pub(super) alive: bool,
}

pub(super) fn ready(
    role: Role,
    expected: &Identity,
    state: &State,
    run_nonce: &[u8; 16],
    claimed_nonce: &[u8; 16],
) -> bool {
    state.identity == *expected
        && state.uid == [role.uid(); 4]
        && state.gid == [role.uid(); 4]
        && state.capabilities == [0; 5]
        && state.groups.is_empty()
        && state.no_new_privs
        && state.seccomp == 2
        && state.cgroup_bound
        && state.descriptors_bound
        && state.alive
        && claimed_nonce == run_nonce
}

pub(super) fn separate(states: &[State; 3], host: &[u64; 3]) -> bool {
    (0..3).all(|namespace| {
        let ids = states.each_ref().map(|s| s.identity.namespaces[namespace]);
        ids.iter().all(|id| *id != 0 && id != &host[namespace])
            && ids[0] != ids[1]
            && ids[0] != ids[2]
            && ids[1] != ids[2]
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Check {
    PrivateHomeReadable,
    HostHomeReadable,
    HostHomeDenied,
    StateMarkerCreated,
    StateMarkerObserved,
    PreviousStateAbsent,
    StateGenerationBound,
    StateCleanupComplete,
    PositiveCanary,
    PositiveIpc,
    HostPathsDenied,
    PeerCanaryDenied,
    PeerProcDenied,
    InheritedFdClosed,
    EnvironmentCleared,
    ShellAbsent,
    PrivilegeDenied,
    NamespaceDenied,
    LibraryReadonly,
    LibraryFaultRejected,
    SignalDenied,
    PtraceDenied,
    ProcessMemoryDenied,
    NetworkDenied,
    KvmAbsent,
    AncillaryClosed,
    GuardFraming,
    KernelIdentity,
    ForeignReadyRejected,
    NoForwardedPayload,
    ResourceLimits,
    PidsBounded,
    DetachedDescendant,
    TmpfsBounded,
    DescendantsKilled,
    CgroupEmpty,
    CgroupKillStopped,
    CgroupKillFailureDetected,
    MemoryMapped,
    MemoryBounded,
    ChildSignalObserved,
    OutputLimitDetected,
    OutputCaptureBounded,
    WatchdogHandoff,
    WatchdogLeaseRenewed,
    ResourcesRemoved,
    AuditBounded,
    ReportTimeoutDetected,
    ReportEofDetected,
    RolesReaped,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Observation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) scenario: Option<Scenario>,
    pub(super) check: Check,
    pub(super) role: Option<Role>,
    pub(super) passed: bool,
    pub(super) attempts: u64,
    pub(super) denials: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> State {
        State {
            identity: Identity {
                pid: 123,
                start_ticks: 42,
                namespaces: [10, 20, 30],
                code: (4, 5),
            },
            uid: [Role::A.uid(); 4],
            gid: [Role::A.uid(); 4],
            capabilities: [0; 5],
            groups: Vec::new(),
            no_new_privs: true,
            seccomp: 2,
            cgroup_bound: true,
            descriptors_bound: true,
            alive: true,
        }
    }

    #[test]
    fn ready_does_not_accept_reused_pid_changed_code_or_foreign_run() {
        let baseline = state();
        assert!(ready(
            Role::A,
            &baseline.identity,
            &baseline,
            &[1; 16],
            &[1; 16]
        ));
        for change in 0..6 {
            let mut changed = state();
            match change {
                0 => changed.identity.start_ticks += 1,
                1 => changed.identity.code.1 += 1,
                2 => changed.identity.namespaces[0] += 1,
                3 => changed.uid[2] = 0,
                4 => changed.cgroup_bound = false,
                5 => changed.alive = false,
                _ => unreachable!(),
            }
            assert!(!ready(
                Role::A,
                &baseline.identity,
                &changed,
                &[1; 16],
                &[1; 16]
            ));
        }
        assert!(!ready(
            Role::A,
            &baseline.identity,
            &baseline,
            &[1; 16],
            &[2; 16]
        ));
    }

    #[test]
    fn unconfined_kernel_state_cannot_unlock_the_barrier() {
        let baseline = state();
        for change in 0..5 {
            let mut changed = state();
            match change {
                0 => changed.capabilities[3] = 1,
                1 => changed.groups.push(27),
                2 => changed.no_new_privs = false,
                3 => changed.seccomp = 0,
                4 => changed.descriptors_bound = false,
                _ => unreachable!(),
            }
            assert!(!ready(
                Role::A,
                &baseline.identity,
                &changed,
                &[1; 16],
                &[1; 16]
            ));
        }
    }

    #[test]
    fn distinct_uid_alone_does_not_establish_namespace_separation() {
        let mut states = [state(), state(), state()];
        assert!(!separate(&states, &[1, 2, 3]));
        states[1].identity.namespaces = [11, 21, 31];
        states[2].identity.namespaces = [12, 22, 32];
        assert!(separate(&states, &[1, 2, 3]));
        states[2].identity.namespaces[2] = 3;
        assert!(!separate(&states, &[1, 2, 3]));
    }

    #[test]
    fn audit_has_no_channel_for_payload_path_environment_or_stderr() {
        let value = Observation {
            scenario: None,
            check: Check::InheritedFdClosed,
            role: Some(Role::B),
            passed: true,
            attempts: 1,
            denials: 1,
        };
        let value = serde_json::to_value(value).unwrap();
        let keys = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        assert_eq!(keys, ["attempts", "check", "denials", "passed", "role"]);
    }
}
