//! MCP tool admission and RPC drain accounting. Does not assert guest-process exit.
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(String);
impl RequestId {
    pub fn parse(value: &Value) -> Option<Self> {
        (value.is_string() || value.as_i64().is_some() || value.as_u64().is_some())
            .then(|| Self(value.to_string()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason {
    MaxCalls,
    Timeout,
    AgentFinished,
    Cancelled,
    UpstreamLost,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    Closed(CloseReason),
    DuplicateId,
}

#[derive(Debug, Clone, Serialize)]
pub struct DrainReceipt {
    closed_reason: CloseReason,
    admitted_calls: u64,
    completed_calls: u64,
    rejected_calls: u64,
    pending_calls: usize,
}

impl DrainReceipt {
    pub fn closed_reason(&self) -> CloseReason {
        self.closed_reason
    }
    pub fn admitted_calls(&self) -> u64 {
        self.admitted_calls
    }
    pub fn completed_calls(&self) -> u64 {
        self.completed_calls
    }
    pub fn rejected_calls(&self) -> u64 {
        self.rejected_calls
    }
    pub fn pending_calls(&self) -> usize {
        self.pending_calls
    }
}

#[derive(Debug)]
pub struct Admission {
    max_calls: u64,
    timeout: Duration,
    started: Instant,
    closed: Option<(CloseReason, Instant)>,
    admitted: u64,
    completed: u64,
    rejected: u64,
    pending: BTreeMap<String, u64>,
    uncertain: bool,
}
impl Admission {
    pub fn new(max_calls: u64, timeout: Duration, started: Instant) -> Self {
        Self {
            max_calls,
            timeout,
            started,
            closed: None,
            admitted: 0,
            completed: 0,
            rejected: 0,
            pending: BTreeMap::new(),
            uncertain: false,
        }
    }
    pub fn tick(&mut self, now: Instant) {
        if now.saturating_duration_since(self.started) >= self.timeout {
            self.close(CloseReason::Timeout, now);
        }
    }
    /// Only tools/call enters here; protocol metadata never spends tool budget.
    pub fn admit(&mut self, id: RequestId, now: Instant) -> Result<u64, Rejection> {
        self.tick(now);
        if self.closed.is_none() && self.admitted >= self.max_calls {
            self.close(CloseReason::MaxCalls, now);
        }
        if let Some((reason, _)) = self.closed {
            self.rejected = self.rejected.saturating_add(1);
            return Err(Rejection::Closed(reason));
        }
        if self.pending.contains_key(&id.0) {
            self.rejected = self.rejected.saturating_add(1);
            return Err(Rejection::DuplicateId);
        }
        // admitted < max_calls <= u64::MAX, hence no overflow.
        self.admitted += 1;
        self.pending.insert(id.0, self.admitted);
        Ok(self.admitted)
    }
    /// Remove only when the corresponding upstream response has been observed.
    pub fn complete(&mut self, id: &RequestId) -> Option<u64> {
        let sequence = self.pending.remove(&id.0)?;
        self.completed += 1;
        Some(sequence)
    }
    pub fn close(&mut self, reason: CloseReason, now: Instant) {
        if self.closed.is_none() {
            self.closed = Some((reason, now));
        }
    }
    pub fn upstream_lost(&mut self, now: Instant) {
        self.uncertain = true;
        self.close(CloseReason::UpstreamLost, now);
        // Never discard pending entries to manufacture a successful barrier.
    }
    pub fn enforce_drain_deadline(&mut self, now: Instant, limit: Duration) -> bool {
        if let Some((_, closed_at)) = self.closed
            && !self.pending.is_empty()
            && now.saturating_duration_since(closed_at) >= limit
        {
            self.uncertain = true;
        }
        !self.uncertain
    }
    pub fn admitted_calls(&self) -> u64 {
        self.admitted
    }
    pub fn completed_calls(&self) -> u64 {
        self.completed
    }
    pub fn rejected_calls(&self) -> u64 {
        self.rejected
    }
    pub fn is_uncertain(&self) -> bool {
        self.uncertain
    }
    pub fn pending_calls(&self) -> usize {
        self.pending.len()
    }
    pub fn closed_reason(&self) -> Option<CloseReason> {
        self.closed.map(|(reason, _)| reason)
    }
    /// A receipt proves only that admitted RPCs completed after admission closed.
    /// Guest cgroup quiescence must still be established independently.
    pub fn receipt(&self) -> Option<DrainReceipt> {
        let (closed_reason, _) = self.closed?;
        if self.uncertain || !self.pending.is_empty() {
            return None;
        }
        Some(DrainReceipt {
            closed_reason,
            admitted_calls: self.admitted,
            completed_calls: self.completed,
            rejected_calls: self.rejected,
            pending_calls: 0,
        })
    }
}
