use serde_json::json;
use std::time::{Duration, Instant};
use tempest::admission::{Admission, CloseReason, Rejection, RequestId};
fn id(value: u64) -> RequestId {
    RequestId::parse(&json!(value)).unwrap()
}

#[test]
fn excess_call_cannot_enter_and_closing_does_not_drop_inflight_work() {
    let now = Instant::now();
    let mut gate = Admission::new(2, Duration::from_secs(10), now);
    assert_eq!(gate.admit(id(1), now), Ok(1));
    assert_eq!(gate.admit(id(2), now), Ok(2));
    assert_eq!(
        gate.admit(id(3), now),
        Err(Rejection::Closed(CloseReason::MaxCalls))
    );
    assert_eq!(gate.pending_calls(), 2);
    assert!(gate.receipt().is_none());
    assert_eq!(gate.complete(&id(2)), Some(2));
    assert!(gate.receipt().is_none());
    assert_eq!(gate.complete(&id(1)), Some(1));
    let receipt = gate.receipt().unwrap();
    assert_eq!(receipt.admitted_calls(), 2);
    assert_eq!(receipt.completed_calls(), 2);
    assert_eq!(receipt.rejected_calls(), 1);
}

#[test]
fn timeout_and_zero_budgets_reject_before_admission() {
    let now = Instant::now();
    for (max, timeout, reason) in [
        (0, Duration::from_secs(1), CloseReason::MaxCalls),
        (1, Duration::ZERO, CloseReason::Timeout),
    ] {
        let mut gate = Admission::new(max, timeout, now);
        assert_eq!(gate.admit(id(1), now), Err(Rejection::Closed(reason)));
        assert_eq!(gate.receipt().unwrap().admitted_calls(), 0);
    }
    let mut gate = Admission::new(4, Duration::from_secs(1), now);
    gate.admit(id(1), now).unwrap();
    gate.tick(now + Duration::from_secs(1));
    assert!(gate.receipt().is_none());
    assert_eq!(
        gate.admit(id(2), now + Duration::from_secs(1)),
        Err(Rejection::Closed(CloseReason::Timeout))
    );
    gate.complete(&id(1));
    assert!(gate.receipt().is_some());
}

#[test]
fn duplicate_ids_and_unobserved_responses_do_not_change_pending_count() {
    let now = Instant::now();
    let mut gate = Admission::new(4, Duration::from_secs(1), now);
    gate.admit(id(1), now).unwrap();
    assert_eq!(gate.admit(id(1), now), Err(Rejection::DuplicateId));
    assert_eq!(gate.complete(&id(9)), None);
    assert_eq!(gate.pending_calls(), 1);
    assert_ne!(id(1), RequestId::parse(&json!("1")).unwrap());
    assert!(RequestId::parse(&json!(null)).is_none());
    assert!(RequestId::parse(&json!(1.2)).is_none());
}

#[test]
fn connection_loss_or_drain_timeout_can_never_yield_a_verified_receipt() {
    let now = Instant::now();
    for lost in [false, true] {
        let mut gate = Admission::new(2, Duration::from_secs(9), now);
        gate.admit(id(1), now).unwrap();
        gate.close(CloseReason::Cancelled, now);
        if lost {
            gate.upstream_lost(now);
        } else {
            assert!(
                !gate.enforce_drain_deadline(now + Duration::from_secs(2), Duration::from_secs(1))
            );
        }
        assert!(gate.receipt().is_none());
        // A late reply cannot undo the already-recorded uncertain cleanup.
        gate.complete(&id(1));
        assert!(gate.receipt().is_none());
    }
}
