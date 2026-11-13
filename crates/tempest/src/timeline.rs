//! Clock correction and conservative MCP interval correlation.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClockSample {
    pub group: String,
    pub sample: u64,
    pub host_before_ns: u64,
    pub host_after_ns: u64,
    pub guest_ns: u64,
    pub offset_ns: i64,
    pub rtt_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallInterval {
    pub call_id: u64,
    pub start_host_ns: u64,
    pub end_host_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Correlation {
    pub corrected_host_ns: Option<u64>,
    pub candidate_call_ids: Vec<u64>,
    pub background: bool,
    pub ambiguous: bool,
    pub diagnostic: Option<String>,
}

fn midpoint(sample: &ClockSample) -> u64 {
    sample.host_before_ns + (sample.host_after_ns - sample.host_before_ns) / 2
}

/// Convert a guest timestamp to host time by linearly interpolating offset
/// between the surrounding clock samples. Extrapolation and a single sample
/// are deliberately rejected: their uncertainty is not bounded by evidence.
pub fn correct_guest_time(samples: &[ClockSample], guest_ns: u64) -> Result<(u64, u64), String> {
    if samples.len() < 2 {
        return Err("at least two clock samples are required for interpolation".into());
    }
    let mut ordered: Vec<_> = samples.iter().collect();
    ordered.sort_by_key(|sample| sample.guest_ns);
    let pair = ordered
        .windows(2)
        .find(|pair| pair[0].guest_ns <= guest_ns && guest_ns <= pair[1].guest_ns)
        .ok_or_else(|| "event is outside the measured clock interval".to_owned())?;
    let left = pair[0];
    let right = pair[1];
    let span = u128::from(right.guest_ns - left.guest_ns);
    if span == 0 {
        return Err("clock samples have duplicate guest timestamps".into());
    }
    let position = u128::from(guest_ns - left.guest_ns);
    let left_host = i128::from(midpoint(left));
    let right_host = i128::from(midpoint(right));
    let delta = right_host - left_host;
    let corrected =
        left_host + delta * i128::try_from(position).unwrap() / i128::try_from(span).unwrap();
    let corrected =
        u64::try_from(corrected).map_err(|_| "corrected timestamp overflow".to_owned())?;
    Ok((corrected, left.rtt_ns.max(right.rtt_ns)))
}

pub fn correlate(samples: &[ClockSample], calls: &[CallInterval], guest_ns: u64) -> Correlation {
    let Ok((host_ns, margin)) = correct_guest_time(samples, guest_ns) else {
        return Correlation {
            corrected_host_ns: None,
            candidate_call_ids: vec![],
            background: true,
            ambiguous: false,
            diagnostic: Some("clock interpolation unavailable".into()),
        };
    };
    let candidates: Vec<_> = calls
        .iter()
        .filter(|call| {
            host_ns >= call.start_host_ns.saturating_sub(margin)
                && host_ns <= call.end_host_ns.saturating_add(margin)
        })
        .map(|call| call.call_id)
        .collect();
    Correlation {
        corrected_host_ns: Some(host_ns),
        background: candidates.is_empty(),
        ambiguous: candidates.len() > 1,
        candidate_call_ids: candidates,
        diagnostic: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(guest_ns: u64, host_ns: u64, rtt_ns: u64) -> ClockSample {
        ClockSample {
            group: "g".into(),
            sample: 0,
            host_before_ns: host_ns - rtt_ns / 2,
            host_after_ns: host_ns + rtt_ns / 2,
            guest_ns,
            offset_ns: 0,
            rtt_ns,
        }
    }
    #[test]
    fn interpolates_and_keeps_overlapping_candidates() {
        let samples = [sample(1_000, 2_000, 100), sample(2_000, 3_000, 100)];
        let calls = [
            CallInterval {
                call_id: 1,
                start_host_ns: 2_000,
                end_host_ns: 2_500,
            },
            CallInterval {
                call_id: 2,
                start_host_ns: 2_500,
                end_host_ns: 3_000,
            },
        ];
        let value = correlate(&samples, &calls, 1_500);
        assert_eq!(value.corrected_host_ns, Some(2_500));
        assert_eq!(value.candidate_call_ids, vec![1, 2]);
        assert!(value.ambiguous);
        assert!(!value.background);
    }
    #[test]
    fn one_sample_is_diagnostic_background() {
        let value = correlate(&[sample(1_000, 2_000, 100)], &[], 1_000);
        assert!(value.background);
        assert!(value.corrected_host_ns.is_none());
        assert!(value.diagnostic.is_some());
    }
    #[test]
    fn outside_every_call_is_background_but_keeps_time() {
        let samples = [sample(1_000, 2_000, 10), sample(2_000, 3_000, 10)];
        let value = correlate(&samples, &[], 1_500);
        assert!(value.background);
        assert_eq!(value.corrected_host_ns, Some(2_500));
    }
}
