//! Parser for the pinned Izanagi text event and alert format. Unknown lines
//! remain available as raw evidence and carry a diagnostic.
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogRecord {
    pub timestamp: Option<String>,
    pub level: Option<String>,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub operation: Option<String>,
    pub result: Option<String>,
    pub alert: Option<String>,
    pub raw: String,
    pub diagnostic: Option<String>,
}

pub fn parse_line(line: &str) -> LogRecord {
    let raw = line.to_owned();
    let invalid = || LogRecord {
        timestamp: None,
        level: None,
        pid: None,
        process: None,
        operation: None,
        result: None,
        alert: None,
        raw: raw.clone(),
        diagnostic: Some("unrecognized Izanagi log format".into()),
    };
    let Some(after_open) = line.strip_prefix('[') else {
        return invalid();
    };
    let Some((timestamp, remainder)) = after_open.split_once("] ") else {
        return invalid();
    };
    if timestamp.len() != 23
        || timestamp.as_bytes().get(4) != Some(&b'-')
        || timestamp.as_bytes().get(19) != Some(&b'.')
    {
        return invalid();
    }
    let Some((level, remainder)) = remainder.split_once(" pid=") else {
        return invalid();
    };
    if !matches!(level, "INFO" | "WARN" | "ERROR" | "CRITICAL") {
        return invalid();
    }
    let Some((pid, remainder)) = remainder.split_once(' ') else {
        return invalid();
    };
    let Ok(pid) = pid.parse::<u32>() else {
        return invalid();
    };
    let Some((process, event)) = remainder.split_once(": ") else {
        return invalid();
    };
    if process.is_empty() {
        return invalid();
    }
    let (event, alert) = event
        .split_once(" | ")
        .map_or((event, None), |(event, alert)| {
            (event, Some(alert.to_owned()))
        });
    let Some((operation, result)) = event.split_once(" → ") else {
        return invalid();
    };
    if operation.is_empty() || result.is_empty() {
        return invalid();
    }
    LogRecord {
        timestamp: Some(timestamp.into()),
        level: Some(level.into()),
        pid: Some(pid),
        process: Some(process.into()),
        operation: Some(operation.into()),
        result: Some(result.into()),
        alert,
        raw,
        diagnostic: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_event_and_alert_lines() {
        let event = parse_line("[2026-11-12 23:20:48.324] INFO pid=593 sh: openat(0) → 3");
        assert_eq!(event.pid, Some(593));
        assert_eq!(event.operation.as_deref(), Some("openat(0)"));
        assert!(event.alert.is_none());
        let alert = parse_line(
            "[2026-11-12 23:20:48.812] WARN pid=584 tempest-guest-n: connect(127.0.0.1:4567) → err=115 | Network access to non-allowlisted host: 127.0.0.1:4567",
        );
        assert_eq!(alert.level.as_deref(), Some("WARN"));
        assert_eq!(
            alert.alert.as_deref(),
            Some("Network access to non-allowlisted host: 127.0.0.1:4567")
        );
    }
    #[test]
    fn format_changes_are_diagnostic_and_raw_is_preserved() {
        for line in [
            "2026-11-12 INFO pid=1 x: read() → 1",
            "[2026-11-12 23:20:48.812] NOTICE pid=1 x: read() → 1",
            "[2026-11-12 23:20:48.812] INFO process=x read()",
        ] {
            let parsed = parse_line(line);
            assert_eq!(parsed.raw, line);
            assert!(parsed.diagnostic.is_some());
        }
    }
}
