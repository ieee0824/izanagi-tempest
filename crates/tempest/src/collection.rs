//! Per-file collection failures never imply absence of findings.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fmt, io};

#[derive(Debug)]
pub(crate) struct Failure(pub &'static str);
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Failure {}
pub(crate) fn error(reason: &'static str) -> io::Error {
    io::Error::other(Failure(reason))
}
pub(crate) fn reason(error: &io::Error) -> &'static str {
    error
        .get_ref()
        .and_then(|v| v.downcast_ref::<Failure>())
        .map_or("local_io", |v| v.0)
}
pub(crate) fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub(crate) fn chunk(
    value: &Value,
    id: &str,
    name: &str,
    offset: u64,
    total: u64,
    hash: &str,
) -> io::Result<Vec<u8>> {
    if value["export_id"] != id
        || value["file"] != name
        || value["offset"].as_u64() != Some(offset)
        || value["total_bytes"].as_u64() != Some(total)
        || value["sha256"] != hash
    {
        return Err(error("chunk_identity_mismatch"));
    }
    let text = value["data_hex"]
        .as_str()
        .ok_or_else(|| error("chunk_encoding_error"))?;
    if text.len() % 2 != 0 || text.len() > 65536 {
        return Err(error("chunk_encoding_error"));
    }
    let digit = |b: u8| -> io::Result<u8> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(error("chunk_encoding_error")),
        }
    };
    let data: Vec<u8> = text
        .as_bytes()
        .chunks_exact(2)
        .map(|b| Ok(digit(b[0])? * 16 + digit(b[1])?))
        .collect::<io::Result<_>>()?;
    if data.is_empty() {
        return Err(error("truncated_file"));
    }
    if value["next_offset"].as_u64() != Some(offset + data.len() as u64)
        || offset + data.len() as u64 > total
    {
        return Err(error("chunk_length_mismatch"));
    }
    if value["chunk_sha256"] != format!("{:x}", Sha256::digest(&data)) {
        return Err(error("chunk_hash_mismatch"));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> Value {
        json!({"export_id":"current-export","file":"api.jsonl","offset":0,"next_offset":3,"total_bytes":3,"sha256":format!("{:x}",Sha256::digest(b"abc")),"chunk_sha256":format!("{:x}",Sha256::digest(b"abc")),"data_hex":"616263"})
    }
    #[test]
    fn stale_export_file_or_offset_cannot_be_imported() {
        let value = fixture();
        let hash = value["sha256"].as_str().unwrap();
        assert_eq!(
            chunk(&value, "current-export", "api.jsonl", 0, 3, hash).unwrap(),
            b"abc"
        );
        for (id, name, offset, total) in [
            ("old-export", "api.jsonl", 0, 3),
            ("current-export", "capture.pcap", 0, 3),
            ("current-export", "api.jsonl", 1, 3),
            ("current-export", "api.jsonl", 0, 4),
        ] {
            assert_eq!(
                reason(&chunk(&value, id, name, offset, total, hash).unwrap_err()),
                "chunk_identity_mismatch"
            );
        }
    }
    #[test]
    fn altered_bytes_lengths_and_truncation_are_separate_failures() {
        for (field, value, expected) in [
            ("data_hex", json!("616264"), "chunk_hash_mismatch"),
            ("next_offset", json!(4), "chunk_length_mismatch"),
            ("data_hex", json!(""), "truncated_file"),
            ("data_hex", json!("61626z"), "chunk_encoding_error"),
        ] {
            let mut input = fixture();
            input[field] = value;
            assert_eq!(
                reason(
                    &chunk(
                        &input,
                        "current-export",
                        "api.jsonl",
                        0,
                        3,
                        input["sha256"].as_str().unwrap()
                    )
                    .unwrap_err()
                ),
                expected
            );
        }
    }
}
