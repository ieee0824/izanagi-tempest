//! Request estimates matched to pinned LWS routing; never internal IAM evidence.
use hyper::{HeaderMap, Method, Uri};
use serde_json::Value;
use std::collections::BTreeMap;
use tempest_model::capability::{self, ResourceKind, Support};

pub const INSPECTION_LIMIT: usize = 64 * 1024;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub service: String,
    pub action: Option<String>,
    pub resource: Option<String>,
    pub diagnostic: Option<String>,
}
pub fn access_key(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    if let Some(auth) = headers.get("authorization") {
        return auth
            .to_str()
            .ok()?
            .strip_prefix("AWS4-HMAC-SHA256 ")?
            .split(',')
            .find_map(|p| p.trim().strip_prefix("Credential="))?
            .split('/')
            .next()
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
    }
    let query: BTreeMap<String, String> =
        serde_urlencoded::from_str(uri.query().unwrap_or("")).ok()?;
    query
        .get("X-Amz-Credential")?
        .split('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}
fn unknown(service: &str, reason: &str) -> Mapping {
    Mapping {
        service: service.into(),
        action: None,
        resource: None,
        diagnostic: Some(reason.into()),
    }
}
pub fn infer(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    body_complete: bool,
) -> Mapping {
    let path = uri.path();
    let mut params: BTreeMap<String, String> =
        serde_urlencoded::from_str(uri.query().unwrap_or("")).unwrap_or_default();
    let form = headers
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h.starts_with("application/x-www-form-urlencoded"));
    if form {
        if !body_complete {
            return unknown(
                "unknown",
                "request parameters exceed inspection limit or are incomplete",
            );
        }
        if let Ok(values) = serde_urlencoded::from_bytes::<BTreeMap<String, String>>(body) {
            params.extend(values);
        }
    }
    let json = serde_json::from_slice::<Value>(body).ok();
    let target = headers
        .get("x-amz-target")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("AmazonSQS."));
    let action = params.get("Action").map(String::as_str);
    let service = if path.starts_with("/v2/email/") || path.starts_with("/_les/") {
        "ses"
    } else if target.is_some() {
        "sqs"
    } else if let Some(a) = action {
        if matches!(
            a,
            "CreateUser"
                | "ListUsers"
                | "CreateAccessKey"
                | "DeleteAccessKey"
                | "PutUserPolicy"
                | "DeleteUserPolicy"
        ) {
            "iam"
        } else if matches!(
            a,
            "VerifyEmailIdentity"
                | "VerifyDomainIdentity"
                | "ListIdentities"
                | "DeleteIdentity"
                | "SendEmail"
        ) {
            "ses"
        } else {
            "sqs"
        }
    } else {
        "s3"
    };
    let pair = match service {
        "ses" => {
            if path.starts_with("/_les/") {
                return unknown(service, "mail inspection is unavailable in strict mode");
            }
            let a = action.or_else(|| match (method.as_str(), path) {
                ("POST", "/v2/email/outbound-emails") => Some("SendEmail"),
                ("POST", "/v2/email/identities") => Some("CreateEmailIdentity"),
                ("GET", p) if p.starts_with("/v2/email/identities/") => Some("GetEmailIdentity"),
                ("DELETE", p) if p.starts_with("/v2/email/identities/") => {
                    Some("DeleteEmailIdentity")
                }
                _ => None,
            });
            let Some(a) = a else {
                return unknown(service, "unmapped SES operation");
            };
            let resource = if a == "SendEmail" {
                let sender = params
                    .get("Source")
                    .map(String::as_str)
                    .or_else(|| json.as_ref()?.get("FromEmailAddress")?.as_str());
                let Some(sender) = sender else {
                    return unknown(service, "missing sender or incomplete request metadata");
                };
                format!(
                    "arn:aws:ses:{}:{}:identity/{sender}",
                    capability::REGION,
                    capability::ACCOUNT
                )
            } else {
                "*".into()
            };
            (format!("ses:{a}"), resource)
        }
        "sqs" => {
            let Some(a) = target.or(action) else {
                return unknown(service, "missing SQS action");
            };
            let api = format!("sqs:{a}");
            let Some(cap) = capability::lookup(&api) else {
                return unknown(service, "unknown SQS action");
            };
            let get = |key: &str| {
                params
                    .get(key)
                    .map(String::as_str)
                    .or_else(|| json.as_ref()?.get(key)?.as_str())
            };
            let resource = if cap.resource == ResourceKind::Global {
                "*".into()
            } else {
                if !body_complete {
                    return unknown(
                        service,
                        "SQS request metadata incomplete or exceeds inspection limit",
                    );
                }
                let q = if matches!(a, "CreateQueue" | "GetQueueUrl") {
                    get("QueueName").map(str::to_owned)
                } else if let Some(url) = get("QueueUrl") {
                    queue_from_url(url)
                } else {
                    queue_from_path(path)
                };
                let Some(q) = q else {
                    return unknown(service, "missing or invalid SQS queue reference");
                };
                format!(
                    "arn:aws:sqs:{}:{}:{q}",
                    capability::REGION,
                    capability::ACCOUNT
                )
            };
            (api, resource)
        }
        "s3" => {
            if path.starts_with("/_ls2/")
                || headers.contains_key("x-amz-copy-source")
                || headers.contains_key("x-amz-tagging")
            {
                return unknown(
                    service,
                    "inspection, copy or compound writes are unavailable in strict mode",
                );
            }
            if params.keys().any(|k| {
                !k.starts_with("X-Amz-")
                    && !matches!(
                        k.as_str(),
                        "prefix"
                            | "delimiter"
                            | "max-keys"
                            | "marker"
                            | "continuation-token"
                            | "start-after"
                            | "encoding-type"
                            | "list-type"
                            | "versionId"
                            | "response-content-type"
                            | "response-content-disposition"
                            | "response-cache-control"
                            | "response-content-encoding"
                            | "response-content-language"
                            | "response-expires"
                            | "x-id"
                    )
            }) {
                return unknown(
                    service,
                    "S3 subresource operation is unavailable in strict mode",
                );
            }
            let Ok(decoded) =
                percent_encoding::percent_decode_str(path.trim_start_matches('/')).decode_utf8()
            else {
                return unknown(service, "invalid UTF-8 path");
            };
            let (bucket, key) = decoded.split_once('/').unwrap_or((&decoded, ""));
            let version = params.contains_key("versionId");
            let a = match (method.as_str(), bucket.is_empty(), key.is_empty()) {
                ("GET", true, _) => "ListAllMyBuckets",
                ("PUT", false, true) => "CreateBucket",
                ("DELETE", false, true) => "DeleteBucket",
                ("GET" | "HEAD", false, true) => "ListBucket",
                ("PUT", false, false) => "PutObject",
                ("GET" | "HEAD", false, false) => {
                    if version {
                        "GetObjectVersion"
                    } else {
                        "GetObject"
                    }
                }
                ("DELETE", false, false) => {
                    if version {
                        "DeleteObjectVersion"
                    } else {
                        "DeleteObject"
                    }
                }
                _ => return unknown(service, "unmapped S3 operation"),
            };
            let resource = if bucket.is_empty() {
                "*".into()
            } else if key.is_empty() {
                format!("arn:aws:s3:::{bucket}")
            } else {
                format!("arn:aws:s3:::{bucket}/{key}")
            };
            (format!("s3:{a}"), resource)
        }
        _ => {
            return unknown(
                service,
                "administrative operation outside recorder capability catalog",
            );
        }
    };
    match capability::lookup(&pair.0) {
        Some(cap) if !matches!(cap.support, Support::Unsupported(_)) => Mapping {
            service: service.into(),
            action: Some(pair.0),
            resource: Some(pair.1),
            diagnostic: None,
        },
        _ => unknown(
            service,
            "operation absent from pinned strict capability catalog",
        ),
    }
}
fn queue_from_url(url: &str) -> Option<String> {
    queue_from_path(url.split('?').next()?)
}
fn queue_from_path(path: &str) -> Option<String> {
    let name = path.trim_end_matches('/').rsplit('/').next()?;
    if name.is_empty() {
        return None;
    }
    Some(name.to_owned())
}

/// Inspect only a bounded error prefix, never store response text or Message.
pub fn error_code(body: &[u8]) -> Option<String> {
    if let Ok(json) = serde_json::from_slice::<Value>(body) {
        let code = json
            .get("Code")
            .or_else(|| json.get("code"))
            .or_else(|| json.get("__type"))?
            .as_str()?;
        return Some(code.rsplit('#').next()?.chars().take(256).collect());
    }
    let mut reader = quick_xml::Reader::from_reader(body);
    loop {
        match reader.read_event() {
            Ok(quick_xml::events::Event::Start(e)) if e.local_name().as_ref() == b"Code" => {
                let text = reader.read_text(e.name()).ok()?;
                return Some(text.chars().take(256).collect());
            }
            Ok(quick_xml::events::Event::Eof) | Err(_) => return None,
            _ => {}
        }
    }
}
