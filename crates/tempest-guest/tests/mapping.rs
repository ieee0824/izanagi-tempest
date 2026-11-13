use hyper::{HeaderMap, Method, Uri};
use tempest_guest::mapping::{self, infer};

fn mapped(method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> mapping::Mapping {
    let mut hs = HeaderMap::new();
    for (name, value) in headers {
        hs.insert(
            hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    infer(
        &method.parse::<Method>().unwrap(),
        &path.parse::<Uri>().unwrap(),
        &hs,
        body,
        true,
    )
}
#[test]
fn credential_claim_header_precedence_and_presigned_query() {
    let mut headers = HeaderMap::new();
    let uri: Uri = "/?X-Amz-Credential=QUERY%2Fdate%2Fregion%2Fs3%2Faws4_request"
        .parse()
        .unwrap();
    assert_eq!(
        mapping::access_key(&headers, &uri).as_deref(),
        Some("QUERY")
    );
    headers.insert("authorization","AWS4-HMAC-SHA256 SignedHeaders=host, Credential=HEADER/date/r/s3/aws4_request, Signature=unused".parse().unwrap());
    assert_eq!(
        mapping::access_key(&headers, &uri).as_deref(),
        Some("HEADER")
    );
    headers.insert("authorization", "Bearer malformed".parse().unwrap());
    assert_eq!(mapping::access_key(&headers, &uri), None);
    headers.insert(
        "authorization",
        hyper::header::HeaderValue::from_bytes(&[0x80]).unwrap(),
    );
    assert_eq!(
        mapping::access_key(&headers, &uri).as_deref(),
        Some("QUERY")
    );
    for value in [
        "AWS4-HMAC-SHA256 Credential=/date/r/s3/aws4_request",
        "AWS4-HMAC-SHA256 Signature=x",
    ] {
        headers.insert("authorization", value.parse().unwrap());
        assert_eq!(mapping::access_key(&headers, &uri), None);
    }
    assert_eq!(
        mapping::access_key(&HeaderMap::new(), &"/".parse().unwrap()),
        None
    );
}
#[test]
fn s3_path_style_versions_and_strict_rejections() {
    for (method, path, action, resource) in [
        ("GET", "/", "s3:ListAllMyBuckets", "*"),
        ("HEAD", "/bucket", "s3:ListBucket", "arn:aws:s3:::bucket"),
        ("PUT", "/bucket", "s3:CreateBucket", "arn:aws:s3:::bucket"),
        (
            "DELETE",
            "/bucket",
            "s3:DeleteBucket",
            "arn:aws:s3:::bucket",
        ),
        (
            "GET",
            "/bucket/a%20b/nested",
            "s3:GetObject",
            "arn:aws:s3:::bucket/a b/nested",
        ),
        (
            "HEAD",
            "/bucket/a?versionId=v1",
            "s3:GetObjectVersion",
            "arn:aws:s3:::bucket/a",
        ),
        ("PUT", "/bucket/a", "s3:PutObject", "arn:aws:s3:::bucket/a"),
        (
            "DELETE",
            "/bucket/a?versionId=v1",
            "s3:DeleteObjectVersion",
            "arn:aws:s3:::bucket/a",
        ),
    ] {
        let m = mapped(method, path, &[], b"");
        assert_eq!(m.action.as_deref(), Some(action));
        assert_eq!(m.resource.as_deref(), Some(resource));
        assert!(m.diagnostic.is_none());
    }
    for (path, headers) in [
        ("/bucket?notification", vec![]),
        ("/_ls2/objects", vec![]),
        ("/bucket/a", vec![("x-amz-copy-source", "/other/a")]),
        ("/bucket/a", vec![("x-amz-tagging", "a=b")]),
        ("/bucket/%FF", vec![]),
    ] {
        let m = mapped("GET", path, &headers, b"");
        assert!(m.action.is_none() && m.diagnostic.is_some());
    }
}
#[test]
fn sqs_query_json_and_routing_ignores_misleading_signing_scope() {
    let form = [
        ("content-type", "application/x-www-form-urlencoded"),
        (
            "authorization",
            "AWS4-HMAC-SHA256 Credential=key/date/r/s3/aws4_request",
        ),
    ];
    for (body, action, resource) in [
        ("Action=ListQueues", "sqs:ListQueues", "*"),
        (
            "Action=CreateQueue&QueueName=jobs",
            "sqs:CreateQueue",
            "arn:aws:sqs:us-east-1:000000000000:jobs",
        ),
        (
            "Action=ReceiveMessage&QueueUrl=http%3A%2F%2F127.0.0.1%3A4566%2F000000000000%2Fjobs",
            "sqs:ReceiveMessage",
            "arn:aws:sqs:us-east-1:000000000000:jobs",
        ),
    ] {
        let m = mapped("POST", "/", &form, body.as_bytes());
        assert_eq!(m.service, "sqs");
        assert_eq!(m.action.as_deref(), Some(action));
        assert_eq!(m.resource.as_deref(), Some(resource));
    }
    let json = [
        ("content-type", "application/x-amz-json-1.0"),
        ("x-amz-target", "AmazonSQS.SendMessage"),
    ];
    let m = mapped(
        "POST",
        "/",
        &json,
        br#"{"QueueUrl":"http://127.0.0.1:4566/000000000000/jobs","MessageBody":"dummy"}"#,
    );
    assert_eq!(m.action.as_deref(), Some("sqs:SendMessage"));
    assert_eq!(
        m.resource.as_deref(),
        Some("arn:aws:sqs:us-east-1:000000000000:jobs")
    );
    let m = mapped(
        "POST",
        "/000000000000/a%20b",
        &[("x-amz-target", "AmazonSQS.ReceiveMessage")],
        b"{}",
    );
    // Pinned lqs queue_name does not percent-decode the path.
    assert_eq!(
        m.resource.as_deref(),
        Some("arn:aws:sqs:us-east-1:000000000000:a%20b")
    );
}
#[test]
fn ses_query_and_v2_share_the_catalog() {
    let m = mapped(
        "POST",
        "/",
        &[("content-type", "application/x-www-form-urlencoded")],
        b"Action=SendEmail&Source=sender%40example.invalid",
    );
    assert_eq!(m.action.as_deref(), Some("ses:SendEmail"));
    assert_eq!(
        m.resource.as_deref(),
        Some("arn:aws:ses:us-east-1:000000000000:identity/sender@example.invalid")
    );
    let m = mapped(
        "POST",
        "/v2/email/outbound-emails",
        &[],
        br#"{"FromEmailAddress":"sender@example.invalid"}"#,
    );
    assert_eq!(m.action.as_deref(), Some("ses:SendEmail"));
    let m = mapped(
        "GET",
        "/v2/email/identities/sender@example.invalid",
        &[],
        b"",
    );
    assert_eq!(m.action.as_deref(), Some("ses:GetEmailIdentity"));
    assert_eq!(m.resource.as_deref(), Some("*"));
    assert!(mapped("GET", "/_les/messages", &[], b"").action.is_none());
}
#[test]
fn bounded_or_incomplete_parameters_do_not_become_guesses() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    let m = infer(
        &Method::POST,
        &"/".parse().unwrap(),
        &headers,
        b"Action=SendEmail&Source=partial",
        false,
    );
    assert!(m.action.is_none() && m.diagnostic.is_some());
}
#[test]
fn xml_json_errors_keep_code_only() {
    assert_eq!(
        mapping::error_code(
            br#"<Error><Code>AccessDenied</Code><Message>private content</Message></Error>"#
        )
        .as_deref(),
        Some("AccessDenied")
    );
    assert_eq!(
        mapping::error_code(
            br#"<ns:Error xmlns:ns="x"><ns:Code>NotImplemented</ns:Code></ns:Error>"#
        )
        .as_deref(),
        Some("NotImplemented")
    );
    assert_eq!(
        mapping::error_code(br#"{"__type":"com.amazonaws.sqs#AccessDenied","message":"private"}"#)
            .as_deref(),
        Some("AccessDenied")
    );
    for body in [
        b"".as_slice(),
        b"not an error",
        br#"{"Message":"no code"}"#,
        b"<Error><Code>",
    ] {
        assert_eq!(mapping::error_code(body), None);
    }
}

#[test]
fn probe_does_not_turn_malformed_errors_or_unknown_credentials_into_denial() {
    use tempest_guest::seed::classify;
    use tempest_model::guest::ProbeOutcome::*;
    for (status, code, complete, known, expected) in [
        (200, None, true, true, Allow),
        (403, Some("AccessDenied"), true, true, Deny),
        (501, Some("NotImplemented"), true, true, Unsupported),
        (501, Some("NotImplemented"), true, false, Unsupported),
        (403, None, true, true, Error),
        (501, None, true, true, Error),
        (403, Some("AccessDenied"), false, true, Error),
        (403, Some("AccessDenied"), true, false, Error),
        (200, None, true, false, Error),
        (404, None, true, true, Error),
    ] {
        assert_eq!(classify(status, code, complete, known), expected);
    }
}
