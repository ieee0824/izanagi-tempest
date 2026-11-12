use serde_json::{Value, json};
use tempest::scenario::load;

const SCENARIO: &str = include_str!("../../../scenarios/s3-overread-001.yaml");
fn base() -> Value {
    yaml_serde::from_str(SCENARIO).unwrap()
}
fn parse(
    value: &Value,
) -> Result<tempest::scenario::LoadedScenario, Vec<tempest_model::Diagnostic>> {
    load(yaml_serde::to_string(value).unwrap().as_bytes())
}
fn rejects(value: &Value, path: &str, reason: &str) {
    let errors = parse(value).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.path.contains(path) && e.reason.contains(reason)),
        "expected {path}: {reason}, got {errors:?}"
    );
}

#[test]
fn documented_scenario_hash_and_static_scope() {
    let loaded = load(SCENARIO.as_bytes()).unwrap();
    assert_eq!(loaded.raw, SCENARIO.as_bytes());
    assert_eq!(
        loaded.sha256,
        "7c2cc8dacc784c9f2dc079f7ac61f7d2983617fea1c8757b75f059fa30d8fb69"
    );
    assert_eq!(loaded.sha256, load(SCENARIO.as_bytes()).unwrap().sha256);
    assert_ne!(
        loaded.sha256,
        load(format!("{SCENARIO}\n").as_bytes()).unwrap().sha256
    );
    let valid = loaded.validated;
    assert!(valid.finding_present() && valid.retest_present());
    assert!(!valid.deviation_semantics_unchecked());
    assert_eq!(
        valid.scenario().setup.users[0].policy.statement.0[0]
            .resource
            .0[0],
        "arn:aws:s3:::*-data/*"
    );
    assert_eq!(valid.scenario().budget.max_calls, 50);
    assert_eq!(valid.scenario().budget.timeout.0.as_secs(), 900);
    // This allow evidence deliberately differs from the deny baseline.
    assert_ne!(
        valid.scenario().expect[1].result,
        valid
            .scenario()
            .expected_finding
            .as_ref()
            .unwrap()
            .evidence
            .result
    );
}

#[test]
fn measured_yaml_regressions_reach_production_semantics() {
    let cases: Vec<Value> =
        serde_json::from_str(include_str!("fixtures/yaml-regressions.json")).unwrap();
    assert_eq!(cases.len(), 39);
    for case in cases {
        let result = load(case["yaml"].as_str().unwrap().as_bytes());
        if let Some(reason) = case["error_contains"].as_str() {
            let errors = result.expect_err(case["name"].as_str().unwrap());
            assert!(
                errors.iter().any(|e| e.to_string().contains(reason)),
                "{}: {errors:?}",
                case["name"]
            );
        } else {
            result.unwrap_or_else(|errors| panic!("{}: {errors:?}", case["name"]));
        }
    }
}

#[test]
fn optional_parents_defaults_and_opaque_deviation() {
    for finding in [false, true] {
        for retest in [false, true] {
            let mut value = base();
            if !finding {
                value.as_object_mut().unwrap().remove("expected_finding");
            }
            if !retest {
                value.as_object_mut().unwrap().remove("retest");
            }
            value["deviation"] = json!({"allow":[{"future_rule":[1,"x"]}],"deny":["opaque"]});
            let loaded = parse(&value).unwrap();
            let v = loaded.validated;
            assert_eq!(v.finding_present(), finding);
            assert_eq!(v.retest_present(), retest);
            assert!(v.deviation_semantics_unchecked());
            assert_eq!(
                v.scenario().deviation.allow[0],
                value["deviation"]["allow"][0]
            );
        }
    }
    for budget in [json!({}), json!({"max_calls":0}), json!({"timeout":"2h"})] {
        let mut v = base();
        v["budget"] = budget.clone();
        let l = parse(&v).unwrap();
        let b = &l.validated.scenario().budget;
        assert_eq!(b.max_calls, budget["max_calls"].as_u64().unwrap_or(50));
        assert_eq!(
            b.timeout.0.as_secs(),
            if budget.get("timeout").is_some() {
                7200
            } else {
                900
            }
        );
    }
}

#[test]
fn duration_type_units_and_overflow() {
    for timeout in ["0ms", "1s", "15m", "2h"] {
        let mut v = base();
        v["budget"] = json!({"timeout":timeout});
        parse(&v).unwrap();
    }
    for timeout in [
        json!(null),
        json!(10),
        json!(""),
        json!("-1s"),
        json!("1.5m"),
        json!("1d"),
        json!("18446744073709551615h"),
    ] {
        let mut v = base();
        v["budget"] = json!({"timeout":timeout});
        rejects(&v, "budget.timeout", "");
    }
}

#[test]
fn rejects_unsupported_policy_elements_in_setup_and_retest() {
    for pointer in ["/setup/users/0/policy", "/retest/policy"] {
        for field in [
            "Condition",
            "Principal",
            "NotAction",
            "NotResource",
            "NotPrincipal",
        ] {
            let mut v = base();
            v.pointer_mut(pointer).unwrap()["Statement"][0][field] = json!({});
            rejects(
                &v,
                if pointer.starts_with("/setup") {
                    "setup.users[0].policy"
                } else {
                    "retest.policy"
                },
                field,
            );
        }
        for field in ["Action", "Resource"] {
            let mut v = base();
            v.pointer_mut(pointer).unwrap()["Statement"][0][field] = json!(["${aws:username}"]);
            rejects(
                &v,
                if pointer.starts_with("/setup") {
                    "setup.users[0].policy"
                } else {
                    "retest.policy"
                },
                "policy variables",
            );
        }
    }
}

#[test]
fn lws_policy_single_array_optional_fields_and_patterns() {
    let mut v = base();
    v["setup"]["users"][0]["policy"] =
        json!({"Statement":{"Sid":null,"Effect":"Allow","Action":"s3:*","Resource":"*"}});
    parse(&v).unwrap();
    for (field, value, reason) in [
        ("Effect", json!("Permit"), "Allow or Deny"),
        ("Action", json!([]), "empty pattern"),
        ("Resource", json!(""), "empty patterns"),
    ] {
        let mut bad = v.clone();
        bad["setup"]["users"][0]["policy"]["Statement"][field] = value;
        rejects(&bad, "policy.Statement", reason);
    }
    v["retest"]["policy"]["Version"] = json!("future");
    rejects(&v, "retest.policy.Version", "unsupported policy version");
}

#[test]
fn same_api_and_reference_validation_for_all_three_sites() {
    for pointer in [
        "/expect/0",
        "/expected_finding/evidence",
        "/retest/expect/0",
    ] {
        for (api, resource, reason) in [
            (
                "s3:Unknown",
                "arn:aws:s3:::public-data/readme.txt",
                "unknown API",
            ),
            (
                "s3:CopyObject",
                "arn:aws:s3:::public-data/readme.txt",
                "strict unsupported",
            ),
            (
                "s3:GetObjectVersion",
                "arn:aws:s3:::public-data/readme.txt",
                "input representation error",
            ),
            (
                "s3:GetObject",
                "arn:aws:s3:::public-data-other/readme.txt",
                "bucket is not defined",
            ),
            (
                "s3:GetObject",
                "arn:aws:s3:::public-data/missing",
                "object is not defined",
            ),
            ("s3:GetObject", "arn:aws:s3:::public-data", "resource kind"),
            (
                "s3:ListBucket",
                "arn:aws:s3:::public-data/readme.txt",
                "resource kind",
            ),
            ("s3:GetObject", "arn:aws:s3:::public-data/*", "concrete ARN"),
            (
                "s3:GetObject",
                "arn:aws:s3:us-east-1:000000000000:public-data/readme.txt",
                "empty region/account",
            ),
            (
                "sqs:GetQueueUrl",
                "arn:aws:sqs:us-east-1:000000000000:missing",
                "queue is not defined",
            ),
        ] {
            let mut v = base();
            let c = v.pointer_mut(pointer).unwrap();
            c["api"] = json!(api);
            c["resource"] = json!(resource);
            let path = if pointer == "/expect/0" {
                "expect[0]"
            } else if pointer == "/retest/expect/0" {
                "retest.expect[0]"
            } else {
                "expected_finding.evidence"
            };
            rejects(&v, path, reason);
        }
    }
}

#[test]
fn sqs_ses_global_and_queue_resources() {
    let mut v = base();
    v["setup"]["queues"] = json!([{"name":"jobs"}]);
    for (api, resource) in [
        ("sqs:GetQueueUrl", "arn:aws:sqs:us-east-1:000000000000:jobs"),
        ("sqs:ListQueues", "*"),
        ("ses:ListIdentities", "*"),
        ("s3:ListAllMyBuckets", "*"),
    ] {
        v["expect"][0] = json!({"api":api,"resource":resource,"result":"allow"});
        parse(&v).unwrap();
    }
    v["expect"][0] = json!({"api":"sqs:ListQueues","resource":"arn:aws:sqs:us-east-1:000000000000:jobs","result":"allow"});
    rejects(&v, "expect[0].resource", "global resource");
    v["expect"][0] = json!({"api":"sqs:GetQueueUrl","resource":"arn:aws:sqs:us-east-1:111111111111:jobs","result":"deny"});
    rejects(&v, "expect[0].resource", "account");
    v["expect"][0] = json!({"api":"ses:SendEmail","resource":"arn:aws:ses:us-east-1:000000000000:identity/test@example.invalid","result":"allow"});
    rejects(&v, "expect[0].api", "input representation error");
}

#[test]
fn retest_user_inference_and_multiuser_static_boundary() {
    let mut v = base();
    v["retest"].as_object_mut().unwrap().remove("user");
    assert_eq!(
        parse(&v)
            .unwrap()
            .validated
            .scenario()
            .retest
            .as_ref()
            .unwrap()
            .user
            .as_deref(),
        Some("worker")
    );
    let mut user = v["setup"]["users"][0].clone();
    user["name"] = json!("other");
    v["setup"]["users"].as_array_mut().unwrap().push(user);
    rejects(&v, "retest.user", "explicit user");
    v["retest"]["user"] = json!("other");
    parse(&v).unwrap();
    v["retest"]["user"] = json!("missing");
    rejects(&v, "retest.user", "unknown setup user");
    v.as_object_mut().unwrap().remove("retest");
    parse(&v).unwrap();
}

#[test]
fn setup_duplicates_and_finding_result() {
    for pointer in ["/setup/users", "/setup/buckets", "/setup/buckets/0/objects"] {
        let mut v = base();
        let a = v.pointer_mut(pointer).unwrap().as_array_mut().unwrap();
        a.push(a[0].clone());
        rejects(&v, "setup.", "duplicate");
    }
    let mut v = base();
    v["setup"]["queues"] = json!([{"name":"q"},{"name":"q"}]);
    rejects(&v, "setup.queues[1].name", "duplicate");
    let mut v = base();
    v["expected_finding"]["evidence"]["result"] = json!("deny");
    rejects(&v, "expected_finding.evidence.result", "must be allow");
}

#[test]
fn unadopted_request_extensions_remain_explicit_representation_errors() {
    use tempest_model::capability::{ResourceKind, Support, lookup};
    let excluded = [
        "s3:GetObjectVersion",
        "s3:DeleteObjectVersion",
        "sqs:SendMessage",
        "sqs:DeleteMessage",
        "sqs:ChangeMessageVisibility",
        "sqs:SetQueueAttributes",
        "sqs:TagQueue",
        "sqs:UntagQueue",
        "sqs:AddPermission",
        "sqs:RemovePermission",
        "sqs:SendMessageBatch",
        "sqs:DeleteMessageBatch",
        "sqs:ChangeMessageVisibilityBatch",
        "ses:SendEmail",
        "ses:VerifyEmailIdentity",
        "ses:VerifyDomainIdentity",
        "ses:DeleteIdentity",
        "ses:CreateEmailIdentity",
        "ses:GetEmailIdentity",
        "ses:DeleteEmailIdentity",
    ];
    for api in excluded {
        let capability = lookup(api).unwrap();
        assert!(matches!(capability.support, Support::Unrepresentable(_)));
        let resource = match capability.resource {
            ResourceKind::Object => "arn:aws:s3:::public-data/readme.txt",
            ResourceKind::Queue => "arn:aws:sqs:us-east-1:000000000000:jobs",
            ResourceKind::Identity => {
                "arn:aws:ses:us-east-1:000000000000:identity/test@example.invalid"
            }
            ResourceKind::Global => "*",
            ResourceKind::Bucket => unreachable!(),
        };
        for (pointer, path) in [
            ("/expect/0", "expect[0].api"),
            (
                "/expected_finding/evidence",
                "expected_finding.evidence.api",
            ),
            ("/retest/expect/0", "retest.expect[0].api"),
        ] {
            let mut value = base();
            value["setup"]["queues"] = json!([{"name":"jobs"}]);
            *value.pointer_mut(pointer).unwrap() =
                json!({"api":api,"resource":resource,"result":"allow"});
            rejects(&value, path, "input representation error");
        }
    }
    // No implicit latest-version or default identity, nor an unreviewed schema extension.
    let mut value = base();
    value["expect"][0]["versionId"] = json!("v1");
    rejects(&value, "expect[0]", "unknown field");
    let mut value = base();
    value["setup"]["identities"] = json!(["test@example.invalid"]);
    rejects(&value, "setup", "unknown field");
    let mut value = base();
    value["expect"][0]["api"] = json!("s3:UnrecognizedOperation");
    rejects(&value, "expect[0].api", "unknown API");
    value["expect"][0]["api"] = json!("s3:PutBucketNotification");
    rejects(&value, "expect[0].api", "LWS strict unsupported");
    assert!(parse(&base()).is_ok());
}
