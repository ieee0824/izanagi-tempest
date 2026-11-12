use serde_json::{Value, json};
use tempest::{
    plan::{ExecutionPlan, RepairIntent, Stage},
    scenario::load,
};
use tempest_model::guest::AccessKeys;

fn input() -> Value {
    yaml_serde::from_str(include_str!("../../../scenarios/s3-overread-001.yaml")).unwrap()
}
fn plan(value: &Value, actor: Option<&str>) -> Result<ExecutionPlan, tempest_model::Diagnostic> {
    let scenario = load(yaml_serde::to_string(value).unwrap().as_bytes()).unwrap();
    ExecutionPlan::resolve(&scenario.validated, actor)
}
fn multi() -> Value {
    let mut value = input();
    let mut admin = value["setup"]["users"][0].clone();
    admin["name"] = json!("admin");
    value["setup"]["users"].as_array_mut().unwrap().push(admin);
    value
}
fn keys(worker: &str) -> AccessKeys {
    [("worker".to_owned(), worker.to_owned())].into()
}

#[test]
fn optional_parents_never_create_unconfigured_work() {
    for finding in [false, true] {
        for retest in [false, true] {
            let mut value = input();
            if !finding {
                value.as_object_mut().unwrap().remove("expected_finding");
            }
            if !retest {
                value.as_object_mut().unwrap().remove("retest");
            }
            let plan = plan(&value, None).unwrap();
            assert_eq!(plan.actor(), "worker");
            assert_eq!(plan.self_check().is_some(), finding);
            assert_eq!(plan.retest().is_some(), retest);
            assert_eq!(plan.expect().len(), 2);
            assert_eq!(plan.summary()["runtime_checks"], "not_performed");
            assert_eq!(plan.summary()["finding_configured"], finding);
            assert_eq!(plan.summary()["retest_configured"], retest);
            assert!(!plan.summary().to_string().contains("TOPSECRET"));
            assert!(
                !plan
                    .summary()
                    .to_string()
                    .contains("private-data/secret.txt")
            );
        }
    }
}

#[test]
fn ambiguous_runtime_actor_does_not_invalidate_static_input() {
    let value = multi();
    // Static load succeeds; only the runtime resolution is ambiguous.
    assert!(plan(&value, None).unwrap_err().reason.contains("--actor"));
    assert!(
        plan(&value, Some("missing"))
            .unwrap_err()
            .reason
            .contains("unknown")
    );
    assert_eq!(plan(&value, Some("admin")).unwrap().actor(), "admin");
    let mut reversed = value;
    reversed["setup"]["users"].as_array_mut().unwrap().reverse();
    assert_eq!(plan(&reversed, Some("worker")).unwrap().actor(), "worker");
    assert!(plan(&reversed, None).is_err());
}

#[test]
fn retest_replaces_only_its_named_policy_without_mutating_primary() {
    let mut value = multi();
    value["retest"]["user"] = json!("admin");
    let plan = plan(&value, Some("worker")).unwrap();
    let retest = plan.retest().unwrap();
    assert_eq!(retest.actor(), "admin");
    assert_eq!(retest.repair_intent(), RepairIntent::DifferentActor);
    let before = serde_json::to_value(plan.setup()).unwrap();
    let after = serde_json::to_value(retest.setup()).unwrap();
    assert_eq!(before["users"][0], after["users"][0]);
    assert_eq!(before["buckets"], after["buckets"]);
    assert_eq!(before["queues"], after["queues"]);
    let expected: tempest_model::policy::Policy =
        serde_json::from_value(value["retest"]["policy"].clone()).unwrap();
    assert_eq!(
        after["users"][1]["policy"],
        serde_json::to_value(expected).unwrap()
    );
    assert_ne!(before["users"][1]["policy"], after["users"][1]["policy"]);
}

#[test]
fn credential_and_policy_revisions_are_scoped_to_run_and_stage() {
    let plan = plan(&input(), None).unwrap();
    let primary = plan.bind("run-001", &keys("PRIMARY-WORKER-ID")).unwrap();
    let retest = plan
        .retest()
        .unwrap()
        .bind("run-001", &keys("FRESH-WORKER-ID"))
        .unwrap();
    assert_eq!(primary.stage(), Stage::Primary);
    assert_eq!(retest.stage(), Stage::Retest);
    assert_eq!(primary.actor(), retest.actor());
    assert_eq!(primary.run_id(), "run-001");
    assert_ne!(primary.policy_sha256(), retest.policy_sha256());
    assert_ne!(primary.access_key_sha256(), retest.access_key_sha256());
    assert!(!retest.accepts_claim(primary.access_key_id()));
    let probe = primary.probe(plan.self_check().unwrap());
    assert_eq!(probe.access_key_id, primary.access_key_id());
    assert_eq!(probe.resource, plan.self_check().unwrap().resource);
    let audit = serde_json::to_string(&primary).unwrap();
    assert!(!audit.contains(primary.access_key_id()));
    assert!(!format!("{primary:?}").contains(primary.access_key_id()));
}

#[test]
fn incomplete_or_colliding_seed_registry_cannot_choose_another_key() {
    let plan = plan(&multi(), Some("worker")).unwrap();
    assert!(plan.bind("run", &keys("MISSING-ADMIN")).is_err());
    let mut supplied: AccessKeys = [
        ("worker".into(), "ONE-LOCAL-KEY".into()),
        ("admin".into(), "ONE-LOCAL-KEY".into()),
    ]
    .into();
    assert!(plan.bind("run", &supplied).is_err());
    supplied.insert("admin".into(), "SECOND-LOCAL-KEY".into());
    assert!(plan.bind("", &supplied).is_err());
    assert_eq!(
        plan.bind("run", &supplied).unwrap().access_key_id(),
        "ONE-LOCAL-KEY"
    );
    supplied.insert("unexpected".into(), "EXTRA-LOCAL-KEY".into());
    assert!(plan.bind("run", &supplied).is_err());
}

#[test]
fn repair_intent_requires_a_deny_check_for_the_primary_finding_target() {
    let value = input();
    assert_eq!(
        plan(&value, None)
            .unwrap()
            .retest()
            .unwrap()
            .repair_intent(),
        RepairIntent::TargetedRepairCheck
    );
    let mut value = value;
    value["retest"]["expect"][0]["result"] = json!("allow");
    assert_eq!(
        plan(&value, None)
            .unwrap()
            .retest()
            .unwrap()
            .repair_intent(),
        RepairIntent::NoMatchingDenyCheck
    );
    value.as_object_mut().unwrap().remove("expected_finding");
    assert_eq!(
        plan(&value, None)
            .unwrap()
            .retest()
            .unwrap()
            .repair_intent(),
        RepairIntent::NotConfigured
    );
}

#[test]
fn cli_plan_resolves_without_claiming_runtime_execution() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_tempest"))
        .args([
            "plan",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../scenarios/s3-overread-001.yaml"
            ),
            "--actor",
            "worker",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["actor"], "worker");
    assert_eq!(value["validation"], "runtime_resolution");
    assert_eq!(value["runtime_checks"], "not_performed");
    assert_eq!(value["repair_intent"], "targeted_repair_check");
}

#[test]
fn prompt_contains_only_the_selected_primary_credential_and_public_instructions() {
    let plan = plan(&multi(), Some("worker")).unwrap();
    let primary_keys: AccessKeys = [
        ("worker".into(), "PUBLIC-WORKER-KEY".into()),
        ("admin".into(), "HIDDEN-ADMIN-KEY".into()),
    ]
    .into();
    let primary = plan.bind("run-a", &primary_keys).unwrap();
    let prompt = plan.agent_prompt("run-a", &primary).unwrap();
    assert!(prompt.contains("PUBLIC-WORKER-KEY"));
    assert!(prompt.contains("127.0.0.1:4566"));
    for hidden in [
        "HIDDEN-ADMIN-KEY",
        "TOPSECRET",
        "private-data",
        "*-data",
        "expected_finding",
    ] {
        assert!(!prompt.contains(hidden), "leaked {hidden}");
    }
    assert!(plan.agent_prompt("run-b", &primary).is_err());
    let retest = plan.retest().unwrap().bind("run-a", &primary_keys).unwrap();
    assert!(plan.agent_prompt("run-a", &retest).is_err());
}
