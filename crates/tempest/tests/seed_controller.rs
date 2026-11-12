use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tempest::{
    plan::{ExecutionPlan, Stage},
    scenario::load,
    seed_controller::SeedController,
};
use tempest_model::{Diagnostic, guest::AccessKeys};

static COUNTER: AtomicU64 = AtomicU64::new(0);
struct Root(PathBuf);
impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tempest-seed-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn controller(&self, id: &str) -> SeedController {
        SeedController::create(&self.0, id, plan()).unwrap()
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn plan() -> ExecutionPlan {
    let loaded = load(include_bytes!("../../../scenarios/s3-overread-001.yaml")).unwrap();
    ExecutionPlan::resolve(&loaded.validated, None).unwrap()
}
fn keys(key: &str) -> AccessKeys {
    [("worker".into(), key.into())].into()
}

#[tokio::test]
async fn one_attempt_is_persisted_before_transport_and_duplicate_seed_revokes_use() {
    let root = Root::new();
    let mut controller = root.controller("run-1");
    assert!(controller.agent_prompt().is_err());
    controller
        .seed(Stage::Primary, |setup| {
            let marker = root.0.join("run-1/primary-seed-attempt.json");
            assert!(marker.is_file());
            assert_eq!(
                marker.metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(setup.users[0].name, "worker");
            async { Ok(keys("FIRST-WORKER-KEY")) }
        })
        .await
        .unwrap();
    assert!(
        controller
            .agent_prompt()
            .unwrap()
            .contains("FIRST-WORKER-KEY")
    );
    let audit =
        serde_json::to_string(&controller.binding_metadata(Stage::Primary).unwrap()).unwrap();
    assert!(!audit.contains("FIRST-WORKER-KEY"));
    assert!(
        controller
            .seed(Stage::Primary, |_| async { panic!("must not resend") })
            .await
            .is_err()
    );
    assert!(controller.agent_prompt().is_err());
    assert!(
        controller
            .accepts_claim(Stage::Primary, "FIRST-WORKER-KEY")
            .is_err()
    );
}

#[tokio::test]
async fn lost_response_and_invalid_registry_are_terminal_without_leaking_errors() {
    let root = Root::new();
    for (id, response) in [
        ("lost", Err(Diagnostic::new("transport", "SECRET-ERROR"))),
        ("invalid", Ok(AccessKeys::new())),
    ] {
        let mut controller = root.controller(id);
        let error = controller
            .seed(Stage::Primary, |_| async { response })
            .await
            .unwrap_err();
        assert!(!error.reason.contains("SECRET-ERROR"));
        assert!(
            controller
                .seed(Stage::Retest, |_| async { panic!("aborted run") })
                .await
                .is_err()
        );
        assert!(controller.agent_prompt().is_err());
    }
}

#[tokio::test]
async fn cancellation_never_permits_resend_or_another_stage() {
    let root = Root::new();
    let mut controller = root.controller("cancelled");
    let result = tokio::time::timeout(
        Duration::from_millis(10),
        controller.seed(Stage::Primary, |_| async {
            std::future::pending::<Result<AccessKeys, Diagnostic>>().await
        }),
    )
    .await;
    assert!(result.is_err());
    assert!(root.0.join("cancelled/primary-seed-attempt.json").is_file());
    assert!(controller.agent_prompt().is_err());
    assert!(
        controller
            .seed(Stage::Retest, |_| async { panic!("uncertain primary") })
            .await
            .is_err()
    );
    drop(controller);
    assert!(SeedController::create(&root.0, "cancelled", plan()).is_err());
}

#[tokio::test]
async fn stage_registries_bind_their_own_policy_and_do_not_accept_old_keys() {
    let root = Root::new();
    let mut controller = root.controller("two-stages");
    controller
        .seed(Stage::Primary, |_| async { Ok(keys("PRIMARY-KEY")) })
        .await
        .unwrap();
    let primary_policy = plan().setup().users[0].policy.clone();
    controller
        .seed(Stage::Retest, |setup| {
            assert_ne!(
                serde_json::to_value(&setup.users[0].policy).unwrap(),
                serde_json::to_value(primary_policy).unwrap()
            );
            async { Ok(keys("RETEST-KEY")) }
        })
        .await
        .unwrap();
    let check = plan().expect()[0].clone();
    assert_eq!(
        controller
            .probe(Stage::Primary, &check)
            .unwrap()
            .access_key_id,
        "PRIMARY-KEY"
    );
    assert_eq!(
        controller
            .probe(Stage::Retest, &check)
            .unwrap()
            .access_key_id,
        "RETEST-KEY"
    );
    assert!(
        !controller
            .accepts_claim(Stage::Retest, "PRIMARY-KEY")
            .unwrap()
    );
    assert!(!controller.agent_prompt().unwrap().contains("RETEST-KEY"));
    let primary =
        serde_json::to_value(controller.binding_metadata(Stage::Primary).unwrap()).unwrap();
    let retest = serde_json::to_value(controller.binding_metadata(Stage::Retest).unwrap()).unwrap();
    assert_ne!(primary["policy_sha256"], retest["policy_sha256"]);
}

#[test]
fn run_reservation_is_exclusive_after_drop_and_rejects_path_escape_or_public_root() {
    let root = Root::new();
    drop(root.controller("reserved"));
    assert!(SeedController::create(&root.0, "reserved", plan()).is_err());
    for id in ["../escape", "/absolute", "", ".", "a/b"] {
        assert!(SeedController::create(&root.0, id, plan()).is_err());
    }
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(SeedController::create(&root.0, "public", plan()).is_err());
}

#[tokio::test]
async fn a_retest_registry_reusing_the_primary_key_invalidates_the_run() {
    let root = Root::new();
    let mut controller = root.controller("reused-key");
    controller
        .seed(Stage::Primary, |_| async { Ok(keys("OLD-KEY")) })
        .await
        .unwrap();
    assert!(
        controller
            .seed(Stage::Retest, |_| async { Ok(keys("OLD-KEY")) })
            .await
            .is_err()
    );
    assert!(controller.agent_prompt().is_err());
    assert!(controller.binding_metadata(Stage::Retest).is_err());
}
