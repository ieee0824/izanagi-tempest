use std::{env, fs, process::ExitCode};
use tempest::{plan::ExecutionPlan, scenario::load};
use tempest_model::capability::LWS_COMMIT;

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--version" || args[0] == "-V") {
        let binary_mode = if cfg!(feature = "native-test-upstream") {
            "native_test_upstream; formal_test_only=true"
        } else {
            "production; formal_test_only=false"
        };
        println!("tempest {} ({binary_mode})", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if args.first().is_some_and(|arg| arg == "run") {
        return tempest::run_cli::run(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "recover") {
        return tempest::run_cli::recover(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "report") {
        if args.get(1).is_some_and(|arg| arg == "--aggregate") {
            return tempest::aggregate::run(&args[2..]);
        }
        return tempest::report::run(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "mcp-proxy") {
        return tempest::proxy_cli::run(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "mcp-connect") {
        return tempest::supervisor::connect_cli(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "model-api-relay") {
        return tempest::model_api_relay::run(&args[1..]);
    }
    if args
        .first()
        .is_some_and(|arg| arg == "capability-probe-mcp")
    {
        return tempest::capability_probe_mcp::run(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "capability-discover") {
        return tempest::capability_runner::run(&args[1..]);
    }
    if args.first().is_some_and(|arg| arg == "mcp-session") {
        return tempest::supervisor::session_cli(&args[1..]);
    }
    const USAGE: &str = "Usage: tempest --version\n       tempest validate <scenario.yaml>\n       tempest plan <scenario.yaml> [--actor NAME]\n       tempest run --help\n       tempest recover RUN_DIRECTORY\n       tempest report RUN_DIRECTORY\n       tempest report --aggregate RUNS_DIRECTORY\n       tempest mcp-proxy --help\n       tempest mcp-session --help\n       tempest mcp-connect --help\n       tempest model-api-relay --help\n       tempest capability-probe-mcp --help\n       tempest capability-discover --help";
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let is_plan = args.first().is_some_and(|a| a == "plan");
    let valid_args = (args.len() == 2 && (args[0] == "validate" || is_plan))
        || (is_plan && args.len() == 4 && args[2] == "--actor" && args[3].to_str().is_some());
    if !valid_args {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let raw = match fs::read(&args[1]) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("{}: {e}", args[1].to_string_lossy());
            return ExitCode::from(2);
        }
    };
    match load(&raw) {
        Ok(loaded) => {
            let valid = &loaded.validated;
            if is_plan {
                let selected = args.get(3).and_then(|a| a.to_str());
                match ExecutionPlan::resolve(valid, selected) {
                    Ok(plan) => {
                        let mut summary = plan.summary();
                        summary["id"] = valid.scenario().id.clone().into();
                        summary["sha256"] = loaded.sha256.into();
                        summary["validation"] = "runtime_resolution".into();
                        println!("{summary}");
                        return ExitCode::SUCCESS;
                    }
                    Err(error) => {
                        eprintln!("{error}");
                        return ExitCode::from(1);
                    }
                }
            }

            println!(
                "{}",
                serde_json::json!({
                    "id":valid.scenario().id,
                    "sha256":loaded.sha256,
                    "lws_commit":LWS_COMMIT,
                    "validation":"static",
                    "finding_present":valid.finding_present(),
                    "retest_present":valid.retest_present(),
                    "deviation_semantics_unchecked":valid.deviation_semantics_unchecked(),
                    "runtime_checks":"not_performed",
                    "budget":{"max_calls":valid.scenario().budget.max_calls,"timeout_ms":valid.scenario().budget.timeout.0.as_millis()}
                })
            );
            ExitCode::SUCCESS
        }
        Err(errors) => {
            for error in errors {
                eprintln!("{error}");
            }
            ExitCode::from(1)
        }
    }
}
