use std::{env, fs, process::ExitCode};
use tempest::scenario::load;
use tempest_model::capability::LWS_COMMIT;

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("Usage: tempest validate <scenario.yaml>");
        return ExitCode::SUCCESS;
    }
    if args.len() != 2 || args[0] != "validate" {
        eprintln!("Usage: tempest validate <scenario.yaml>");
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
