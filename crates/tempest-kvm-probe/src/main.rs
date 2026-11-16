fn main() {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if std::env::args_os().len() == 1 {
        match tempest_kvm_probe::supervisor::run() {
            Ok(result) => {
                println!(
                    "{{\"deadline_exceeded\":{},\"child_terminal_reaped\":{},\"explicit_cleanup_complete\":{},\"primary_errno\":{},\"cleanup_errno\":{}}}",
                    result.deadline_exceeded,
                    result.child_terminal_reaped,
                    result.explicit_cleanup_complete,
                    result
                        .primary_errno
                        .map_or_else(|| "null".into(), |value| value.to_string()),
                    result
                        .cleanup_errno
                        .map_or_else(|| "null".into(), |value| value.to_string())
                );
                std::process::exit(if result.explicit_cleanup_complete {
                    0
                } else {
                    1
                });
            }
            Err(_) => {
                println!("{{\"status\":\"rejected_or_unconfirmed\"}}");
                std::process::exit(2);
            }
        }
    }
    println!("{{\"status\":\"rejected\",\"reason\":\"fixed_native_entry_required\"}}");
    std::process::exit(2);
}
