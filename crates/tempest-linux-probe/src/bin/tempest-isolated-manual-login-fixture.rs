fn main() -> std::process::ExitCode {
    #[cfg(all(target_os = "linux", target_arch = "x86_64", debug_assertions))]
    return tempest_linux_probe::isolated_manual_login_fixture();

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64", debug_assertions)))]
    std::process::ExitCode::FAILURE
}
