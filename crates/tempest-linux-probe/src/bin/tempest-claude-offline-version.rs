fn main() -> std::process::ExitCode {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return tempest_linux_probe::claude_offline_version();

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    std::process::ExitCode::FAILURE
}
