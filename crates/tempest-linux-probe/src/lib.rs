//! Linux/x86_64 dummy isolation investigation, NOT a launcher authorization API.
//!
//! The dependency boundary deliberately excludes the Tempest runtime crate.
//! The production permit API is not available to this crate:
//!
//! ```compile_fail
//! use tempest::capability_proof::authorize_launch;
//! ```
//!
//! No permit is produced by this public API:
//!
//! ```compile_fail
//! use tempest_linux_probe::authorize_launch;
//! ```
//!
//! ```compile_fail
//! let _: () = tempest_linux_probe::run(&[]);
//! ```
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! Fixed, dummy-only Linux boundary investigation. Never a model launcher.
//! No executable, mount path, environment or network target is caller-selected.

mod ancillary;
mod capsule;
mod capture;
mod cgroup;
mod claude_offline;
mod contract;
mod guard;
// Read-only observations, deliberately not an authorization or barrier API.
#[allow(dead_code)]
mod holder_scan;
mod identity;
mod lease;
mod os;
mod registry;
// Deliberately unconnected contract prototype; no route/launcher entry point.
#[allow(dead_code)]
mod route_contract;
mod runtime;
mod seccomp;
mod watchdog;
mod worker;

pub fn run(args: &[std::ffi::OsString]) -> std::process::ExitCode {
    runtime::run(args)
}

pub fn worker() -> std::process::ExitCode {
    std::process::ExitCode::from(worker::run() as u8)
}

mod private_io;

/// Run only the pinned offline Claude version fixture.
pub fn claude_offline_version() -> std::process::ExitCode {
    claude_offline::run().0
}

pub use claude_offline::{OfflineObservation, OfflineRecovery};

/// Run the fixed version fixture and return the outer supervisor's observations.
pub fn claude_offline_version_observed() -> (std::process::ExitCode, Option<OfflineObservation>) {
    claude_offline::run()
}

/// Run the fixed offline Claude configuration isolation fixture.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn claude_offline_config() -> std::process::ExitCode {
    claude_offline::run_config()
}

/// Run the fixed, unauthenticated offline PTY fixture.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn claude_offline_pty() -> std::process::ExitCode {
    claude_offline::run_pty()
}

/// Run the fixed writable-configuration PTY fixture.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn claude_offline_writable_pty() -> std::process::ExitCode {
    claude_offline::run_writable_pty()
}

/// Exercise a local synthetic login policy under the fixed PTY supervisor.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn claude_offline_local_auth_pty() -> std::process::ExitCode {
    claude_offline::run_local_auth_pty()
}

/// Check the fixed manual login entry before any process, mount, or network setup.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn claude_manual_login() -> std::process::ExitCode {
    claude_offline::run_manual_login()
}

/// Read the fixed host management inputs without enabling login or consumption.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn host_login_diagnostic() -> std::process::ExitCode {
    claude_offline::run_host_login_diagnostic()
}

/// Sign one diagnostic response for a verified host-managed consumption.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn host_login_responder() -> std::process::ExitCode {
    claude_offline::run_host_login_responder()
}

/// Publish the committed host ledger record for read-only login diagnostics.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn host_login_publisher() -> std::process::ExitCode {
    claude_offline::run_host_login_publisher()
}
