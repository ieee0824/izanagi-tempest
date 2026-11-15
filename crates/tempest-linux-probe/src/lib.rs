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
mod contract;
mod guard;
mod identity;
mod lease;
mod os;
mod registry;
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
