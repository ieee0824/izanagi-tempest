//! Verify a bounded host-channel receipt for offline interoperability checks.
use serde_json::Value;
use std::{
    fs,
    io::{self, Read},
    process::ExitCode,
};

fn verify() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 5 && args.len() != 6 {
        return Err(
            "usage: tempest-host-channel-verify PUBLIC_KEY REQUEST NOW_UNIX_MS LEDGER_ID [--vsock]"
                .into(),
        );
    }
    let key = fs::read(&args[1])?;
    if key.len() != 32 {
        return Err("invalid public key length".into());
    }
    let request_bytes = fs::read(&args[2])?;
    if request_bytes.len() > 1024 {
        return Err("request too large".into());
    }
    let request: Value = serde_json::from_slice(&request_bytes)?;
    let mut now: u64 = args[3].to_str().ok_or("invalid time")?.parse()?;
    let mut input = Vec::new();
    if args.len() == 6 {
        if args[5] != "--vsock" {
            return Err("invalid transport".into());
        }
        input = tempest_linux_probe::host_channel::exchange(&serde_json::to_vec(&request)?)?;
        now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
            .try_into()?;
    } else {
        io::stdin().take(4097).read_to_end(&mut input)?;
    }
    if input.len() > 4096 {
        return Err("response too large".into());
    }
    let expected_ledger = args[4].to_str().ok_or("invalid expected ledger")?;
    tempest_linux_probe::host_channel::verify_receipt(
        &key,
        &request,
        &input,
        now,
        expected_ledger,
    )?;
    println!("host channel receipt verified");
    Ok(())
}

fn main() -> ExitCode {
    match verify() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("host channel receipt refused: {error}");
            ExitCode::FAILURE
        }
    }
}
