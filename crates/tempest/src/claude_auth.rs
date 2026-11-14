use crate::host_io;
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fs, io,
    os::{
        unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        unix::process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

const USAGE: &str =
    "Usage: tempest claude-auth login --agent-executable FILE --config-dir NEW_DIRECTORY";
const CLAUDE_VERSION: &str = "2.1.323 (Claude Code)";
const CLAUDE_SHA256: &str = "5432918d904a9b6afef7bb79d20df24d76052eabc1f41bceb84091d21f8889a7";

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn digest(path: &Path) -> io::Result<String> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

fn owner_private_directory(path: &Path) -> io::Result<PathBuf> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(invalid("Claude auth directory is not owner-private"));
    }
    path.canonicalize()
}

fn owner_private_credential(path: &Path) -> io::Result<()> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o177 != 0
        || metadata.len() == 0
        || metadata.len() > 64 * 1024
    {
        return Err(invalid(
            "Claude credential fallback was not an owner-private regular file",
        ));
    }
    Ok(())
}

fn fixed_agent(path: &Path) -> io::Result<PathBuf> {
    let path = path.canonicalize()?;
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
        || digest(&path)? != CLAUDE_SHA256
    {
        return Err(invalid(
            "Claude executable does not match the reviewed binary",
        ));
    }
    let output = Command::new(&path)
        .arg("--version")
        .env_clear()
        .env("HOME", "/private/var/empty")
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success()
        || output.stderr.len() > 4096
        || String::from_utf8(output.stdout)
            .map_err(|_| invalid("invalid Claude version output"))?
            .trim()
            != CLAUDE_VERSION
    {
        return Err(invalid("Claude executable version is not reviewed"));
    }
    Ok(path)
}

fn new_directory(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() || path.exists() || path.symlink_metadata().is_ok() {
        return Err(invalid(
            "Claude auth config directory must be a new absolute path",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("Claude auth config parent missing"))?
        .canonicalize()?;
    let parent_metadata = parent.symlink_metadata()?;
    let mode = parent_metadata.permissions().mode();
    let owner_private_parent =
        parent_metadata.uid() == unsafe { libc::geteuid() } && mode & 0o022 == 0;
    let root_sticky_temporary_parent =
        parent_metadata.uid() == 0 && mode & libc::S_ISVTX as u32 != 0 && mode & 0o002 != 0;
    if !parent_metadata.is_dir() || (!owner_private_parent && !root_sticky_temporary_parent) {
        return Err(invalid("Claude auth config parent is not trusted"));
    }
    fs::DirBuilder::new().mode(0o700).create(path)?;
    owner_private_directory(path)
}

fn login(executable: &Path, requested_config: &Path) -> io::Result<()> {
    let executable = fixed_agent(executable)?;
    let config = new_directory(requested_config)?;
    let parent = config
        .parent()
        .ok_or_else(|| invalid("Claude auth config parent missing"))?;
    let jail = parent.join(format!(".tempest-claude-login-{}", host_io::random_hex()?));
    fs::DirBuilder::new().mode(0o700).create(&jail)?;
    for directory in ["bin", "home", "tmp", "cwd"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(jail.join(directory))?;
    }
    let agent = jail.join("bin/agent");
    host_io::private_copy(&executable, &agent)?;
    fs::set_permissions(&agent, fs::Permissions::from_mode(0o500))?;
    if digest(&agent)? != CLAUDE_SHA256 {
        return Err(invalid("staged Claude executable changed"));
    }
    let profile = jail.join("login.sb");
    host_io::write_new(&profile, include_bytes!("darwin-claude-login.sb"))?;
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o400))?;

    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .args([
            OsString::from("-D"),
            OsString::from(format!("JAIL={}", jail.display())),
            OsString::from("-D"),
            OsString::from(format!("AUTH_DIR={}", config.display())),
            OsString::from("-f"),
            profile.as_os_str().to_owned(),
            agent.as_os_str().to_owned(),
            OsString::from("auth"),
            OsString::from("login"),
            OsString::from("--claudeai"),
        ])
        .current_dir(jail.join("cwd"))
        .env_clear()
        .env("CLAUDE_CONFIG_DIR", &config)
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
        .env("DISABLE_AUTOUPDATER", "1")
        .env("HOME", jail.join("home"))
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", jail.join("tmp"))
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .process_group(0);
    let status = command.status()?;
    if !status.success() {
        return Err(invalid("Claude subscription login failed"));
    }
    owner_private_credential(&config.join(".credentials.json"))?;
    fs::remove_dir_all(&jail)?;
    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "status": "logged_in",
            "auth_method": "claude.ai subscription",
            "cli_version": CLAUDE_VERSION,
            "config_directory": config,
            "credential_storage": "owner_private_file"
        })
    );
    Ok(())
}

fn options(args: &[OsString]) -> io::Result<(PathBuf, PathBuf)> {
    if args.len() != 5 || args[0] != OsStr::new("login") {
        return Err(invalid("invalid Claude auth arguments"));
    }
    let mut executable = None;
    let mut config = None;
    for pair in args[1..].chunks_exact(2) {
        match pair[0].to_str() {
            Some("--agent-executable") if executable.is_none() => executable = Some(&pair[1]),
            Some("--config-dir") if config.is_none() => config = Some(&pair[1]),
            _ => return Err(invalid("unknown or duplicate Claude auth option")),
        }
    }
    Ok((
        executable
            .ok_or_else(|| invalid("Claude executable missing"))?
            .into(),
        config
            .ok_or_else(|| invalid("Claude config directory missing"))?
            .into(),
    ))
}

pub fn run(args: &[OsString]) -> ExitCode {
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match options(args).and_then(|(executable, config)| login(&executable, &config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("claude-auth: {error}\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_options_are_exact() {
        let args = [
            "login",
            "--config-dir",
            "/private/tmp/auth",
            "--agent-executable",
            "/private/tmp/claude",
        ]
        .map(OsString::from);
        let (executable, config) = options(&args).unwrap();
        assert_eq!(executable, Path::new("/private/tmp/claude"));
        assert_eq!(config, Path::new("/private/tmp/auth"));
        assert!(options(&args[..4]).is_err());
    }

    #[test]
    fn auth_directory_can_be_created_in_the_system_temporary_directory() {
        let requested = std::env::temp_dir().join(format!(
            "tempest-claude-auth-directory-{}",
            host_io::random_hex().unwrap()
        ));
        let created = new_directory(&requested).unwrap();
        let metadata = created.symlink_metadata().unwrap();
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        fs::remove_dir(&created).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn login_profile_allows_only_the_dedicated_file_boundary() {
        let root = std::env::temp_dir().join(format!(
            "tempest-claude-login-profile-{}",
            host_io::random_hex().unwrap()
        ));
        host_io::directory(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let jail = root.join("jail");
        let auth = root.join("auth");
        host_io::directory(&jail).unwrap();
        host_io::directory(&auth).unwrap();
        let profile = jail.join("login.sb");
        host_io::write_new(&profile, include_bytes!("darwin-claude-login.sb")).unwrap();
        let outside = root.join("outside-canary");
        host_io::write_new(&outside, b"must-not-read").unwrap();
        let sandbox = |script: &str| {
            Command::new("/usr/bin/sandbox-exec")
                .args([
                    OsString::from("-D"),
                    OsString::from(format!("JAIL={}", jail.display())),
                    OsString::from("-D"),
                    OsString::from(format!("AUTH_DIR={}", auth.display())),
                    OsString::from("-f"),
                    profile.as_os_str().to_owned(),
                    OsString::from("/bin/sh"),
                    OsString::from("-c"),
                    OsString::from(script),
                ])
                .env_clear()
                .env("AUTH_DIR", &auth)
                .env("OUTSIDE", &outside)
                .env("PATH", "/usr/bin:/bin")
                .current_dir(&jail)
                .output()
                .unwrap()
        };
        let allowed = sandbox("printf allowed > \"$AUTH_DIR/probe\"");
        assert!(
            allowed.status.success(),
            "{}",
            String::from_utf8_lossy(&allowed.stderr)
        );
        assert_eq!(fs::read(auth.join("probe")).unwrap(), b"allowed");
        assert!(!sandbox("cat \"$OUTSIDE\"").status.success());
        assert!(
            !sandbox("/usr/bin/security show-keychain-info")
                .status
                .success()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
