//! Fixed inputs for the dedicated Linux Claude --version experiment.
use super::os::Fault;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

struct Artifact {
    source: &'static str,
    bytes: u64,
    sha256: &'static str,
    targets: &'static [&'static str],
}

const ARTIFACTS: &[Artifact] = &[
    Artifact {
        source: "/var/lib/tempest-claude-offline/claude",
        bytes: 365842960,
        sha256: "0dc4f4a9a165fc60746d7ae8489712e5fc352f1e7ad4eb22e7141bd0812eb0cf",
        targets: &["bin/claude"],
    },
    Artifact {
        source: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        bytes: 236616,
        sha256: "5fc0940888e9d2e1a00e66d6b1a559c36364ee867683652e1074fa576952cc3f",
        targets: &[
            "lib64/ld-linux-x86-64.so.2",
            "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        ],
    },
    Artifact {
        source: "/usr/lib/x86_64-linux-gnu/libc.so.6",
        bytes: 2129424,
        sha256: "755a371e86cc9f564ab54f66140747700fb0a103f698f659f2060f707897e09a",
        targets: &["lib/x86_64-linux-gnu/libc.so.6"],
    },
    Artifact {
        source: "/usr/lib/x86_64-linux-gnu/libdl.so.2",
        bytes: 14408,
        sha256: "4dbcca3c01ca84d092b5b7b2610f5835b55fc70a0288dd9d766b40ac9386e2d9",
        targets: &["lib/x86_64-linux-gnu/libdl.so.2"],
    },
    Artifact {
        source: "/usr/lib/x86_64-linux-gnu/libm.so.6",
        bytes: 952616,
        sha256: "5dcc4d25466e29ca390ed6fabb371c69b65dff6fa4e91c34561057a020d6994a",
        targets: &["lib/x86_64-linux-gnu/libm.so.6"],
    },
    Artifact {
        source: "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
        bytes: 14408,
        sha256: "cd34f895c9d2aa669d5d2654bed6b71210fc9003c3a1e96bb5311a40feb86039",
        targets: &["lib/x86_64-linux-gnu/libpthread.so.0"],
    },
    Artifact {
        source: "/usr/lib/x86_64-linux-gnu/librt.so.1",
        bytes: 14624,
        sha256: "5a00236da5864e8d1123d74e616713110708d6e3e604188f4f256dab4c6941d4",
        targets: &["lib/x86_64-linux-gnu/librt.so.1"],
    },
];

fn copy_checked(
    input: impl Read,
    mut output: impl Write,
    bytes: u64,
    expected: &str,
) -> Result<(), Fault> {
    let mut input = input.take(bytes + 1);
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    let mut copied = 0;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        copied += count as u64;
        if copied > bytes {
            return Err(Fault::Identity);
        }
        hash.update(&buffer[..count]);
        output.write_all(&buffer[..count])?;
    }
    if copied != bytes || format!("{:x}", hash.finalize()) != expected {
        return Err(Fault::Identity);
    }
    Ok(())
}

fn open_input(artifact: &Artifact) -> Result<File, Fault> {
    let source = Path::new(artifact.source);
    for parent in source.parent().ok_or(Fault::Path)?.ancestors() {
        let metadata = parent.symlink_metadata()?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(Fault::Ownership);
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(source)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o7022 != 0
        || metadata.nlink() != 1
        || metadata.len() != artifact.bytes
    {
        return Err(Fault::Identity);
    }
    Ok(file)
}

fn verify_artifact(file: &File, artifact: &Artifact) -> Result<(), Fault> {
    use std::os::unix::fs::FileExt;
    struct FromStart<'a>(&'a File, u64);
    impl Read for FromStart<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let count = self.0.read_at(buf, self.1)?;
            self.1 += count as u64;
            Ok(count)
        }
    }
    copy_checked(
        FromStart(file, 0),
        io::sink(),
        artifact.bytes,
        artifact.sha256,
    )
}

fn stage_artifact(artifact: &Artifact, destination: &Path) -> Result<File, Fault> {
    use std::os::unix::fs::PermissionsExt;
    let input = open_input(artifact)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    copy_checked(input, &mut output, artifact.bytes, artifact.sha256)?;
    output.set_permissions(fs::Permissions::from_mode(0o555))?;
    let written = output.metadata()?;
    drop(output);
    let snapshot = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(destination)?;
    let reopened = snapshot.metadata()?;
    if (written.dev(), written.ino()) != (reopened.dev(), reopened.ino()) {
        return Err(Fault::Identity);
    }
    verify_artifact(&snapshot, artifact)?;
    Ok(snapshot)
}

const UID: u32 = 999;
const GID: u32 = 988;

fn audit_settings(root: &Path) -> Result<[u64; 6], Fault> {
    let directory = root.join("home/fixture/config");
    let info = directory.symlink_metadata()?;
    let file = directory.join("settings.json");
    let meta = file.symlink_metadata()?;
    if !info.is_dir()
        || info.uid() != UID
        || info.gid() != GID
        || info.mode() & 0o7777 != 0o700
        || !meta.is_file()
        || meta.uid() != UID
        || meta.gid() != GID
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
        || meta.len() != 3
        || fs::read(file)? != b"{}\n"
        || fs::read_dir(directory)?.count() != 1
    {
        return Err(Fault::Identity);
    }
    Ok([
        info.dev(),
        info.ino(),
        info.ctime() as u64,
        meta.dev(),
        meta.ino(),
        meta.ctime() as u64,
    ])
}

fn own(path: &Path, mode: u32) -> Result<(), Fault> {
    use std::os::unix::fs::{PermissionsExt, chown};
    chown(path, Some(UID), Some(GID))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn run_child(root: &Path, scratch: &Path) -> Result<(), Fault> {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, process::CommandExt},
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let stdout = scratch.join("stdout");
    let stderr = scratch.join("stderr");
    let child_root = CString::new(root.as_os_str().as_bytes()).map_err(|_| Fault::Path)?;
    let mut command = Command::new("/bin/claude");
    command
        .arg("--version")
        .env_clear()
        .env("HOME", "/home/fixture")
        .env("CLAUDE_CONFIG_DIR", "/home/fixture/config")
        .stdin(Stdio::null())
        .stdout(File::create(&stdout)?)
        .stderr(File::create(&stderr)?);
    // The executable, environment and chroot are fixed, and the child drops
    // all host descriptors at exec apart from stdio.
    unsafe {
        command.pre_exec(move || {
            let limit = libc::rlimit {
                rlim_cur: 4096,
                rlim_max: 4096,
            };
            if libc::chroot(child_root.as_ptr()) < 0
                || libc::chdir(c"/home/fixture".as_ptr()) < 0
                || libc::setgroups(0, std::ptr::null()) < 0
                || libc::setresgid(GID, GID, GID) < 0
                || libc::setresuid(UID, UID, UID) < 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
                || libc::setrlimit(libc::RLIMIT_FSIZE, &limit) < 0
                || libc::syscall(
                    libc::SYS_close_range,
                    3_u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let deadline = Instant::now() + Duration::from_secs(12);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            result => {
                let _ = child.kill();
                child.wait()?;
                return Err(result.err().map_or(Fault::ReportTimeout, Fault::from));
            }
        }
    };
    if !status.success()
        || fs::read(stdout)? != b"2.1.325 (Claude Code)\n"
        || fs::metadata(stderr)?.len() != 0
    {
        return Err(Fault::Identity);
    }
    Ok(())
}

fn verify_mount_table(root: &Path) -> Result<(), Fault> {
    use std::collections::BTreeSet;
    let mut expected = BTreeSet::from([root.to_path_buf()]);
    expected.extend(
        ARTIFACTS
            .iter()
            .flat_map(|entry| entry.targets)
            .map(|path| root.join(path)),
    );
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let mut columns = line.split_whitespace().skip(4);
        let Some(target) = columns.next().map(Path::new) else {
            return Err(Fault::Identity);
        };
        if !target.starts_with(root) {
            continue;
        }
        let flags = columns.next().ok_or(Fault::Identity)?;
        let flags: BTreeSet<_> = flags.split(',').collect();
        if !expected.remove(target)
            || !["ro", "nosuid", "nodev"]
                .iter()
                .all(|flag| flags.contains(flag))
            || flags.contains("rw")
        {
            return Err(Fault::Identity);
        }
    }
    if !expected.is_empty() {
        return Err(Fault::Identity);
    }
    Ok(())
}

fn run_in_root(scratch: &Path, root: &Path) -> Result<(u64, u64), Fault> {
    use super::{capsule, os};
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    for dir in [
        "bin",
        "lib",
        "lib/x86_64-linux-gnu",
        "lib64",
        "home",
        "home/fixture",
        "home/fixture/config",
    ] {
        fs::create_dir(root.join(dir))?;
    }
    for (index, artifact) in ARTIFACTS.iter().enumerate() {
        let staged = stage_artifact(artifact, &scratch.join(format!("artifact-{index}")))?;
        let identity = capsule::library_identity(&staged)?;
        for target in artifact.targets {
            let path = root.join(target);
            drop(
                OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)?,
            );
            capsule::bind_read_only(&staged, &path)?;
            if capsule::verify_bound_file(&path, |file| verify_artifact(file, artifact))?
                != identity
            {
                return Err(Fault::Identity);
            }
        }
    }
    let settings = root.join("home/fixture/config/settings.json");
    fs::write(&settings, b"{}\n")?;
    own(&root.join("home/fixture"), 0o700)?;
    own(&root.join("home/fixture/config"), 0o700)?;
    own(&settings, 0o600)?;
    os::mount(
        None,
        root,
        None,
        libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        None,
    )?;
    verify_mount_table(root)?;
    let before = audit_settings(root)?;
    run_child(root, scratch)?;
    if audit_settings(root)? != before {
        return Err(Fault::Identity);
    }

    let path = CString::new(root.as_os_str().as_bytes()).map_err(|_| Fault::Path)?;
    let mut flags = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    os::syscall(unsafe { libc::statvfs(path.as_ptr(), flags.as_mut_ptr()) })?;
    let usage = unsafe { flags.assume_init() };
    if usage.f_blocks * usage.f_frsize != 16777216 || usage.f_files != 128 {
        return Err(Fault::Identity);
    }
    Ok((
        (usage.f_blocks - usage.f_bfree) * usage.f_frsize,
        usage.f_files - usage.f_ffree,
    ))
}

fn trial(scratch: &Path) -> Result<(u64, u64), Fault> {
    use super::{capsule, os};
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    os::syscall(unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWNET) })?;
    capsule::make_mounts_private()?;
    let root = scratch.join("root");
    fs::create_dir(&root)?;
    capsule::mount_root(&root)?;
    let result = run_in_root(scratch, &root);
    // Detach the complete private mount tree before touching staging files.
    let path = CString::new(root.as_os_str().as_bytes()).map_err(|_| Fault::Path)?;
    os::syscall(unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) })?;
    result
}

pub(super) fn run() -> std::process::ExitCode {
    use std::{ffi::CStr, os::unix::ffi::OsStrExt, process::ExitCode};
    if std::env::args_os().len() != 1 || unsafe { libc::geteuid() } != 0 {
        return ExitCode::FAILURE;
    }
    let mut name = b"/var/lib/tempest-claude-version-XXXXXX\0".to_vec();
    let path = unsafe { libc::mkdtemp(name.as_mut_ptr().cast()) };
    if path.is_null() {
        return ExitCode::FAILURE;
    }
    let scratch = Path::new(std::ffi::OsStr::from_bytes(
        unsafe { CStr::from_ptr(path) }.to_bytes(),
    ));
    let result = trial(scratch);
    // Retain a mounted tree on unmount failure. Its private namespace
    // vanishes at process exit, and an error cannot be reported as success.
    let cleanup = fs::read_to_string("/proc/self/mountinfo").and_then(|table| {
        if table.lines().any(|row| {
            row.split_whitespace()
                .nth(4)
                .is_some_and(|p| p.starts_with(scratch.to_str().unwrap()))
        }) {
            return Err(io::Error::other("trial mounts remain"));
        }
        fs::remove_dir_all(scratch)
    });
    match (result, cleanup) {
        (Ok((bytes, inodes)), Ok(())) => {
            println!(
                "{{\"version\":\"2.1.325\",\"uid\":{UID},\"gid\":{GID},\"tmpfs_bytes\":{bytes},\"tmpfs_inodes\":{inodes},\"cleanup\":true}}"
            );
            ExitCode::SUCCESS
        }
        (result, cleanup) => {
            eprintln!(
                "offline fixture failed: {:?}; cleanup={}",
                result.err(),
                cleanup.is_ok()
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loader_aliases_share_one_artifact_and_all_targets_are_unique() {
        use std::collections::BTreeSet;
        let mut targets = BTreeSet::new();
        for artifact in ARTIFACTS {
            for target in artifact.targets {
                assert!(targets.insert(*target));
            }
        }
        assert_eq!(targets.len(), 8);
        assert_eq!(
            ARTIFACTS
                .iter()
                .filter(|entry| entry.targets.len() == 2)
                .count(),
            1
        );
        assert!(ARTIFACTS.iter().any(|entry| entry.targets
            == [
                "lib64/ld-linux-x86-64.so.2",
                "lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            ]));
    }

    #[test]
    fn copied_bytes_must_match_fixed_length_and_digest() {
        let value = b"dummy";
        let digest = format!("{:x}", Sha256::digest(value));
        let mut staged = Vec::new();
        copy_checked(value.as_slice(), &mut staged, 5, &digest).unwrap();
        assert_eq!(staged, value);
        for input in [b"dimmu".as_slice(), b"dum", b"dummy!"] {
            assert_eq!(
                copy_checked(input, io::sink(), 5, &digest),
                Err(Fault::Identity)
            );
        }
    }
}
