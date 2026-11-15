//! Fixed privileged child bootstrap. All paths and descriptor roles come from
//! the supervisor, never from a workload, environment or CLI option.
use super::{
    contract::Role,
    os::{self, Fault, Snapshot},
    seccomp,
};
use std::{
    ffi::CString,
    fs,
    io::Write,
    os::{
        fd::{AsRawFd, RawFd},
        unix::fs::{DirBuilderExt, OpenOptionsExt},
    },
    path::Path,
};

pub(super) const LIBRARIES: [(&str, &str); 4] = [
    (
        "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
        "lib/x86_64-linux-gnu/libgcc_s.so.1",
    ),
    (
        "/usr/lib/x86_64-linux-gnu/libm.so.6",
        "lib/x86_64-linux-gnu/libm.so.6",
    ),
    (
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "lib/x86_64-linux-gnu/libc.so.6",
    ),
    (
        "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "lib64/ld-linux-x86-64.so.2",
    ),
];

fn chown(path: &Path, uid: u32) -> Result<(), Fault> {
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| Fault::Path)?;
    os::syscall(unsafe { libc::chown(path.as_ptr(), uid, uid) })
}

fn limit(resource: libc::__rlimit_resource_t, amount: u64) -> Result<(), Fault> {
    let value = libc::rlimit {
        rlim_cur: amount,
        rlim_max: amount,
    };
    os::syscall(unsafe { libc::setrlimit(resource, &value) })
}

fn bind(snapshot: &Snapshot, root: &Path, relative: &str) -> Result<(), Fault> {
    let target = root.join(relative);
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o555)
        .open(&target)?;
    // Anonymous memfd dentries cannot be bind-mounted on this kernel. Copy
    // ONLY the sealed, already-verified library bytes into the new private
    // rootfs, verify the opened output bytes, and bind that same open inode.
    // The code image itself remains a sealed descriptor-only execveat image.
    snapshot.materialize(&mut file)?;
    os::mount(
        Some(Path::new(&format!("/proc/self/fd/{}", file.as_raw_fd()))),
        &target,
        None,
        libc::MS_BIND,
        None,
    )?;
    os::mount(
        None,
        &target,
        None,
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        None,
    )
}

pub(super) fn enter(
    role: Role,
    root: &Path,
    libraries: &[Snapshot],
    mappings: &[(RawFd, RawFd)],
    step: &mut u8,
) -> Result<(), Fault> {
    // Clone already supplied independent mount/PID/network namespaces. No
    // device or interface is added to the network namespace.
    *step = 1;
    os::mount(
        None,
        Path::new("/"),
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
    )?;
    *step = 2;
    os::mount(
        Some(Path::new("tmpfs")),
        root,
        Some("tmpfs"),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("size=16777216,nr_inodes=128,mode=0755"),
    )?;
    unsafe {
        libc::umask(0o022);
    }
    for directory in [
        "lib",
        "lib/x86_64-linux-gnu",
        "lib64",
        "proc",
        "dev",
        "sys",
        "tmp",
        "work",
        "private",
        "bin",
    ] {
        fs::DirBuilder::new()
            .mode(0o755)
            .create(root.join(directory))?;
    }
    chown(&root.join("work"), role.uid())?;
    chown(&root.join("tmp"), role.uid())?;
    if role == Role::A {
        chown(&root.join("private"), role.uid())?;
        let path = root.join("private/credential.canary");
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(b"synthetic-canary-only")?;
        chown(&path, role.uid())?;
    }
    *step = 3;
    for (snapshot, (_, relative)) in libraries.iter().zip(LIBRARIES) {
        bind(snapshot, root, relative)?;
    }
    *step = 4;
    os::mount(
        Some(Path::new("proc")),
        &root.join("proc"),
        Some("proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_RDONLY,
        Some("hidepid=2,subset=pid"),
    )?;
    // Duplicate sources away from the fixed destination range before dup2:
    // descriptor-number collisions must not change the selected objects.
    *step = 5;
    let mut copied = Vec::new();
    for (source, target) in mappings {
        let fd = unsafe { libc::fcntl(*source, libc::F_DUPFD_CLOEXEC, 64) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        copied.push((fd, *target));
    }
    for (source, target) in &copied {
        os::syscall(unsafe { libc::dup2(*source, *target) })?;
    }
    os::syscall(unsafe { libc::fcntl(6, libc::F_SETFD, libc::FD_CLOEXEC) })?;
    let keep = mappings
        .iter()
        .map(|(_, target)| *target)
        .collect::<Vec<_>>();
    os::close_except(&keep)?;
    *step = 6;
    use std::os::unix::ffi::OsStrExt;
    let root = CString::new(root.as_os_str().as_bytes()).map_err(|_| Fault::Path)?;
    os::syscall(unsafe { libc::chdir(root.as_ptr()) })?;
    os::syscall(unsafe { libc::chroot(c".".as_ptr()) })?;
    os::syscall(unsafe { libc::chdir(c"/work".as_ptr()) })?;
    *step = 7;
    for (resource, value) in [
        (libc::RLIMIT_CORE, 0),
        (libc::RLIMIT_NOFILE, 32),
        (libc::RLIMIT_NPROC, 12),
        (libc::RLIMIT_FSIZE, 1_048_576),
        (libc::RLIMIT_STACK, 8_388_608),
        (libc::RLIMIT_AS, 201_326_592),
    ] {
        limit(resource, value)?;
    }
    for cap in 0..=40 {
        os::syscall(unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) })?;
    }
    os::syscall(unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    })?;
    os::syscall(unsafe { libc::setgroups(0, std::ptr::null()) })?;
    os::syscall(unsafe { libc::setresgid(role.uid(), role.uid(), role.uid()) })?;
    os::syscall(unsafe { libc::setresuid(role.uid(), role.uid(), role.uid()) })?;
    // UID transitions clear PDEATHSIG. Restore it before the syscall policy
    // makes this setting immutable to the payload.
    os::syscall(unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) })?;
    // Fixed Linux capability ABI v3. No retained effective/permitted/inheritable bits.
    let header = [0x20080522_u32, 0];
    let data = [0_u32; 6];
    os::syscall(unsafe { libc::syscall(libc::SYS_capset, header.as_ptr(), data.as_ptr()) as i32 })?;
    os::syscall(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) })?;
    *step = 8;
    seccomp::install(role, true)?;
    let argv = [
        c"/probe".as_ptr(),
        c"__linux-probe-worker".as_ptr(),
        c"dummy-argv-marker".as_ptr(),
        std::ptr::null(),
    ];
    let env = [c"LANG=C".as_ptr(), c"LC_ALL=C".as_ptr(), std::ptr::null()];
    *step = 9;
    // FD 6 is the sealed code object verified by the root supervisor.
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            6,
            c"".as_ptr(),
            argv.as_ptr(),
            env.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    Err(std::io::Error::last_os_error().into())
}
