//! Bounded metadata parsers. No snapshot from this module establishes a barrier.
use std::os::unix::fs::MetadataExt;
use std::{fs::File, io::Read, path::Path, time::Instant};

#[derive(Debug, PartialEq, Eq)]
pub(super) struct TaskPipeFd {
    pub tid: u32,
    pub start_ticks: u64,
    pub fd: u32,
    pub writes: bool,
}

pub(super) struct ManagerPipe<'a> {
    pub identity: (u64, u64),
    pub expected: &'a [(u32, bool)],
}

/// The single-threaded manager holds its directory iterator open while
/// checking entries. Its enumeration FD therefore cannot vanish mid-scan.
pub(super) fn manager_pipe_fds(
    pipe: (u64, u64),
    budget: &mut Budget,
) -> Result<Vec<(u32, bool)>, Unknown> {
    let mut observed = Vec::new();
    budget.check()?;
    for entry in std::fs::read_dir("/proc/self/fd").map_err(|_| Unknown::Io)? {
        budget.check()?;
        budget.entries_left = budget.entries_left.checked_sub(1).ok_or(Unknown::Limit)?;
        let entry = entry.map_err(|_| Unknown::Io)?;
        let fd: i32 = entry
            .file_name()
            .to_str()
            .ok_or(Unknown::Format)?
            .parse()
            .map_err(|_| Unknown::Format)?;
        let actual = std::fs::metadata(entry.path()).map_err(|_| Unknown::Io)?;
        if actual.mode() & libc::S_IFMT != libc::S_IFIFO || (actual.dev(), actual.ino()) != pipe {
            continue;
        }
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(Unknown::Io);
        }
        let writes = match flags & (libc::O_PATH | libc::O_ACCMODE) {
            libc::O_RDONLY => false,
            libc::O_WRONLY => true,
            _ => return Err(Unknown::Format),
        };
        observed.push((fd as u32, writes));
    }
    observed.sort_unstable();
    budget.check()?;
    Ok(observed)
}

/// Observation only: neither cgroup identity nor a stationary barrier is proven.
/// Shared tables are deliberately represented once per task, never deduplicated.
pub(super) fn task_pipe_fds(
    proc_root: &Path,
    pid: u32,
    pipe_identity: (u64, u64),
    budget: &mut Budget,
) -> Result<Vec<TaskPipeFd>, Unknown> {
    let tasks = proc_root.join(pid.to_string()).join("task");
    let tids = budget.ids(&tasks)?;
    if tids.is_empty() {
        return Err(Unknown::Format);
    }
    let mut result = Vec::new();
    for tid in &tids {
        let task = tasks.join(tid.to_string());
        let before = start_ticks(&budget.read(&task.join("stat"), 65536)?, *tid)?;
        let fds = budget.ids(&task.join("fd"))?;
        let mut identities = Vec::with_capacity(fds.len());
        for fd in &fds {
            budget.check()?;
            let path = task.join("fd").join(fd.to_string());
            let a = std::fs::metadata(&path).map_err(|_| Unknown::Io)?;
            identities.push((a.dev(), a.ino(), a.mode(), a.rdev()));
            if a.mode() & libc::S_IFMT != libc::S_IFIFO || (a.dev(), a.ino()) != pipe_identity {
                continue;
            }
            let info = task.join("fdinfo").join(fd.to_string());
            let access = access_mode(&budget.read(&info, 65536)?)?;
            let b = std::fs::metadata(&path).map_err(|_| Unknown::Io)?;
            let again = access_mode(&budget.read(&info, 65536)?)?;
            if (a.dev(), a.ino(), a.mode()) != (b.dev(), b.ino(), b.mode()) || access != again {
                return Err(Unknown::Format);
            }
            result.push(TaskPipeFd {
                tid: *tid,
                start_ticks: before,
                fd: *fd,
                writes: access == libc::O_WRONLY,
            });
        }
        // Compare all descriptor identities, including nonmatching objects.
        // This detects observed changes, but cannot establish stationarity.
        for (fd, identity) in fds.iter().zip(identities) {
            budget.check()?;
            let metadata =
                std::fs::metadata(task.join("fd").join(fd.to_string())).map_err(|_| Unknown::Io)?;
            if (
                metadata.dev(),
                metadata.ino(),
                metadata.mode(),
                metadata.rdev(),
            ) != identity
            {
                return Err(Unknown::Format);
            }
        }
        if budget.ids(&task.join("fd"))? != fds
            || start_ticks(&budget.read(&task.join("stat"), 65536)?, *tid)? != before
        {
            return Err(Unknown::Format);
        }
    }
    if budget.ids(&tasks)? != tids {
        return Err(Unknown::Format);
    }
    budget.check()?;
    Ok(result)
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Unknown {
    Io,
    Limit,
    Deadline,
    Format,
}

pub(super) struct Budget {
    pub deadline: Instant,
    pub bytes_left: usize,
    pub entries_left: usize,
}

impl Budget {
    fn check(&self) -> Result<(), Unknown> {
        if Instant::now() >= self.deadline {
            Err(Unknown::Deadline)
        } else {
            Ok(())
        }
    }

    pub fn read(&mut self, path: &Path, limit: usize) -> Result<String, Unknown> {
        self.check()?;
        let bound = limit.min(self.bytes_left);
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Unknown::Io)?
            .take(bound.checked_add(1).ok_or(Unknown::Limit)? as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Unknown::Io)?;
        self.check()?;
        if bytes.len() > bound {
            return Err(Unknown::Limit);
        }
        self.bytes_left -= bytes.len();
        String::from_utf8(bytes).map_err(|_| Unknown::Format)
    }

    /// Every directory entry consumes budget, including nonnumeric names.
    pub fn ids(&mut self, path: &Path) -> Result<Vec<u32>, Unknown> {
        self.check()?;
        let mut result = Vec::new();
        for item in std::fs::read_dir(path).map_err(|_| Unknown::Io)? {
            self.check()?;
            self.entries_left = self.entries_left.checked_sub(1).ok_or(Unknown::Limit)?;
            let name = item.map_err(|_| Unknown::Io)?.file_name();
            let name = name.to_str().ok_or(Unknown::Format)?;
            if !name.is_empty() && name.bytes().all(|b| b.is_ascii_digit()) {
                result.push(name.parse().map_err(|_| Unknown::Format)?);
            }
        }
        result.sort_unstable();
        if result.windows(2).any(|w| w[0] == w[1]) {
            return Err(Unknown::Format);
        }
        Ok(result)
    }
}

/// comm may contain spaces, newlines, and parentheses; numeric suffix may not.
pub(super) fn start_ticks(stat: &str, expected_id: u32) -> Result<u64, Unknown> {
    let (id, rest) = stat.split_once(" (").ok_or(Unknown::Format)?;
    if id.parse::<u32>().map_err(|_| Unknown::Format)? != expected_id || expected_id == 0 {
        return Err(Unknown::Format);
    }
    let (_, suffix) = rest.rsplit_once(") ").ok_or(Unknown::Format)?;
    // Suffix starts with field 3 (state); starttime is field 22.
    let ticks = suffix
        .split_ascii_whitespace()
        .nth(19)
        .ok_or(Unknown::Format)?;
    let ticks = ticks.parse::<u64>().map_err(|_| Unknown::Format)?;
    if ticks == 0 {
        Err(Unknown::Format)
    } else {
        Ok(ticks)
    }
}

pub(super) fn access_mode(fdinfo: &str) -> Result<i32, Unknown> {
    let mut flags = None;
    for line in fdinfo.lines() {
        if let Some(value) = line.strip_prefix("flags:") {
            if flags.is_some() {
                return Err(Unknown::Format);
            }
            flags = Some(u32::from_str_radix(value.trim(), 8).map_err(|_| Unknown::Format)?);
        }
    }
    let flags = flags.ok_or(Unknown::Format)?;
    if flags & libc::O_PATH as u32 != 0 {
        return Err(Unknown::Format);
    }
    match flags & libc::O_ACCMODE as u32 {
        0 => Ok(libc::O_RDONLY),
        1 => Ok(libc::O_WRONLY),
        _ => Err(Unknown::Format),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_pipe_dup_and_threads_are_observed_in_subprocess() {
        const MARKER: &str = "TEMPEST_HOLDER_SCAN_CHILD";
        if std::env::var_os(MARKER).is_none() {
            use std::io::{BufRead, Write};
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "holder_scan::tests::real_pipe_dup_and_threads_are_observed_in_subprocess",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env_clear()
                .env(MARKER, "1")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            let values = loop {
                line.clear();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                if let Some((_, payload)) = line.split_once("HOLDER_FIXTURE ") {
                    break payload
                        .split_whitespace()
                        .map(|x| x.parse::<u64>().unwrap())
                        .collect::<Vec<_>>();
                }
            };
            let mut budget = Budget {
                deadline: Instant::now() + std::time::Duration::from_secs(2),
                bytes_left: 1024 * 1024,
                entries_left: 65536,
            };
            let observed = task_pipe_fds(
                Path::new("/proc"),
                child.id(),
                (values[0], values[1]),
                &mut budget,
            );
            child.stdin.take().unwrap().write_all(b"stop\n").unwrap();
            let mut rest = String::new();
            reader.read_to_string(&mut rest).unwrap();
            assert!(child.wait().unwrap().success(), "{rest}");
            let rows = observed.unwrap();
            for tid in [values[2], values[3]] {
                for (fd, writes) in [(values[4], false), (values[5], true), (values[6], true)] {
                    assert!(
                        rows.iter().any(|r| r.tid == tid as u32
                            && r.fd == fd as u32
                            && r.writes == writes)
                    );
                }
            }
            return;
        }
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let duplicate = write.try_clone().unwrap();
        let m = std::fs::metadata(format!("/proc/self/fd/{}", read.as_raw_fd())).unwrap();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            ready_tx
                .send(unsafe { libc::syscall(libc::SYS_gettid) } as u32)
                .unwrap();
            stop_rx.recv().unwrap();
        });
        let tid = ready_rx.recv().unwrap();
        use std::io::Write;
        println!(
            "HOLDER_FIXTURE {} {} {} {} {} {} {}",
            m.dev(),
            m.ino(),
            tid,
            unsafe { libc::syscall(libc::SYS_gettid) },
            read.as_raw_fd(),
            write.as_raw_fd(),
            duplicate.as_raw_fd()
        );
        std::io::stdout().flush().unwrap();
        let mut stop = String::new();
        std::io::stdin().read_line(&mut stop).unwrap();
        stop_tx.send(()).unwrap();
        thread.join().unwrap();
        let mut exhausted = Budget {
            deadline: Instant::now() + std::time::Duration::from_secs(2),
            bytes_left: 0,
            entries_left: 0,
        };
        assert_eq!(
            exhausted.ids(Path::new("/proc/self/task")),
            Err(Unknown::Limit)
        );
    }

    #[test]
    fn stat_comm_cannot_shift_start_time() {
        let suffix = std::iter::once("S")
            .chain(std::iter::repeat_n("0", 18))
            .chain(std::iter::once("123"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            start_ticks(&format!("42 (a ) b\n(c)) {suffix}"), 42),
            Ok(123)
        );
        assert_eq!(
            start_ticks(&format!("42 (a) {suffix}"), 43),
            Err(Unknown::Format)
        );
        assert_eq!(start_ticks("42 (a) S 0", 42), Err(Unknown::Format));
    }

    #[test]
    fn fd_flags_are_unique_octal_and_directional() {
        assert_eq!(
            access_mode("pos:\t0\nflags:\t02000001\n"),
            Ok(libc::O_WRONLY)
        );
        assert_eq!(
            access_mode(&format!("flags: {:o}", libc::O_PATH | libc::O_CLOEXEC)),
            Err(Unknown::Format)
        );
        for bad in ["", "flags: 8", "flags: 2", "flags: 0\nflags: 1"] {
            assert_eq!(access_mode(bad), Err(Unknown::Format));
        }
    }
}
