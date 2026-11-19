//! Read-only dedicated-user admission. Never creates users or changes groups.
use std::ffi::CStr;

#[derive(Debug)]
pub struct UserSnapshot {
    pub account_uid: u32,
    pub account_gid: u32,
    pub private_gid: u32,
    pub kvm_gid: u32,
    pub uids: [u32; 3],
    pub gids: [u32; 3],
    pub groups: Vec<u32>,
    pub shell: Vec<u8>,
    pub home: Vec<u8>,
}

impl UserSnapshot {
    pub fn valid(&self) -> bool {
        (1..1000).contains(&self.account_uid)
            && self.private_gid != 0
            && self.kvm_gid != 0
            && self.private_gid != self.kvm_gid
            && self.account_gid == self.private_gid
            && self.uids == [self.account_uid; 3]
            && self.gids == [self.private_gid; 3]
            && self.groups.contains(&self.kvm_gid)
            && self
                .groups
                .iter()
                .all(|gid| *gid == self.kvm_gid || *gid == self.private_gid)
            && self.shell == b"/usr/sbin/nologin"
            && self.home == b"/nonexistent"
    }
}

/// Must run on the single-threaded entry before fork or opening /dev/kvm.
pub fn current() -> Option<UserSnapshot> {
    if std::fs::read_dir("/proc/self/task").ok()?.count() != 1 {
        return None;
    }
    // libc account/group lookups return static storage; copy each result
    // before calling the next lookup. No password/shadow fields are accessed.
    let account = unsafe { libc::getpwnam(c"tempest-kvm".as_ptr()).as_ref()? };
    let account_uid = account.pw_uid;
    let account_gid = account.pw_gid;
    let shell = unsafe { CStr::from_ptr(account.pw_shell) }
        .to_bytes()
        .to_vec();
    let home = unsafe { CStr::from_ptr(account.pw_dir) }
        .to_bytes()
        .to_vec();
    let private_gid = unsafe { libc::getgrnam(c"tempest-kvm".as_ptr()).as_ref()? }.gr_gid;
    let kvm_gid = unsafe { libc::getgrnam(c"kvm".as_ptr()).as_ref()? }.gr_gid;
    let mut uids = [0; 3];
    let mut gids = [0; 3];
    if unsafe { libc::getresuid(&mut uids[0], &mut uids[1], &mut uids[2]) } != 0
        || unsafe { libc::getresgid(&mut gids[0], &mut gids[1], &mut gids[2]) } != 0
    {
        return None;
    }
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if !(1..=16).contains(&count) {
        return None;
    }
    let mut groups = vec![0; count as usize];
    if unsafe { libc::getgroups(count, groups.as_mut_ptr()) } != count {
        return None;
    }
    Some(UserSnapshot {
        account_uid,
        account_gid,
        private_gid,
        kvm_gid,
        uids,
        gids,
        groups,
        shell,
        home,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn user() -> UserSnapshot {
        UserSnapshot {
            account_uid: 998,
            account_gid: 997,
            private_gid: 997,
            kvm_gid: 993,
            uids: [998; 3],
            gids: [997; 3],
            groups: vec![993],
            shell: b"/usr/sbin/nologin".to_vec(),
            home: b"/nonexistent".to_vec(),
        }
    }
    #[test]
    fn dedicated_system_user_only() {
        assert!(user().valid());
        let mut value = user();
        value.uids = [0; 3];
        assert!(!value.valid());
        let mut value = user();
        value.account_uid = 1000;
        value.uids = [1000; 3];
        assert!(!value.valid());
        let mut value = user();
        value.groups.push(27);
        assert!(!value.valid());
        let mut value = user();
        value.groups.clear();
        assert!(!value.valid());
        let mut value = user();
        value.shell = b"/bin/bash".to_vec();
        assert!(!value.valid());
        let mut value = user();
        value.uids[2] = 0;
        assert!(!value.valid());
    }
}
