//! Fixed child-side VM. Not exposed until connected to the parent deadline.
use crate::{
    ExitSequence, GUEST, RAM_BYTES,
    abi::{MemoryRegion, Registers, SpecialRegisters},
};
use std::{
    cell::Cell,
    fs::OpenOptions,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd},
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    rc::Rc,
};
type Cleanup = Rc<Cell<Option<i32>>>;
type Ioctl = fn(i32, libc::c_ulong, libc::c_ulong) -> io::Result<i32>;
type Map = fn(usize, i32, i32, &Cleanup) -> io::Result<Mapping>;
fn record(sink: &Cleanup, result: io::Result<impl Sized>) {
    let mut first = sink.get();
    remember(&mut first, result);
    sink.set(first);
}
struct Tracked<T: IntoRawFd + AsRawFd> {
    value: Option<T>,
    sink: Cleanup,
}
impl<T: IntoRawFd + AsRawFd> Tracked<T> {
    fn new(value: T, sink: &Cleanup) -> Self {
        Self {
            value: Some(value),
            sink: sink.clone(),
        }
    }
}
impl<T: IntoRawFd + AsRawFd> std::ops::Deref for Tracked<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.value.as_ref().unwrap()
    }
}
impl<T: IntoRawFd + AsRawFd> AsRawFd for Tracked<T> {
    fn as_raw_fd(&self) -> i32 {
        self.value.as_ref().unwrap().as_raw_fd()
    }
}
impl<T: IntoRawFd + AsRawFd> IntoRawFd for Tracked<T> {
    fn into_raw_fd(mut self) -> i32 {
        self.value.take().unwrap().into_raw_fd()
    }
}
impl<T: IntoRawFd + AsRawFd> Drop for Tracked<T> {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            record(&self.sink, close(value));
        }
    }
}

fn ioctl(fd: i32, request: libc::c_ulong, argument: libc::c_ulong) -> io::Result<i32> {
    let result = unsafe { libc::ioctl(fd, request, argument) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

struct Mapping {
    pointer: *mut libc::c_void,
    length: usize,
    sink: Cleanup,
}
struct SlotGuard {
    vm: i32,
    armed: bool,
    sink: Cleanup,
    remove_ioctl: Ioctl,
}
impl SlotGuard {
    fn remove(&mut self) -> io::Result<i32> {
        if !self.armed {
            return Ok(0);
        }
        self.armed = false;
        let empty = MemoryRegion::default();
        (self.remove_ioctl)(
            self.vm,
            0x4020ae46,
            (&empty as *const MemoryRegion) as libc::c_ulong,
        )
    }
}
impl Drop for SlotGuard {
    fn drop(&mut self) {
        let result = self.remove();
        record(&self.sink, result);
    }
}
impl Mapping {
    fn new(length: usize, fd: i32, flags: i32, sink: &Cleanup) -> io::Result<Self> {
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                fd,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            pointer,
            length,
            sink: sink.clone(),
        })
    }
    fn close(&mut self) -> io::Result<()> {
        if self.length == 0 {
            return Ok(());
        }
        if unsafe { libc::munmap(self.pointer, self.length) } != 0 {
            return Err(io::Error::last_os_error());
        }
        self.length = 0;
        Ok(())
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        let result = self.close();
        record(&self.sink, result);
    }
}

pub(crate) struct ChildReport {
    pub primary_errno: Option<i32>,
    pub cleanup_errno: Option<i32>,
}
impl ChildReport {
    pub fn passed(&self) -> bool {
        self.primary_errno.is_none() && self.cleanup_errno.is_none()
    }
}
fn close(fd: impl IntoRawFd) -> io::Result<()> {
    if unsafe { libc::close(fd.into_raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
fn remember(first: &mut Option<i32>, result: io::Result<impl Sized>) {
    if let Err(error) = result {
        first.get_or_insert(error.raw_os_error().unwrap_or(libc::EIO));
    }
}
pub(crate) fn child() -> io::Result<ChildReport> {
    let sink = Rc::new(Cell::new(None));
    let result = execute(&sink);
    Ok(match result {
        Ok(mut report) => {
            if report.cleanup_errno.is_none() {
                report.cleanup_errno = sink.get();
            }
            report
        }
        Err(error) => ChildReport {
            primary_errno: Some(error.raw_os_error().unwrap_or(libc::EIO)),
            cleanup_errno: sink.get(),
        },
    })
}
fn execute(sink: &Cleanup) -> io::Result<ChildReport> {
    let rejected = || io::Error::from_raw_os_error(libc::EPERM);
    let user = crate::identity::current()
        .filter(|user| user.valid())
        .ok_or_else(rejected)?;
    let kvm = Tracked::new(
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/dev/kvm")?,
        sink,
    );
    let metadata = kvm.metadata()?;
    if !metadata.file_type().is_char_device()
        || metadata.gid() != user.kvm_gid
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o660
        || libc::major(metadata.rdev()) != 10
        || libc::minor(metadata.rdev()) != 232
    {
        return Err(rejected());
    }
    execute_device(kvm, sink, ioctl, Mapping::new)
}

// Native entry supplies only the fixed syscall functions above. Unit tests
// substitute resource-producing backends without opening /dev/kvm.
fn execute_device(
    kvm: Tracked<std::fs::File>,
    sink: &Cleanup,
    ioctl: Ioctl,
    map: Map,
) -> io::Result<ChildReport> {
    let rejected = || io::Error::from_raw_os_error(libc::EPERM);
    if ioctl(kvm.as_raw_fd(), 0xae00, 0)? != 12 {
        return Err(rejected());
    }
    for capability in [3, 4, 10, 136] {
        if ioctl(kvm.as_raw_fd(), 0xae03, capability)? < 1 {
            return Err(rejected());
        }
    }
    let length = ioctl(kvm.as_raw_fd(), 0xae04, 0)? as usize;
    if !(4096..=1024 * 1024).contains(&length) {
        return Err(rejected());
    }
    let vm = Tracked::new(
        unsafe { OwnedFd::from_raw_fd(ioctl(kvm.as_raw_fd(), 0xae01, 0)?) },
        sink,
    );
    ioctl(vm.as_raw_fd(), 0xae47, 0xfffbd000)?;
    let mut ram = map(RAM_BYTES, -1, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, sink)?;
    unsafe {
        std::ptr::copy_nonoverlapping(
            GUEST.as_ptr(),
            ram.pointer.cast::<u8>().add(0x1000),
            GUEST.len(),
        );
    }
    let region = MemoryRegion {
        memory_size: RAM_BYTES as u64,
        userspace_addr: ram.pointer as u64,
        ..MemoryRegion::default()
    };
    // Arm before registration: even a failed registration converges on the
    // same explicit removal attempt while VM and RAM are still alive.
    let mut slot = SlotGuard {
        vm: vm.as_raw_fd(),
        armed: true,
        sink: sink.clone(),
        remove_ioctl: ioctl,
    };
    ioctl(
        vm.as_raw_fd(),
        0x4020ae46,
        (&region as *const MemoryRegion) as libc::c_ulong,
    )?;
    let mut cleanup_errno = None;
    let result = (|| {
        let vcpu = Tracked::new(
            unsafe { OwnedFd::from_raw_fd(ioctl(vm.as_raw_fd(), 0xae41, 0)?) },
            sink,
        );
        let mut run = map(length, vcpu.as_raw_fd(), libc::MAP_SHARED, sink)?;
        let executed = (|| {
            let mut special = SpecialRegisters::default();
            ioctl(
                vcpu.as_raw_fd(),
                0x8138ae83,
                (&mut special as *mut SpecialRegisters) as libc::c_ulong,
            )?;
            special.segments[0].base = 0;
            special.segments[0].selector = 0;
            special.cr0 &= !1;
            ioctl(
                vcpu.as_raw_fd(),
                0x4138ae84,
                (&special as *const SpecialRegisters) as libc::c_ulong,
            )?;
            let mut registers = Registers {
                rip: 0x1000,
                rflags: 2,
                ..Registers::default()
            };
            registers.general[6] = 0x2000;
            ioctl(
                vcpu.as_raw_fd(),
                0x4090ae82,
                (&registers as *const Registers) as libc::c_ulong,
            )?;
            let mut sequence = ExitSequence::default();
            for _ in 0..2 {
                ioctl(vcpu.as_raw_fd(), 0xae80, 0)?;
                let bytes = unsafe { std::slice::from_raw_parts(run.pointer.cast::<u8>(), length) };
                if !sequence.accept(bytes) {
                    return Err(rejected());
                }
            }
            ioctl(
                vcpu.as_raw_fd(),
                0x8090ae81,
                (&mut registers as *mut Registers) as libc::c_ulong,
            )?;
            if !sequence.complete()
                || registers.general[0] & 0xff != 0x2a
                || registers.rip != 0x1005
            {
                return Err(rejected());
            }
            Ok(())
        })();
        remember(&mut cleanup_errno, run.close());
        remember(&mut cleanup_errno, close(vcpu));
        executed
    })();
    let removed = slot.remove();
    drop(slot);
    remember(&mut cleanup_errno, removed);
    remember(&mut cleanup_errno, close(vm));
    let unmapped = ram.close();
    remember(&mut cleanup_errno, unmapped);
    remember(&mut cleanup_errno, close(kvm));
    Ok(ChildReport {
        primary_errno: result
            .err()
            .map(|error: io::Error| error.raw_os_error().unwrap_or(libc::EIO)),
        cleanup_errno,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn isolated_resource_test(name: &str) -> bool {
        const CHILD: &str = "TEMPEST_KVM_RESOURCE_TEST_CHILD";
        if std::env::var(CHILD).as_deref() == Ok(name) {
            return false;
        }
        // An unmapped address or closed FD can immediately be reused by an
        // unrelated libtest thread. Observe resource lifetime in its own
        // address space, while retaining the real munmap/close assertions.
        let launch_guard = crate::TEST_CHILD_LAUNCH_LOCK.lock().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--test-threads=1"])
            .env_clear()
            .env(CHILD, name)
            .spawn()
            .unwrap();
        drop(launch_guard);
        let status = child.wait().unwrap();
        assert!(status.success(), "isolated resource test failed: {name}");
        true
    }
    #[derive(Default)]
    struct Fake {
        fail: &'static str,
        hit: bool,
        runs: usize,
        fds: Vec<(i32, u64)>,
        maps: Vec<(usize, usize)>,
    }
    thread_local! { static FAKE: std::cell::RefCell<Fake> = std::cell::RefCell::new(Fake::default()); }
    fn checkpoint(stage: &'static str) -> io::Result<()> {
        FAKE.with(|state| {
            let mut state = state.borrow_mut();
            if state.fail == stage {
                state.hit = true;
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                Ok(())
            }
        })
    }
    fn fake_fd() -> io::Result<i32> {
        let raw = unsafe { libc::memfd_create(c"fixed-kvm-test".as_ptr(), libc::MFD_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { std::fs::File::from_raw_fd(raw) };
        let inode = file.metadata()?.ino();
        FAKE.with(|state| state.borrow_mut().fds.push((raw, inode)));
        Ok(file.into_raw_fd())
    }
    fn fake_ioctl(_fd: i32, request: libc::c_ulong, argument: libc::c_ulong) -> io::Result<i32> {
        let stage = match request {
            0xae00 => "api",
            0xae03 => "extension",
            0xae04 => "map_size",
            0xae01 => "vm",
            0xae47 => "tss",
            0xae41 => "vcpu",
            0x4020ae46 => {
                let region = unsafe { &*(argument as *const MemoryRegion) };
                if region.memory_size == 0 {
                    "slot_remove"
                } else {
                    "slot"
                }
            }
            0x8138ae83 => "sregs_get",
            0x4138ae84 => "sregs_set",
            0x4090ae82 => "regs_set",
            0x8090ae81 => "regs_get",
            0xae80 => FAKE.with(|state| {
                if state.borrow().runs == 0 {
                    "run_io"
                } else {
                    "run_hlt"
                }
            }),
            _ => panic!("unexpected fixed ioctl"),
        };
        checkpoint(stage)?;
        match request {
            0xae00 => Ok(12),
            0xae03 => Ok(1),
            0xae04 => Ok(4096),
            0xae01 | 0xae41 => fake_fd(),
            0x8090ae81 => {
                let registers = unsafe { &mut *(argument as *mut Registers) };
                registers.general[0] = 0x2a;
                registers.rip = 0x1005;
                Ok(0)
            }
            0xae80 => FAKE.with(|state| {
                let mut state = state.borrow_mut();
                let (pointer, length) = *state.maps.last().unwrap();
                let bytes = unsafe { std::slice::from_raw_parts_mut(pointer as *mut u8, length) };
                bytes[8..12]
                    .copy_from_slice(&(if state.runs == 0 { 2_u32 } else { 5 }).to_le_bytes());
                bytes[32] = 1;
                bytes[33] = 1;
                bytes[34..36].copy_from_slice(&0xe9_u16.to_le_bytes());
                bytes[36..40].copy_from_slice(&1_u32.to_le_bytes());
                bytes[40..48].copy_from_slice(&128_u64.to_le_bytes());
                bytes[128] = 0x2a;
                state.runs += 1;
                Ok(0)
            }),
            _ => Ok(0),
        }
    }
    fn fake_map(length: usize, fd: i32, _flags: i32, sink: &Cleanup) -> io::Result<Mapping> {
        checkpoint(if fd == -1 { "ram" } else { "run_map" })?;
        let mapping = Mapping::new(length, -1, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, sink)?;
        FAKE.with(|state| {
            state
                .borrow_mut()
                .maps
                .push((mapping.pointer as usize, length))
        });
        Ok(mapping)
    }
    #[test]
    fn every_initialization_stage_converges_on_real_resource_cleanup() {
        if isolated_resource_test(
            "runtime::tests::every_initialization_stage_converges_on_real_resource_cleanup",
        ) {
            return;
        }
        for stage in [
            "",
            "api",
            "extension",
            "map_size",
            "vm",
            "tss",
            "ram",
            "slot",
            "vcpu",
            "run_map",
            "sregs_get",
            "sregs_set",
            "regs_set",
            "run_io",
            "run_hlt",
            "regs_get",
            "slot_remove",
        ] {
            FAKE.with(|state| {
                *state.borrow_mut() = Fake {
                    fail: stage,
                    ..Fake::default()
                }
            });
            let sink = Rc::new(Cell::new(None));
            // Track the initial device substitute alongside VM/vCPU FDs.
            let device = unsafe { std::fs::File::from_raw_fd(fake_fd().unwrap()) };
            let kvm = Tracked::new(device, &sink);
            let result = execute_device(kvm, &sink, fake_ioctl, fake_map);
            if stage.is_empty() {
                let report = result.unwrap();
                assert_eq!(report.primary_errno, None);
                assert_eq!(report.cleanup_errno, None);
                assert!(report.passed());
            } else {
                FAKE.with(|state| assert!(state.borrow().hit, "stage not reached: {stage}"));
                match result {
                    Ok(report) => {
                        let cleanup_failure = stage == "slot_remove";
                        assert_eq!(
                            report.primary_errno,
                            (!cleanup_failure).then_some(libc::EIO),
                            "primary error after {stage}"
                        );
                        assert_eq!(
                            report.cleanup_errno,
                            cleanup_failure.then_some(libc::EIO),
                            "cleanup error after {stage}"
                        );
                        assert!(!report.passed());
                    }
                    Err(error) => {
                        assert_ne!(stage, "slot_remove");
                        assert_eq!(error.raw_os_error(), Some(libc::EIO));
                    }
                }
            }
            assert_eq!(
                sink.get(),
                None,
                "unexpected guard cleanup error after {stage}"
            );
            FAKE.with(|state| {
                let state = state.borrow();
                for &(fd, inode) in &state.fds {
                    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
                    let result = unsafe { libc::fstat(fd, metadata.as_mut_ptr()) };
                    assert!(result == -1 || unsafe { metadata.assume_init() }.st_ino != inode);
                }
                for &(address, length) in &state.maps {
                    let mut vector = vec![0; length.div_ceil(4096)];
                    let result =
                        unsafe { libc::mincore(address as *mut _, length, vector.as_mut_ptr()) };
                    let errno = io::Error::last_os_error().raw_os_error();
                    assert_eq!(result, -1, "mapping retained after {stage}");
                    assert_eq!(errno, Some(libc::ENOMEM));
                }
            });
        }
    }
    #[test]
    fn early_failure_closes_registered_fd_and_unmaps_memory() {
        if isolated_resource_test(
            "runtime::tests::early_failure_closes_registered_fd_and_unmaps_memory",
        ) {
            return;
        }
        let sink = Rc::new(Cell::new(None));
        let mut observed_fd = -1;
        let mut address = std::ptr::null_mut();
        let result = (|| -> io::Result<()> {
            let tracked = Tracked::new(std::fs::File::open("/dev/null")?, &sink);
            observed_fd = tracked.as_raw_fd();
            let mapping = Mapping::new(4096, -1, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, &sink)?;
            address = mapping.pointer;
            let mut residency = 0_u8;
            assert_eq!(unsafe { libc::mincore(address, 4096, &mut residency) }, 0);
            Err(io::Error::from_raw_os_error(libc::EPERM))
        })();
        let mut residency = 0_u8;
        let mapped = unsafe { libc::mincore(address, 4096, &mut residency) };
        let errno = io::Error::last_os_error().raw_os_error();
        assert_eq!(mapped, -1);
        assert_eq!(errno, Some(libc::ENOMEM));
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EPERM));
        assert_eq!(unsafe { libc::fcntl(observed_fd, libc::F_GETFD) }, -1);
        assert_eq!(sink.get(), None);
    }
    #[test]
    fn failed_unmap_is_recorded_and_does_not_hide_live_mapping() {
        let sink = Rc::new(Cell::new(None));
        let mut mapping =
            Mapping::new(4096, -1, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, &sink).unwrap();
        let original = mapping.pointer;
        // Fixed invalid alignment forces munmap EINVAL; no device access.
        mapping.pointer = unsafe { original.cast::<u8>().add(1).cast() };
        drop(mapping);
        let mut residency = 0_u8;
        let still_mapped = unsafe { libc::mincore(original, 4096, &mut residency) };
        let recovered = unsafe { libc::munmap(original, 4096) };
        assert_eq!(sink.get(), Some(libc::EINVAL));
        assert_eq!(still_mapped, 0);
        assert_eq!(recovered, 0);
    }
    #[test]
    fn slot_registration_failure_attempts_cleanup_and_preserves_primary() {
        let sink = Rc::new(Cell::new(None));
        let fd = std::fs::File::open("/dev/null").unwrap();
        let fail_registration = || -> io::Result<()> {
            let _slot = SlotGuard {
                vm: fd.as_raw_fd(),
                armed: true,
                sink: sink.clone(),
                remove_ioctl: ioctl,
            };
            Err(io::Error::from_raw_os_error(libc::EPERM))
        };
        let primary = fail_registration().unwrap_err();
        assert_eq!(primary.raw_os_error(), Some(libc::EPERM));
        assert_eq!(sink.get(), Some(libc::ENOTTY));
        assert!(fd.metadata().is_ok());
    }
    #[test]
    fn cleanup_fault_does_not_replace_primary_fault_or_become_success() {
        let mut cleanup = None;
        remember(
            &mut cleanup,
            Err::<(), _>(io::Error::from_raw_os_error(libc::EIO)),
        );
        remember(
            &mut cleanup,
            Err::<(), _>(io::Error::from_raw_os_error(libc::EBADF)),
        );
        let report = ChildReport {
            primary_errno: Some(libc::EPERM),
            cleanup_errno: cleanup,
        };
        assert_eq!(report.primary_errno, Some(libc::EPERM));
        assert_eq!(report.cleanup_errno, Some(libc::EIO));
        assert!(!report.passed());
    }
}
