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
}
impl SlotGuard {
    fn remove(&mut self) -> io::Result<i32> {
        if !self.armed {
            return Ok(0);
        }
        self.armed = false;
        let empty = MemoryRegion::default();
        ioctl(
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
    let mut ram = Mapping::new(RAM_BYTES, -1, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, sink)?;
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
        let mut run = Mapping::new(length, vcpu.as_raw_fd(), libc::MAP_SHARED, sink)?;
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
    #[test]
    fn early_failure_closes_registered_fd_and_unmaps_memory() {
        let sink = Rc::new(Cell::new(None));
        let mut observed_fd = -1;
        let result = (|| -> io::Result<()> {
            let tracked = Tracked::new(std::fs::File::open("/dev/null")?, &sink);
            observed_fd = tracked.as_raw_fd();
            let _mapping = Mapping::new(4096, -1, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, &sink)?;
            Err(io::Error::from_raw_os_error(libc::EPERM))
        })();
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EPERM));
        assert_eq!(unsafe { libc::fcntl(observed_fd, libc::F_GETFD) }, -1);
        assert_eq!(sink.get(), None);
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
