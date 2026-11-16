#include <stddef.h>
#include <linux/kvm.h>
_Static_assert(sizeof(struct kvm_regs) == 144, "regs");
_Static_assert(sizeof(struct kvm_segment) == 24, "segment");
_Static_assert(sizeof(struct kvm_dtable) == 16, "dtable");
_Static_assert(sizeof(struct kvm_sregs) == 312, "sregs");
_Static_assert(sizeof(struct kvm_userspace_memory_region) == 32, "memory");
_Static_assert(offsetof(struct kvm_run, exit_reason) == 8, "exit_reason");
_Static_assert(offsetof(struct kvm_run, io) == 32, "io");
_Static_assert(offsetof(struct kvm_run, io.data_offset) == 40, "io_data");
_Static_assert(KVM_EXIT_IO == 2 && KVM_EXIT_HLT == 5, "exit constants");
#define OFFSET(type, field, value) _Static_assert(offsetof(struct type, field) == value, #type "." #field)
OFFSET(kvm_regs, rax, 0);
OFFSET(kvm_regs, rsp, 48);
OFFSET(kvm_regs, rip, 128);
OFFSET(kvm_regs, rflags, 136);
OFFSET(kvm_sregs, cs, 0);
OFFSET(kvm_sregs, cr0, 224);
OFFSET(kvm_userspace_memory_region, slot, 0);
OFFSET(kvm_userspace_memory_region, flags, 4);
OFFSET(kvm_userspace_memory_region, guest_phys_addr, 8);
OFFSET(kvm_userspace_memory_region, memory_size, 16);
OFFSET(kvm_userspace_memory_region, userspace_addr, 24);
_Static_assert(KVM_GET_REGS == 0x8090ae81 && KVM_SET_REGS == 0x4090ae82, "regs ioctl");
_Static_assert(KVM_GET_SREGS == 0x8138ae83 && KVM_SET_SREGS == 0x4138ae84, "sregs ioctl");
_Static_assert(KVM_SET_USER_MEMORY_REGION == 0x4020ae46, "memory ioctl");
