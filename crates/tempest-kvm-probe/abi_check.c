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
