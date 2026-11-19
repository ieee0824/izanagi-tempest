#define _GNU_SOURCE
/* Fixed IPv4 loopback policy for the local isolation fixture. */
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/magic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <errno.h>

enum { CONNECT4_INSTRUCTION_COUNT = 8 };

#define LOAD_FIELD(field)                                                    \
    { .code = BPF_LDX | BPF_MEM | BPF_W, .dst_reg = BPF_REG_2,                 \
      .src_reg = BPF_REG_1, .off = offsetof(struct bpf_sock_addr, field) }
#define REJECT_UNLESS(value, skip)                                           \
    { .code = BPF_JMP | BPF_JNE | BPF_K, .dst_reg = BPF_REG_2,                 \
      .off = skip, .imm = (int32_t)(value) }
#define VERDICT(value)                                                       \
    { .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = value }

int build_connect4_policy(uint16_t listener_port,
                          struct bpf_insn output[static CONNECT4_INSTRUCTION_COUNT])
{
    if (listener_port == 0)
        return -1;

    /* Failed comparisons land at the deny verdict at instruction 6. */
    const struct bpf_insn instructions[CONNECT4_INSTRUCTION_COUNT] = {
        LOAD_FIELD(user_ip4),
        REJECT_UNLESS(htonl(INADDR_LOOPBACK), 4),
        LOAD_FIELD(user_port),
        REJECT_UNLESS(htons(listener_port), 2),
        VERDICT(1),
        { .code = BPF_JMP | BPF_EXIT },
        VERDICT(0),
        { .code = BPF_JMP | BPF_EXIT },
    };
    memcpy(output, instructions, sizeof(instructions));
    return 0;
}

/* The controller must keep the worker stopped until attach and pin are
 * independently verified. These helpers never release a worker. */

static int bpf_call(enum bpf_cmd command, union bpf_attr *attr)
{
    return (int)syscall(SYS_bpf, command, attr, sizeof(*attr));
}

int load_connect4_policy(uint16_t listener_port)
{
    struct bpf_insn instructions[CONNECT4_INSTRUCTION_COUNT];
    if (build_connect4_policy(listener_port, instructions) != 0) {
        errno = EINVAL;
        return -1;
    }

    static const char license[] = "GPL";
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        .expected_attach_type = BPF_CGROUP_INET4_CONNECT,
        .insn_cnt = CONNECT4_INSTRUCTION_COUNT,
        .insns = (uintptr_t)instructions,
        .license = (uintptr_t)license,
    };
    return bpf_call(BPF_PROG_LOAD, &attr);
}

int attach_connect4_policy(int program_fd, int cgroup_fd)
{
    if (program_fd < 0 || cgroup_fd < 0) {
        errno = EBADF;
        return -1;
    }
    union bpf_attr attr = {
        .link_create = {
            .prog_fd = (uint32_t)program_fd,
            .target_fd = (uint32_t)cgroup_fd,
            .attach_type = BPF_CGROUP_INET4_CONNECT,
        },
    };
    return bpf_call(BPF_LINK_CREATE, &attr);
}

/* BPF_OBJ_PIN fails with EEXIST on an occupied path. The controller must
 * resolve the path under its private bpffs directory before calling this. */
int pin_connect4_link(int link_fd, const char *path)
{
    if (link_fd < 0 || path == NULL || *path != '/') {
        errno = EINVAL;
        return -1;
    }
    union bpf_attr attr = {
        .pathname = (uintptr_t)path,
        .bpf_fd = (uint32_t)link_fd,
    };
    return bpf_call(BPF_OBJ_PIN, &attr);
}

/* Use the recorded IDs both before releasing the worker and during recovery.
 * The caller must additionally bind the open cgroup directory to its ledger. */
int check_connect4_link(int fd, uint32_t link_id, uint32_t program_id,
                        uint64_t cgroup_id)
{
    if (fd < 0 || link_id == 0 || program_id == 0 || cgroup_id == 0) {
        errno = EINVAL;
        return -1;
    }
    struct bpf_link_info info = {0};
    union bpf_attr attr = {
        .info = {
            .bpf_fd = (uint32_t)fd,
            .info_len = sizeof(info),
            .info = (uintptr_t)&info,
        },
    };
    if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attr) != 0)
        return -1;

    if (attr.info.info_len <
            offsetof(struct bpf_link_info, cgroup.attach_type) +
                sizeof(info.cgroup.attach_type) ||
        info.type != BPF_LINK_TYPE_CGROUP || info.id != link_id ||
        info.prog_id != program_id || info.cgroup.cgroup_id != cgroup_id ||
        info.cgroup.attach_type != BPF_CGROUP_INET4_CONNECT) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

/* Recovery takes ownership of the returned FD only after matching the ledger.
 * The private directory and serialization are the caller's responsibility. */
int reopen_connect4_link(const char *path, uint32_t link_id,
                         uint32_t program_id, uint64_t cgroup_id)
{
    if (path == NULL || *path != '/') {
        errno = EINVAL;
        return -1;
    }
    union bpf_attr attr = {
        .pathname = (uintptr_t)path,
    };
    int fd = bpf_call(BPF_OBJ_GET, &attr);
    if (fd < 0)
        return -1;
    if (check_connect4_link(fd, link_id, program_id, cgroup_id) == 0)
        return fd;

    int error = errno;
    close(fd);
    errno = error;
    return -1;
}

/* Capture this from the original program FD, before link creation. */
int read_connect4_program_id(int program_fd, uint32_t *program_id)
{
    if (program_fd < 0 || program_id == NULL) {
        errno = EINVAL;
        return -1;
    }
    *program_id = 0;
    struct bpf_prog_info info = {0};
    union bpf_attr attr = {
        .info = {
            .bpf_fd = (uint32_t)program_fd,
            .info_len = sizeof(info),
            .info = (uintptr_t)&info,
        },
    };
    if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attr) != 0)
        return -1;
    if (attr.info.info_len < offsetof(struct bpf_prog_info, id) + sizeof(info.id) ||
        info.type != BPF_PROG_TYPE_CGROUP_SOCK_ADDR || info.id == 0) {
        errno = ESTALE;
        return -1;
    }
    *program_id = info.id;
    return 0;
}

/* On the fixed Linux/x86_64 host the cgroup v2 kernfs inode provides the
 * cgroup ID. Keep the directory FD open and retain the device for recovery. */
int read_connect4_cgroup_identity(int cgroup_fd, dev_t *device, uint64_t *id)
{
    if (cgroup_fd < 0 || device == NULL || id == NULL) {
        errno = EINVAL;
        return -1;
    }
    struct stat metadata;
    struct statfs filesystem;
    if (fstat(cgroup_fd, &metadata) < 0 || fstatfs(cgroup_fd, &filesystem) < 0)
        return -1;
    if (!S_ISDIR(metadata.st_mode) ||
        filesystem.f_type != CGROUP2_SUPER_MAGIC ||
        metadata.st_uid != 0 || (metadata.st_mode & 0022) != 0 ||
        metadata.st_ino == 0) {
        errno = ESTALE;
        return -1;
    }
    *device = metadata.st_dev;
    *id = metadata.st_ino;
    return 0;
}
