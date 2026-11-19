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
#include <fcntl.h>
#include <sys/file.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>

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

/* The recovery caller holds the lease preventing further worker admission. */
int check_connect4_cgroup_empty(int cgroup_fd, dev_t device, uint64_t id)
{
    dev_t current_device;
    uint64_t current_id;
    if (read_connect4_cgroup_identity(cgroup_fd, &current_device, &current_id) < 0)
        return -1;
    if (current_device != device || current_id != id) {
        errno = ESTALE;
        return -1;
    }
    int events = openat(cgroup_fd, "cgroup.events", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (events < 0)
        return -1;

    char data[256];
    size_t count = 0;
    unsigned interruptions = 0;
    while (count < sizeof(data)) {
        ssize_t received = read(events, data + count, sizeof(data) - count);
        if (received == 0)
            break;
        if (received < 0) {
            if (errno == EINTR && interruptions++ < 8)
                continue;
            int error = errno;
            close(events);
            errno = error;
            return -1;
        }
        count += (size_t)received;
    }
    close(events);
    if (count == sizeof(data)) {
        errno = EOVERFLOW;
        return -1;
    }
    if (count == 0 || data[count - 1] != '\n') {
        errno = EPROTO;
        return -1;
    }

    int populated = -1;
    for (const char *line = data; line < data + count;) {
        const char *end = memchr(line, '\n', (size_t)(data + count - line));
        if (end - line >= 10 && memcmp(line, "populated ", 10) == 0) {
            if (populated != -1 || end - line != 11 ||
                (line[10] != '0' && line[10] != '1')) {
                errno = EPROTO;
                return -1;
            }
            populated = line[10] - '0';
        }
        line = end + 1;
    }
    if (populated != 0) {
        errno = populated < 0 ? EPROTO : EBUSY;
        return -1;
    }
    return 0;
}

/* The controller holds the admission gate closed and has recorded the
 * recovery identities before calling this. Failure after pin keeps the pin
 * for recovery. Success returns a second, independently opened link FD. */
int pin_and_verify_connect4_link(int link_fd, const char *path, int cgroup_fd,
                                 dev_t device, uint64_t cgroup_id,
                                 uint32_t link_id, uint32_t program_id)
{
    dev_t actual_device;
    uint64_t actual_cgroup_id;
    if (read_connect4_cgroup_identity(cgroup_fd, &actual_device,
                                     &actual_cgroup_id) < 0)
        return -1;
    if (actual_device != device || actual_cgroup_id != cgroup_id) {
        errno = ESTALE;
        return -1;
    }
    if (check_connect4_link(link_fd, link_id, program_id, cgroup_id) < 0 ||
        pin_connect4_link(link_fd, path) < 0)
        return -1;
    return reopen_connect4_link(path, link_id, program_id, cgroup_id);
}

static int confirm_worker_exit(int worker_pidfd)
{
    if (worker_pidfd < 0) {
        errno = EBADF;
        return -1;
    }
    struct pollfd worker = { .fd = worker_pidfd, .events = POLLIN };
    int ready = poll(&worker, 1, 0);
    if (ready < 0)
        return -1;
    if (ready != 1 || !(worker.revents & POLLIN) ||
        (worker.revents & (POLLERR | POLLNVAL))) {
        errno = EBUSY;
        return -1;
    }

    return 0;
}

/* Both admission and recovery must independently open this same immutable
 * lock entry in the root-owned fixture state directory. Never unlink it. */
int acquire_connect4_lease(int state_fd)
{
    struct stat directory;
    if (fstat(state_fd, &directory) < 0)
        return -1;
    if (!S_ISDIR(directory.st_mode) || directory.st_uid != 0 ||
        (directory.st_mode & 07777) != 0700) {
        errno = ESTALE;
        return -1;
    }
    int lease = openat(state_fd, "admission.lock",
                       O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (lease < 0)
        return -1;
    struct stat metadata;
    if (fstat(lease, &metadata) < 0)
        goto fail;
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != 0 ||
        (metadata.st_mode & 07777) != 0600 || metadata.st_nlink != 1) {
        errno = ESTALE;
        goto fail;
    }
    if (flock(lease, LOCK_EX | LOCK_NB) < 0)
        goto fail;
    return lease;

fail:
    {
        int error = errno;
        close(lease);
        errno = error;
        return -1;
    }
}

/* State is per trial. Keep this marker until the state directory is retired.
 * Persist it before writing the token that permits the worker to connect. */
static int record_release_intent(int state_fd)
{
    int marker = openat(state_fd, "release-intent",
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                        0600);
    if (marker < 0)
        return -1;
    if (close(marker) < 0)
        return -1;
    return fsync(state_fd);
}

static int confirm_release_state(int state_fd, int worker_pidfd)
{
    struct stat marker;
    if (fstatat(state_fd, "release-intent", &marker, AT_SYMLINK_NOFOLLOW) == 0)
        return confirm_worker_exit(worker_pidfd);
    if (errno != ENOENT)
        return -1;
    // No release token could have been sent. Cgroup emptiness is still required.
    return 0;
}

/* After release intent, require the original pidfd even if the controller
 * lost the result of the release operation. */
int recover_connect4_pin(int state_fd, const char *path, int worker_pidfd,
                         int cgroup_fd, dev_t device, uint64_t cgroup_id,
                         uint32_t link_id, uint32_t program_id)
{
    int lease = acquire_connect4_lease(state_fd);
    if (lease < 0)
        return -1;

    /* The independent manager retained this pidfd before admission.
     * A live worker is stopped even when admission never succeeded. The
     * manager retries EBUSY within its recovery deadline, leaving the pin. */
    int result = 0;
    if (worker_pidfd >= 0 &&
        syscall(SYS_pidfd_send_signal, worker_pidfd, SIGKILL, NULL, 0) < 0 &&
        errno != ESRCH)
        result = -1;
    if (result == 0 && worker_pidfd >= 0)
        result = confirm_worker_exit(worker_pidfd);
    if (result == 0)
        result = confirm_release_state(state_fd, worker_pidfd);
    int link = -1;
    if (result == 0) {
        link = reopen_connect4_link(path, link_id, program_id, cgroup_id);
        if (link < 0)
            result = -1;
    }
    if (result == 0)
        result = check_connect4_cgroup_empty(cgroup_fd, device, cgroup_id);
    if (result == 0)
        result = unlink(path);

    int error = errno;
    if (link >= 0)
        close(link);
    close(lease);
    if (result < 0)
        errno = error;
    return result;
}

/* The manager owns the worker and holds its original pidfd. Gate FD is
 * a private pipe write end that only the manager can use. */
int release_connect4_worker(int state_fd, int gate_fd, int worker_pidfd,
                            int link_fd,
                            const char *path, int cgroup_fd, dev_t device,
                            uint64_t cgroup_id, uint32_t link_id,
                            uint32_t program_id)
{
    int lease = acquire_connect4_lease(state_fd);
    if (lease < 0)
        return -1;

    siginfo_t status = {0};
    int verified = -1;
    if (worker_pidfd < 0) {
        errno = EBADF;
    } else if (waitid(P_PIDFD, (id_t)worker_pidfd, &status,
                      WEXITED | WNOHANG | WNOWAIT) == 0) {
        if (status.si_pid != 0)
            errno = ESRCH;
        else
            verified = pin_and_verify_connect4_link(link_fd, path, cgroup_fd,
                                                     device, cgroup_id, link_id,
                                                     program_id);
    }
    int result = -1;
    if (verified >= 0 && record_release_intent(state_fd) == 0) {
        const char token = 'R';
        ssize_t sent = write(gate_fd, &token, sizeof(token));
        if (sent == 1)
            result = 0;
        else if (sent == 0)
            errno = EIO;
    }
    int error = errno;
    if (verified >= 0)
        close(verified);
    close(lease);
    if (result < 0)
        errno = error;
    return result;
}

/* The manager forks the blocked worker before acquiring a lease. It retains
 * the returned pidfd and the exclusive gate write end.
 * The controller and worker must not inherit the manager's recovery lease. */
int retain_connect4_worker(pid_t child)
{
    if (child <= 0) {
        errno = EINVAL;
        return -1;
    }
    int fd = (int)syscall(SYS_pidfd_open, child, 0);
    if (fd < 0)
        return -1;
    siginfo_t status = {0};
    int checked = waitid(P_PIDFD, (id_t)fd, &status,
                         WEXITED | WNOHANG | WNOWAIT);
    if (checked == 0 && status.si_pid == 0)
        return fd;
    int error = checked < 0 ? errno : ESRCH;
    close(fd);
    errno = error;
    return -1;
}
