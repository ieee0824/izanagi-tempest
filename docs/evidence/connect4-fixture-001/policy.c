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
#include <dirent.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <poll.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <time.h>
#include <stdio.h>
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

/* Capture the link ID from the original attach FD, after checking it
 * against the program and cgroup identities supplied by the manager. */
int read_connect4_link_id(int fd, uint32_t program_id, uint64_t cgroup_id,
                          uint32_t *link_id)
{
    if (fd < 0 || program_id == 0 || cgroup_id == 0 || link_id == NULL) {
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
        info.type != BPF_LINK_TYPE_CGROUP || info.id == 0 ||
        info.prog_id != program_id || info.cgroup.cgroup_id != cgroup_id ||
        info.cgroup.attach_type != BPF_CGROUP_INET4_CONNECT) {
        errno = ESTALE;
        return -1;
    }
    *link_id = info.id;
    return 0;
}

int check_connect4_link(int fd, uint32_t link_id, uint32_t program_id,
                        uint64_t cgroup_id)
{
    uint32_t actual_id;
    if (read_connect4_link_id(fd, program_id, cgroup_id, &actual_id) < 0)
        return -1;
    if (actual_id != link_id) {
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
                                 uint32_t link_id, uint32_t program_id,
                                 int *pinned)
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
    *pinned = 1;
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

/* Use the PID captured alongside the original pidfd by the manager.
 * The caller checks that the worker is live before and after this observation
 * and holds the lease that controls cgroup movement. */
static int check_connect4_worker_membership(int cgroup_fd, pid_t child)
{
    if (child <= 0) {
        errno = EINVAL;
        return -1;
    }
    int fd = openat(cgroup_fd, "cgroup.procs", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    FILE *members = fdopen(fd, "r");
    if (!members) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    char expected[32];
    int length = snprintf(expected, sizeof(expected), "%ld\n", (long)child);
    char line[32];
    int error = ENOENT;
    unsigned matches = 0;
    for (unsigned n = 0; n < 256; ++n) {
        if (!fgets(line, sizeof(line), members)) {
            if (ferror(members))
                error = EIO;
            else if (matches == 1)
                error = 0;
            break;
        }
        if (!strchr(line, '\n')) {
            error = EPROTO;
            break;
        }
        if (length > 0 && strcmp(line, expected) == 0) {
            if (++matches > 1) {
                error = EPROTO;
                break;
            }
        }
        error = EOVERFLOW;
    }
    fclose(members);
    if (error != 0) {
        errno = error;
        return -1;
    }
    return 0;
}

/* Both PID views come from the manager's host procfs. */
static int check_connect4_pidfd_pid(int pidfd, pid_t child)
{
    char path[64], expected[32], line[128];
    if (pidfd < 0 || child <= 0) {
        errno = EINVAL;
        return -1;
    }
    snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);
    snprintf(expected, sizeof(expected), "Pid:\t%ld\n", (long)child);
    FILE *info = fopen(path, "re");
    if (!info)
        return -1;
    unsigned matches = 0;
    int valid = 0;
    for (unsigned n = 0; n < 32; ++n) {
        if (!fgets(line, sizeof(line), info)) {
            valid = feof(info) && !ferror(info) && matches == 1;
            break;
        }
        if (!strchr(line, '\n'))
            break;
        if (strncmp(line, "Pid:", 4) == 0) {
            if (strcmp(line, expected) != 0 || ++matches != 1)
                break;
        }
    }
    fclose(info);
    if (!valid) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int empty_supplementary_groups(const char *value)
{
    value += strspn(value, " \t");
    return strcmp(value, "\n") == 0;
}

static int check_connect4_worker_privileges(pid_t child)
{
    static const char *const required[] = {
        "Uid:\t62004\t62004\t62004\t62004\n",
        "Gid:\t62004\t62004\t62004\t62004\n",
        "Groups:\t\n",
        "CapInh:\t0000000000000000\n",
        "CapPrm:\t0000000000000000\n",
        "CapEff:\t0000000000000000\n",
        "CapBnd:\t0000000000000000\n",
        "CapAmb:\t0000000000000000\n",
        "NoNewPrivs:\t1\n",
        "Seccomp:\t2\n",
        "Threads:\t1\n",
    };
    char path[64], line[1024];
    snprintf(path, sizeof(path), "/proc/%ld/status", (long)child);
    FILE *status = fopen(path, "re");
    if (!status)
        return -1;
    unsigned seen = 0;
    int accepted = 0;
    const unsigned fields = sizeof(required) / sizeof(required[0]);
    for (unsigned n = 0; n < 128; ++n) {
        if (!fgets(line, sizeof(line), status)) {
            accepted = feof(status) && !ferror(status) &&
                seen == (1U << fields) - 1U;
            break;
        }
        if (!strchr(line, '\n'))
            break;
        for (unsigned field = 0; field < fields; ++field) {
            size_t key = strcspn(required[field], ":") + 1;
            if (strncmp(line, required[field], key) != 0)
                continue;
            int matches = strcmp(required[field], "Groups:\t\n") == 0
                ? empty_supplementary_groups(line + key)
                : strcmp(line, required[field]) == 0;
            if ((seen & (1U << field)) || !matches) {
                fprintf(stderr, "worker status field=%.*s reason=%s\n",
                        (int)(key - 1), required[field],
                        (seen & (1U << field)) ? "duplicate" : "mismatch");
                goto done;
            }
            seen |= 1U << field;
            break;
        }
    }
done:
    fclose(status);
    if (!accepted) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static int check_worker_pipe_direction(pid_t child, int fd, int direction)
{
    char path[64], line[128];
    snprintf(path, sizeof(path), "/proc/%ld/fdinfo/%d", (long)child, fd);
    FILE *info = fopen(path, "re");
    if (!info)
        return -1;
    int found = 0;
    int valid = 0;
    for (unsigned n = 0; n < 32; ++n) {
        if (!fgets(line, sizeof(line), info)) {
            valid = feof(info) && !ferror(info) && found;
            break;
        }
        if (!strchr(line, '\n'))
            break;
        if (strncmp(line, "flags:", 6) == 0) {
            unsigned flags;
            int consumed;
            if (found || sscanf(line + 6, "%o%n", &flags, &consumed) != 1 ||
                strcmp(line + 6 + consumed, "\n") != 0 ||
                (flags & (O_PATH | O_ACCMODE)) != (unsigned)direction)
                break;
            found = 1;
        }
    }
    fclose(info);
    if (!valid) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

static int check_pipe_end(int fd, int direction, struct stat *identity)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fstat(fd, identity) < 0)
        return -1;
    if ((flags & (O_PATH | O_ACCMODE)) != direction || !S_ISFIFO(identity->st_mode)) {
        errno = ESTALE;
        return -1;
    }
    return 0;
}

struct worker_pipe {
    int child_fd;
    int child_direction;
    int parent_fd;
    int parent_direction;
};

static int check_worker_pipes(pid_t child, const struct worker_pipe *pipes, size_t count)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/fd", (long)child);
    DIR *table = opendir(path);
    if (!table)
        return -1;

    size_t found = 0;
    int result = -1;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(table);
        if (!entry) {
            if (errno == 0 && found == count)
                result = 0;
            else if (errno == 0)
                errno = ESTALE;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        const struct worker_pipe *expected = NULL;
        for (size_t i = 0; i < count; ++i) {
            char fd_name[32];
            snprintf(fd_name, sizeof(fd_name), "%d", pipes[i].child_fd);
            if (strcmp(entry->d_name, fd_name) == 0) {
                expected = &pipes[i];
                break;
            }
        }
        if (!expected) {
            errno = ESTALE;
            break;
        }
        struct stat parent_end, child_end;
        if (check_pipe_end(expected->parent_fd, expected->parent_direction, &parent_end) < 0 ||
            fstatat(dirfd(table), entry->d_name, &child_end, 0) < 0)
            break;
        if (!S_ISFIFO(child_end.st_mode) || child_end.st_dev != parent_end.st_dev ||
            child_end.st_ino != parent_end.st_ino) {
            errno = ESTALE;
            break;
        }
        if (check_worker_pipe_direction(child, expected->child_fd, expected->child_direction) < 0)
            break;
        ++found;
    }
    int error = errno;
    closedir(table);
    if (result < 0)
        errno = error;
    return result;
}

static int64_t monotonic_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        return -1;
    return (int64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}

static int poll_before(struct pollfd *fd, int64_t deadline)
{
    for (;;) {
        int64_t now = monotonic_ns();
        if (now < 0)
            return -1;
        if (now >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        int64_t remaining = deadline - now;
        int ready = poll(fd, 1, (int)((remaining + 999999) / 1000000));
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0) {
            if (ready == 0)
                errno = ETIMEDOUT;
            return -1;
        }
        now = monotonic_ns();
        if (now < 0)
            return -1;
        if (now >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        return 0;
    }
}

static int read_before(int fd, void *buffer, size_t size, int64_t deadline)
{
    char *bytes = buffer;
    for (size_t offset = 0; offset < size;) {
        struct pollfd readable = {.fd = fd, .events = POLLIN};
        if (poll_before(&readable, deadline) < 0)
            return -1;
        ssize_t count = read(fd, bytes + offset, size - offset);
        if (count < 0 && (errno == EAGAIN || errno == EINTR))
            continue;
        if (count <= 0) {
            if (count == 0)
                errno = EPIPE;
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

static int write_before(int fd, const void *buffer, size_t size, int64_t deadline)
{
    const char *bytes = buffer;
    for (size_t offset = 0; offset < size;) {
        struct pollfd writable = {.fd = fd, .events = POLLOUT};
        if (poll_before(&writable, deadline) < 0)
            return -1;
        ssize_t count = write(fd, bytes + offset, size - offset);
        if (count < 0 && (errno == EAGAIN || errno == EINTR))
            continue;
        if (count <= 0) {
            if (count == 0)
                errno = EIO;
            return -1;
        }
        offset += (size_t)count;
    }
    return 0;
}

/* The fixed fixture uses Izanagi v3 authenticated frames. The parent and
 * guest authenticate the bytes, while this relay bounds the frame size. */
static int transfer_authenticated_frame(int source, int destination,
                                        unsigned char expected_type, int64_t deadline)
{
    enum { HEADER = 7, TRAILER = 8 + 32, MAX_BODY = 4096 };
    unsigned char frame[HEADER + MAX_BODY + TRAILER];
    if (read_before(source, frame, HEADER, deadline) < 0)
        return -1;
    if (frame[0] != 0xff || frame[1] != 3 || frame[2] != expected_type) {
        errno = EPROTO;
        return -1;
    }
    uint32_t size = (uint32_t)frame[3] | (uint32_t)frame[4] << 8 |
                    (uint32_t)frame[5] << 16 | (uint32_t)frame[6] << 24;
    if (size > MAX_BODY) {
        errno = EMSGSIZE;
        return -1;
    }
    if (read_before(source, frame + HEADER, size + TRAILER, deadline) < 0)
        return -1;
    return write_before(destination, frame, HEADER + size + TRAILER, deadline);
}

/* Only the fixed authenticated Hello/Ready/Exec conversation is relayed.
 * The trusted parent constructs the fixed request and validates the response. */
int relay_fixed_agent_request(int request_fd, int response_fd, int socket_fd, int64_t deadline)
{
    enum { READY = 3, HELLO = 5, EXEC = 6, EXEC_RESULT = 7 };
    if (transfer_authenticated_frame(request_fd, socket_fd, HELLO, deadline) < 0 ||
        transfer_authenticated_frame(socket_fd, response_fd, HELLO, deadline) < 0 ||
        transfer_authenticated_frame(socket_fd, response_fd, READY, deadline) < 0 ||
        transfer_authenticated_frame(request_fd, socket_fd, EXEC, deadline) < 0)
        return -1;
    return transfer_authenticated_frame(socket_fd, response_fd, EXEC_RESULT, deadline);
}

/* The manager has closed its own copy of the readiness write end. */
static int confirm_connect4_ready(int ready_fd)
{
    if (ready_fd < 0) {
        errno = EBADF;
        return -1;
    }
    struct pollfd ready = { .fd = ready_fd, .events = POLLIN };
    int64_t start = monotonic_ns();
    if (start < 0)
        return -1;
    int64_t deadline = start + 2000000000;
    for (unsigned phase = 0; phase < 2; ++phase) {
        if (poll_before(&ready, deadline) < 0)
            return -1;
        if (ready.revents & (POLLERR | POLLNVAL)) {
            errno = EIO;
            return -1;
        }
        char value;
        ssize_t count = read(ready_fd, &value, 1);
        if (count < 0)
            return -1;
        if ((phase == 0 && (count != 1 || value != 'Y')) ||
            (phase == 1 && count != 0)) {
            errno = EPROTO;
            return -1;
        }
    }
    return 0;
}

static int controller_is_live(int controller_pidfd)
{
    if (controller_pidfd < 0) {
        errno = EBADF;
        return -1;
    }
    struct pollfd controller = { .fd = controller_pidfd, .events = POLLIN };
    int ready = poll(&controller, 1, 0);
    if (ready == 0)
        return 0;
    if (ready > 0)
        errno = ECANCELED;
    return -1;
}

/* The manager owns the worker and holds its original pidfd. Gate FD is
 * a private pipe write end that only the manager can use. */
static int stop_test_controller(int controller_pidfd)
{
    if (controller_is_live(controller_pidfd) < 0 ||
        syscall(SYS_pidfd_send_signal, controller_pidfd, SIGKILL, NULL, 0) < 0)
        return -1;
    struct pollfd exit_event = { .fd = controller_pidfd, .events = POLLIN };
    int result = poll(&exit_event, 1, 1000);
    if (result == 1 && (exit_event.revents & POLLIN))
        return 0;
    if (result >= 0)
        errno = result == 0 ? ETIMEDOUT : EIO;
    return -1;
}

static int send_connect4_release(int gate_fd)
{
    const char token = 'R';
    ssize_t sent;
    do {
        sent = write(gate_fd, &token, sizeof(token));
    } while (sent < 0 && errno == EINTR);
    if (sent == 1)
        return 0;
    if (sent == 0)
        errno = EIO;
    return -1;
}

static int release_connect4_worker(int state_fd, int ready_fd,
                            const struct worker_pipe *pipes, size_t pipe_count,
                            int controller_pidfd,
                            pid_t child, int worker_pidfd,
                            int link_fd,
                            const char *path, int cgroup_fd, dev_t device,
                            uint64_t cgroup_id, uint32_t link_id,
                            uint32_t program_id, int *pinned,
                            int stop_before_release)
{
    /* FD 3 is the only channel that can release the worker. */
    if (pipe_count == 0 || pipes[0].child_fd != 3 ||
        pipes[0].child_direction != O_RDONLY || pipes[0].parent_direction != O_WRONLY) {
        errno = EINVAL;
        return -1;
    }
    int gate_fd = pipes[0].parent_fd;

    int lease = acquire_connect4_lease(state_fd);
    if (lease < 0)
        return -1;

    siginfo_t status = {0};
    int verified = -1;
    int result = -1;
    const char *stage = "ready";
    if (confirm_connect4_ready(ready_fd) < 0)
        goto done;
    stage = "child";
    if (waitid(P_PIDFD, (id_t)worker_pidfd, &status,
               WEXITED | WNOHANG | WNOWAIT) < 0)
        goto done;
    if (status.si_pid != 0) {
        errno = ESRCH;
        goto done;
    }
    stage = "pidfd-identity";
    if (check_connect4_pidfd_pid(worker_pidfd, child) < 0)
        goto done;
    stage = "membership";
    if (check_connect4_worker_membership(cgroup_fd, child) < 0)
        goto done;
    stage = "pin-and-reopen";
    verified = pin_and_verify_connect4_link(link_fd, path, cgroup_fd,
                                            device, cgroup_id, link_id,
                                            program_id, pinned);
    if (verified < 0)
        goto done;
    stage = "worker-privileges";
    if (check_connect4_worker_privileges(child) < 0)
        goto done;
    stage = "worker-descriptors";
    if (check_worker_pipes(child, pipes, pipe_count) < 0)
        goto done;
    stage = "membership-recheck";
    if (check_connect4_worker_membership(cgroup_fd, child) < 0)
        goto done;
    stage = "child-recheck";
    if (waitid(P_PIDFD, (id_t)worker_pidfd, &status,
               WEXITED | WNOHANG | WNOWAIT) < 0)
        goto done;
    if (status.si_pid != 0) {
        errno = ESRCH;
        goto done;
    }
    stage = "controller";
    if (stop_before_release) {
        if (stop_test_controller(controller_pidfd) < 0)
            goto done;
        fputs("fault=before-release controller_exit_observed=1\n", stderr);
    }
    if (controller_is_live(controller_pidfd) < 0)
        goto done;
    stage = "release-intent";
    if (record_release_intent(state_fd) < 0)
        goto done;
    stage = "controller-recheck";
    if (controller_is_live(controller_pidfd) < 0)
        goto done;
    stage = "release-token";
    result = send_connect4_release(gate_fd);

done:;
    int error = errno;
    if (result < 0)
        fprintf(stderr, "connect4 release stage=%s errno=%d\n", stage, error);
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

/* The worker calls this after closing inherited management descriptors.
 * EOF on manager failure and expiry both leave the worker unauthorized. */
int await_connect4_release(int gate_fd)
{
    struct pollfd gate = { .fd = gate_fd, .events = POLLIN };
    int ready = poll(&gate, 1, 5000);
    if (ready < 0)
        return -1;
    if (ready == 0) {
        errno = ETIMEDOUT;
        return -1;
    }
    if (!(gate.revents & POLLIN) || (gate.revents & (POLLERR | POLLNVAL))) {
        errno = EPIPE;
        return -1;
    }
    char token;
    ssize_t count = read(gate_fd, &token, sizeof(token));
    if (count < 0)
        return -1;
    if (count != 1 || token != 'R') {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

/* Used only immediately after fork. Any failure requires child exit. */
static int map_fixed_pipes(const int *inherited, size_t count,
                           int preserve_stdio, int descriptor_flags)
{
    enum { FIRST_FD = 3, MAX_PIPES = 5 };
    int temporary[MAX_PIPES];
    if (count == 0 || count > MAX_PIPES) {
        errno = EINVAL;
        return -1;
    }
    unsigned first_unused = FIRST_FD + (unsigned)count;
    for (size_t i = 0; i < count; ++i) {
        temporary[i] = fcntl(inherited[i], F_DUPFD_CLOEXEC, first_unused);
        if (temporary[i] < 0)
            return -1;
    }
    for (size_t i = 0; i < count; ++i) {
        if (dup3(temporary[i], FIRST_FD + (int)i, descriptor_flags) < 0)
            return -1;
    }
    if ((!preserve_stdio && syscall(SYS_close_range, 0U, FIRST_FD - 1U, 0U) < 0) ||
        syscall(SYS_close_range, first_unused, ~0U, 0U) < 0)
        return -1;
    return 0;
}

static int map_worker_pipes(const int *inherited, size_t count)
{
    return map_fixed_pipes(inherited, count, 0, O_CLOEXEC);
}

/* Apply the same fixed privilege drop to probe and relay children. */
static int drop_fixed_privileges(uid_t uid, gid_t gid)
{
    for (unsigned cap = 0; cap <= CAP_LAST_CAP; ++cap) {
        if (prctl(PR_CAPBSET_DROP, (unsigned long)cap, 0UL, 0UL, 0UL) < 0)
            return -1;
    }
    if (setgroups(0, NULL) < 0 || setresgid(gid, gid, gid) < 0 ||
        setresuid(uid, uid, uid) < 0)
        return -1;
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
    };
    struct __user_cap_data_struct capabilities[2] = {0};
    if (syscall(SYS_capset, &header, capabilities) < 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) < 0)
        return -1;
    return 0;
}

static int drop_connect4_worker_privileges(void)
{
    return drop_fixed_privileges(62004, 62004);
}

/* Run only in the dedicated fork child, before the manager takes the lease.
 * On failure the child caller must exit without proceeding to the gate. */
int prepare_connect4_worker(int gate_read_fd, int ready_write_fd)
{
    if (gate_read_fd != 3 || ready_write_fd != 4) {
        errno = EINVAL;
        return -1;
    }
    if (syscall(SYS_close_range, 0U, 2U, 0U) < 0 ||
        syscall(SYS_close_range, 5U, ~0U, 0U) < 0)
        return -1;
    return drop_connect4_worker_privileges();
}

#define GUARD_SYSCALL(number) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, number, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
#define FILTER_ARG(index) \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[index]))
#define FILTER_DENY BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)

/* The cgroup policy constrains the destination. This filter constrains the
 * socket kind and prevents execution or file opens during connect setup. */
int restrict_fixed_relay_setup(void)
{
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        GUARD_SYSCALL(SYS_read),
        GUARD_SYSCALL(SYS_write),
        GUARD_SYSCALL(SYS_poll),
        GUARD_SYSCALL(SYS_clock_gettime),
        GUARD_SYSCALL(SYS_connect),
        GUARD_SYSCALL(SYS_getsockopt),
        GUARD_SYSCALL(SYS_close),
        GUARD_SYSCALL(SYS_seccomp),
        GUARD_SYSCALL(SYS_exit),
        GUARD_SYSCALL(SYS_exit_group),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 1, 0),
        FILTER_DENY,
        FILTER_ARG(0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 0, 5),
        FILTER_ARG(1),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, 3),
        FILTER_ARG(2),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        FILTER_DENY,
    };
    const struct sock_fprog program = {
        .len = sizeof(code) / sizeof(code[0]),
        .filter = code,
    };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
}

/* Install after connecting. Socket creation and further connects are denied. */
int restrict_fixed_relay_io(int request_fd, int response_fd, int socket_fd)
{
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        GUARD_SYSCALL(SYS_poll),
        GUARD_SYSCALL(SYS_exit),
        GUARD_SYSCALL(SYS_exit_group),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clock_gettime, 0, 4),
        FILTER_ARG(0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, CLOCK_MONOTONIC, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        FILTER_DENY,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 0, 5),
        FILTER_ARG(0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, request_fd, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, socket_fd, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        FILTER_DENY,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 5),
        FILTER_ARG(0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, response_fd, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, socket_fd, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        FILTER_DENY,
        FILTER_DENY,
    };
    const struct sock_fprog program = {
        .len = sizeof(code) / sizeof(code[0]),
        .filter = code,
    };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
}

int restrict_connect4_worker(void)
{
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        GUARD_SYSCALL(SYS_read),
        GUARD_SYSCALL(SYS_poll),
        GUARD_SYSCALL(SYS_close),
        GUARD_SYSCALL(SYS_connect),
        GUARD_SYSCALL(SYS_exit),
        GUARD_SYSCALL(SYS_exit_group),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 4),
        FILTER_ARG(0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        FILTER_DENY,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 1, 0),
        FILTER_DENY,
        FILTER_ARG(0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 0, 5),
        FILTER_ARG(1),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SOCK_STREAM | SOCK_CLOEXEC, 0, 3),
        FILTER_ARG(2),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        FILTER_DENY,
    };
    const struct sock_fprog program = {
        .len = sizeof(code) / sizeof(code[0]),
        .filter = code,
    };
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
}

/* The parent waits for the ready byte and EOF before inspecting FD 3. */
int connect4_worker_wait(void)
{
    if (prepare_connect4_worker(3, 4) < 0 || restrict_connect4_worker() < 0)
        return -1;
    const char ready = 'Y';
    ssize_t sent = write(4, &ready, sizeof(ready));
    int closed = close(4);
    if (sent != sizeof(ready) || closed < 0) {
        errno = EIO;
        return -1;
    }
    return await_connect4_release(3);
}

/* A successful connection remains owned by the worker. */
static struct sockaddr_in connect4_loopback_address(uint16_t port)
{
    return (struct sockaddr_in){
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
    };
}

static int connect4_loopback(uint16_t port, int *connected_fd)
{
    *connected_fd = -1;
    const struct sockaddr_in address = connect4_loopback_address(port);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (fd < 0)
        return -1;
    if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) < 0) {
        int error = errno;
        close(fd);
        return error;
    }
    *connected_fd = fd;
    return 0;
}

/* On failure the worker owns no socket and errno identifies the connect fault. */
int open_fixed_relay_connection(uint16_t port, int64_t deadline)
{
    int64_t now = monotonic_ns();
    if (now < 0)
        return -1;
    if (now >= deadline) {
        errno = ETIMEDOUT;
        return -1;
    }
    const struct sockaddr_in address = connect4_loopback_address(port);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP);
    if (fd < 0)
        return -1;
    if (connect(fd, (const struct sockaddr *)&address, sizeof(address)) < 0) {
        if (errno != EINPROGRESS)
            goto fail;
        struct pollfd writable = {.fd = fd, .events = POLLOUT};
        if (poll_before(&writable, deadline) < 0)
            goto fail;
        int error;
        socklen_t length = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) < 0)
            goto fail;
        if (length != sizeof(error) || error != 0) {
            errno = length != sizeof(error) ? EIO : error;
            goto fail;
        }
    }
    now = monotonic_ns();
    if (now >= 0 && now < deadline)
        return fd;
    if (now >= 0)
        errno = ETIMEDOUT;
fail:;
    int error = errno;
    close(fd);
    errno = error;
    return -1;
}

/* Run in the isolated child after mapping its five fixed pipe ends.
 * A failure is terminal. The parent owns recovery and reaping. */
int connect_fixed_relay_worker(uint16_t port, int64_t deadline)
{
    if (restrict_fixed_relay_setup() < 0)
        return -1;
    if (write(4, "Y", 1) != 1 || close(4) < 0 || await_connect4_release(3) < 0)
        return -1;
    if (close(3) < 0)
        return -1;

    int socket_fd = open_fixed_relay_connection(port, deadline);
    int connect_errno = socket_fd < 0 ? errno : 0;
    if (write(7, &connect_errno, sizeof(connect_errno)) != sizeof(connect_errno) ||
        close(7) < 0)
        return -1;
    if (socket_fd < 0) {
        errno = connect_errno;
        return -1;
    }
    if (restrict_fixed_relay_io(5, 6, socket_fd) < 0)
        return -1;
    return socket_fd;
}

/* The caller exits with this result so the worker's remaining descriptors
 * close together. The separate status pipe records the actual connect errno. */
int run_fixed_relay_worker(uint16_t port, int64_t deadline)
{
    int socket_fd = connect_fixed_relay_worker(port, deadline);
    if (socket_fd < 0)
        return 1;
    return relay_fixed_agent_request(5, 6, socket_fd, deadline) == 0 ? 0 : 2;
}

static const char alternate_request[] = "tempest-alternate-dummy-v1";
static const char alternate_response[] = "tempest-alternate-ack-v1";

static int relay_fixed_token(int source, int destination, const char *expected,
                             size_t size, int64_t deadline)
{
    char token[sizeof(alternate_request)];
    if (size > sizeof(token) || read_before(source, token, size, deadline) < 0)
        return -1;
    if (memcmp(token, expected, size) != 0) {
        errno = EPROTO;
        return -1;
    }
    return write_before(destination, token, size, deadline);
}

static int run_fixed_alternate_worker(uint16_t port, int64_t deadline)
{
    int socket_fd = connect_fixed_relay_worker(port, deadline);
    if (socket_fd < 0)
        return 1;
    if (relay_fixed_token(5, socket_fd, alternate_request,
                          sizeof(alternate_request) - 1, deadline) < 0 ||
        relay_fixed_token(socket_fd, 6, alternate_response,
                          sizeof(alternate_response) - 1, deadline) < 0)
        return 2;
    return 0;
}

static int try_connect4_loopback(uint16_t port)
{
    int fd;
    int result = connect4_loopback(port, &fd);
    if (fd >= 0)
        close(fd);
    return result;
}

/* Call in the dedicated child. The manager observes the actual exit status
 * and separately counts accepted connections on both listeners. */
static int run_connect4_worker(uint16_t allowed, uint16_t denied,
                               atomic_int *release_seen)
{
    if (allowed == 0 || denied == 0 || allowed == denied)
        return 70;
    if (connect4_worker_wait() < 0)
        return errno == EPIPE ? 75 : 70;
    if (release_seen != NULL) {
        atomic_store_explicit(release_seen, 1, memory_order_release);
        /* The fault case holds here until the manager closes the gate. */
        (void)await_connect4_release(3);
        /* Give the upper owner a bounded interval to observe adoption and
         * stop a live worker even after the supervisor closes the gate. */
        (void)poll(NULL, 0, 2000);
        return 74;
    }
    if (try_connect4_loopback(allowed) != 0)
        return 71;
    int refused = try_connect4_loopback(denied);
    if (refused == EPERM)
        return 0;
    if (refused == 0)
        return 72;
    if (refused > 0 && refused < 128)
        return 128 + refused;
    return 73;
}

int open_connect4_listener(uint16_t *port)
{
    if (port == NULL) {
        errno = EINVAL;
        return -1;
    }
    *port = 0;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                    IPPROTO_TCP);
    if (fd < 0)
        return -1;
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
    };
    socklen_t length = sizeof(address);
    if (bind(fd, (struct sockaddr *)&address, length) == 0 &&
        listen(fd, 8) == 0 &&
        getsockname(fd, (struct sockaddr *)&address, &length) == 0) {
        *port = ntohs(address.sin_port);
        return fd;
    }
    int error = errno;
    close(fd);
    errno = error;
    return -1;
}

/* Call once the producer for this phase has completed. Each listener is
 * nonblocking, and unexpected traffic beyond the backlog is a test failure. */
int count_connect4_accepts(int listener)
{
    int flags = fcntl(listener, F_GETFL);
    if (flags < 0)
        return -1;
    if (!(flags & O_NONBLOCK)) {
        errno = EINVAL;
        return -1;
    }
    for (int count = 0; count < 16; ++count) {
        int accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        if (accepted < 0)
            return errno == EAGAIN || errno == EWOULDBLOCK ? count : -1;
        close(accepted);
    }
    errno = EOVERFLOW;
    return -1;
}

struct connect4_phase {
    int allowed_accepts;
    int denied_accepts;
    int worker_code;
    int worker_status;
};

int measure_connect4_control(int allowed_listener, uint16_t allowed_port,
                             int denied_listener, uint16_t denied_port,
                             struct connect4_phase *phase)
{
    *phase = (struct connect4_phase){-1, -1, -1, -1};
    if (try_connect4_loopback(allowed_port) != 0 ||
        try_connect4_loopback(denied_port) != 0) {
        errno = EIO;
        return -1;
    }
    phase->allowed_accepts = count_connect4_accepts(allowed_listener);
    phase->denied_accepts = count_connect4_accepts(denied_listener);
    if (phase->allowed_accepts != 1 || phase->denied_accepts != 1) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

/* Observe without reaping so the manager can still use the original pidfd
 * for recovery. On timeout the manager must keep the policy pinned. */
int measure_connect4_worker(int pidfd, int controller_pidfd,
                            int allowed_listener, int denied_listener,
                            struct connect4_phase *phase)
{
    *phase = (struct connect4_phase){-1, -1, -1, -1};
    struct pollfd watched[] = {
        { .fd = pidfd, .events = POLLIN },
        { .fd = controller_pidfd, .events = POLLIN },
    };
    int ready = poll(watched, 2, 2000);
    if (ready < 0)
        return -1;
    if (ready == 0) {
        errno = ETIMEDOUT;
        return -1;
    }
    if (controller_is_live(controller_pidfd) < 0 || confirm_worker_exit(pidfd) < 0)
        return -1;
    siginfo_t status = {0};
    if (waitid(P_PIDFD, (id_t)pidfd, &status, WEXITED | WNOHANG | WNOWAIT) < 0)
        return -1;
    phase->worker_code = status.si_code;
    phase->worker_status = status.si_status;
    phase->allowed_accepts = count_connect4_accepts(allowed_listener);
    phase->denied_accepts = count_connect4_accepts(denied_listener);
    if (status.si_code != CLD_EXITED || status.si_status != 0 ||
        phase->allowed_accepts != 1 || phase->denied_accepts != 0) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

/* Move only the manager's live, unreaped direct child while its private
 * release pipe is still closed to commands. Verify the destination by FD. */
int place_connect4_worker(int state_fd, int cgroup_fd, dev_t device,
                          uint64_t cgroup_id, pid_t child, int pidfd)
{
    if (child <= 0 || pidfd < 0) {
        errno = EINVAL;
        return -1;
    }
    int lease = acquire_connect4_lease(state_fd);
    if (lease < 0)
        return -1;
    int result = -1;
    if (check_connect4_cgroup_empty(cgroup_fd, device, cgroup_id) < 0 ||
        check_connect4_pidfd_pid(pidfd, child) < 0)
        goto done;

    siginfo_t status = {0};
    if (waitid(P_PIDFD, (id_t)pidfd, &status, WEXITED | WNOHANG | WNOWAIT) < 0)
        goto done;
    if (status.si_pid != 0) {
        errno = ESRCH;
        goto done;
    }

    int members = openat(cgroup_fd, "cgroup.procs",
                         O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (members < 0)
        goto done;
    char value[32];
    int size = snprintf(value, sizeof(value), "%ld\n", (long)child);
    ssize_t written = write(members, value, (size_t)size);
    int write_error = errno;
    close(members);
    if (written != size) {
        errno = written < 0 ? write_error : EIO;
        goto done;
    }
    result = check_connect4_worker_membership(cgroup_fd, child);

done:;
    int error = errno;
    close(lease);
    if (result < 0)
        errno = error;
    return result;
}

struct connect4_worker {
    pid_t pid;
    int pidfd;
    int gate;
    int ready;
};

struct fixed_relay_pipes {
    int request;
    int response;
    int status;
};

/* Call in the trusted client child immediately before exec. Stdio belongs
 * to the harness; only its two data pipes pass through as extra descriptors. */
int map_fixed_relay_client_pipes(const struct fixed_relay_pipes *relay)
{
    const int inherited[] = {relay->request, relay->response};
    return map_fixed_pipes(inherited, sizeof(inherited) / sizeof(inherited[0]), 1, 0);
}

enum { FIXED_RELAY_PIPE_COUNT = 4 };

static void describe_fixed_relay_pipes(
    const struct connect4_worker *worker, const struct fixed_relay_pipes *relay,
    struct worker_pipe pipes[static FIXED_RELAY_PIPE_COUNT])
{
    pipes[0] = (struct worker_pipe){3, O_RDONLY, worker->gate, O_WRONLY};
    pipes[1] = (struct worker_pipe){5, O_RDONLY, relay->request, O_WRONLY};
    pipes[2] = (struct worker_pipe){6, O_WRONLY, relay->response, O_RDONLY};
    pipes[3] = (struct worker_pipe){7, O_WRONLY, relay->status, O_RDONLY};
}

/* Fork before taking the lease. Child pipe ends are remapped together
 * so no inherited descriptor can collide with the fixed layout. */
static int spawn_worker(uint16_t allowed, uint16_t denied,
                        struct connect4_worker *worker, atomic_int *release_seen,
                        struct fixed_relay_pipes *relay, int64_t deadline, int alternate)
{
    enum { GATE, READY, REQUEST, RESPONSE, STATUS };
    const unsigned count = relay == NULL ? 2 : 5;
    int pipes[5][2];
    unsigned opened = 0;
    *worker = (struct connect4_worker){-1, -1, -1, -1};
    if (relay != NULL)
        *relay = (struct fixed_relay_pipes){-1, -1, -1};
    for (; opened < count; ++opened) {
        int flags = O_CLOEXEC | (opened >= REQUEST ? O_NONBLOCK : 0);
        if (pipe2(pipes[opened], flags) < 0)
            break;
    }
    if (opened != count) {
        int error = errno;
        for (unsigned i = 0; i < opened; ++i) {
            close(pipes[i][0]);
            close(pipes[i][1]);
        }
        errno = error;
        return -1;
    }

    const unsigned child_end[] = {0, 1, 0, 1, 1};
    int privileged = geteuid() == 0;
    pid_t child = fork();
    if (child == 0) {
        int inherited[5];
        for (unsigned i = 0; i < count; ++i)
            inherited[i] = pipes[i][child_end[i]];
        if (map_worker_pipes(inherited, count) < 0)
            _exit(69);
        if (relay == NULL)
            _exit(run_connect4_worker(allowed, denied, release_seen));
        if ((privileged ? drop_connect4_worker_privileges() :
             prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL)) < 0)
            _exit(70);
        _exit(alternate ? run_fixed_alternate_worker(allowed, deadline)
                        : run_fixed_relay_worker(allowed, deadline));
    }

    int error = errno;
    for (unsigned i = 0; i < count; ++i)
        close(pipes[i][child_end[i]]);
    if (child > 0) {
        int pidfd = retain_connect4_worker(child);
        if (pidfd >= 0) {
            *worker = (struct connect4_worker){child, pidfd, pipes[GATE][1], pipes[READY][0]};
            if (relay != NULL)
                *relay = (struct fixed_relay_pipes){pipes[REQUEST][1], pipes[RESPONSE][0],
                                                  pipes[STATUS][0]};
            return 0;
        }
        error = errno;
    }
    for (unsigned i = 0; i < count; ++i)
        close(pipes[i][1 - child_end[i]]);
    if (child > 0) {
        /* This manager is the sole reaper. The PID cannot have been reused. */
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    }
    errno = error;
    return -1;
}

int spawn_connect4_worker(uint16_t allowed, uint16_t denied,
                          struct connect4_worker *worker, atomic_int *release_seen)
{
    return spawn_worker(allowed, denied, worker, release_seen, NULL, 0, 0);
}

int spawn_fixed_relay_worker(uint16_t port, int64_t deadline,
                             struct connect4_worker *worker,
                             struct fixed_relay_pipes *relay)
{
    return spawn_worker(port, 0, worker, NULL, relay, deadline, 0);
}

int spawn_fixed_alternate_worker(uint16_t port, int64_t deadline,
                                 struct connect4_worker *worker,
                                 struct fixed_relay_pipes *relay)
{
    return spawn_worker(port, 0, worker, NULL, relay, deadline, 1);
}

int read_fixed_relay_connect_errno(const struct fixed_relay_pipes *relay,
                                   int64_t deadline, int *connect_errno)
{
    int reported;
    if (read_before(relay->status, &reported, sizeof(reported), deadline) < 0)
        return -1;
    if (reported < 0 || reported > 4095) {
        errno = EPROTO;
        return -1;
    }
    *connect_errno = reported;
    return 0;
}

/* Leave the child waitable so cleanup can still verify the original pidfd. */
int observe_fixed_relay_exit(const struct connect4_worker *worker,
                             int64_t deadline, int *relay_exit)
{
    struct pollfd exited = {.fd = worker->pidfd, .events = POLLIN};
    if (poll_before(&exited, deadline) < 0)
        return -1;
    siginfo_t status = {0};
    if (waitid(P_PIDFD, (id_t)worker->pidfd, &status, WEXITED | WNOHANG | WNOWAIT) < 0)
        return -1;
    if (status.si_pid != worker->pid || status.si_code != CLD_EXITED ||
        status.si_status > 2) {
        errno = EPROTO;
        return -1;
    }
    *relay_exit = status.si_status;
    return 0;
}

struct connect4_trial {
    int state_fd;
    int cgroup_fd;
    dev_t device;
    uint64_t cgroup_id;
    int link_fd;
    uint32_t link_id;
    uint32_t program_id;
    const char *pin_path;
};

/* Only used when this manager observed that pin creation never succeeded.
 * An unexpected path or release marker is a recovery discrepancy. */
static int confirm_unpinned_connect4_trial(const struct connect4_trial *trial)
{
    int lease = acquire_connect4_lease(trial->state_fd);
    if (lease < 0)
        return -1;
    struct stat metadata;
    int result = -1;
    if (lstat(trial->pin_path, &metadata) == 0) {
        errno = EEXIST;
    } else if (errno == ENOENT) {
        if (fstatat(trial->state_fd, "release-intent", &metadata,
                    AT_SYMLINK_NOFOLLOW) == 0)
            errno = ESTALE;
        else if (errno == ENOENT)
            result = check_connect4_cgroup_empty(trial->cgroup_fd,
                                                  trial->device, trial->cgroup_id);
    }
    int error = errno;
    close(lease);
    if (result < 0)
        errno = error;
    return result;
}

/* The manager supplies a fresh, registered trial and retains ownership of
 * its cgroup and original link FD, including on recovery failure. */
/* Preserve the last observed pin phase across a return to the live manager.
 * Recovery after loss of that manager must reconstruct state independently. */
enum connect4_pin_phase {
    CONNECT4_PIN_ABSENT,
    CONNECT4_PIN_HELD,
    CONNECT4_PIN_REMOVED,
    CONNECT4_PIN_UNKNOWN,
};

struct connect4_pending_recovery {
    pid_t pid;
    int pidfd;
    enum connect4_pin_phase phase;
};

int retry_connect4_recovery(const struct connect4_trial *trial,
                            struct connect4_pending_recovery *pending);

static int record_connect4_trial(const struct connect4_trial *trial);

int handoff_connect4_worker_fd(int channel, pid_t worker, int worker_pidfd);

/* Preserve the worker identity for deferred recovery if immediate cleanup fails. */
static int finish_connect4_worker(const struct connect4_trial *trial,
                                  const struct connect4_worker *worker,
                                  int pinned, int saved,
                                  struct connect4_pending_recovery *pending)
{
    if (syscall(SYS_pidfd_send_signal, worker->pidfd, SIGKILL, NULL, 0) < 0 &&
        errno != ESRCH)
        saved = errno;
    struct pollfd exited = { .fd = worker->pidfd, .events = POLLIN };
    if (poll(&exited, 1, 2000) == 1 && confirm_worker_exit(worker->pidfd) == 0) {
        int recovered = pinned ? recover_connect4_pin(trial->state_fd, trial->pin_path, worker->pidfd,
                                 trial->cgroup_fd, trial->device, trial->cgroup_id,
                                 trial->link_id, trial->program_id)
            : confirm_unpinned_connect4_trial(trial);
        if (recovered < 0) {
            *pending = (struct connect4_pending_recovery){worker->pid, worker->pidfd,
                CONNECT4_PIN_UNKNOWN};
            return -1;
        }
        *pending = (struct connect4_pending_recovery){worker->pid, worker->pidfd,
            pinned ? CONNECT4_PIN_REMOVED : CONNECT4_PIN_ABSENT};
        if (retry_connect4_recovery(trial, pending) < 0)
            return -1;
        fputs("worker_exit_observed=1 worker_reaped_by_pidfd=1\n", stderr);
    } else {
        *pending = (struct connect4_pending_recovery){worker->pid, worker->pidfd,
            pinned ? CONNECT4_PIN_HELD : CONNECT4_PIN_UNKNOWN};
        errno = ETIMEDOUT;
        return -1;
    }
    if (saved != 0) {
        errno = saved;
        return -1;
    }
    return 0;
}

/* Control workers have the same privileges and descriptors as restricted
 * workers. The immediate caller owns the child and its pidfd. */
int release_fixed_relay_control(const struct connect4_worker *worker,
                                const struct fixed_relay_pipes *relay,
                                int controller_pidfd)
{
    struct worker_pipe pipes[FIXED_RELAY_PIPE_COUNT];
    describe_fixed_relay_pipes(worker, relay, pipes);
    if (controller_is_live(controller_pidfd) < 0 ||
        confirm_connect4_ready(worker->ready) < 0 ||
        check_connect4_pidfd_pid(worker->pidfd, worker->pid) < 0 ||
        check_connect4_worker_privileges(worker->pid) < 0 ||
        check_worker_pipes(worker->pid, pipes, FIXED_RELAY_PIPE_COUNT) < 0 ||
        controller_is_live(controller_pidfd) < 0)
        return -1;
    return send_connect4_release(worker->gate);
}

struct fixed_relay_result {
    int connect_errno;
    int relay_exit;
};

typedef int (*fixed_relay_exchange)(const struct fixed_relay_pipes *, int64_t, void *);

struct fixed_relay_client {
    const char *binary;
    const char *run_nonce;
    const char *phase;
    /* Complete IZANAGI_SECRET_FILE assignment from the trusted VM owner. */
    const char *secret_env;
    const char *session_env;
};

/* Called only by the trusted harness. The client runs as the dedicated VM
 * owner, inherits no supervisor descriptors, and writes its ACK to stdout. */
int exchange_fixed_relay_client(const struct fixed_relay_pipes *relay,
                                int64_t deadline, void *context)
{
    const struct fixed_relay_client *client = context;
    pid_t owner = getpid();
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0) {
        if (drop_fixed_privileges(999, 988) < 0 ||
            prctl(PR_SET_PDEATHSIG, SIGKILL, 0UL, 0UL, 0UL) < 0 ||
            getppid() != owner || map_fixed_relay_client_pipes(relay) < 0)
            _exit(126);
        char *const argv[] = {
            (char *)client->binary, (char *)client->run_nonce, (char *)client->phase, NULL,
        };
        char *const env[] = {(char *)client->secret_env, (char *)client->session_env, NULL};
        execve(client->binary, argv, env);
        _exit(127);
    }

    int pidfd = retain_connect4_worker(child);
    int error = pidfd < 0 ? errno : 0;
    if (pidfd >= 0) {
        struct pollfd exited = {.fd = pidfd, .events = POLLIN};
        if (poll_before(&exited, deadline) < 0)
            error = errno;
    }
    /* Sole reaper: even if pidfd acquisition failed, PID reuse is impossible. */
    if (error != 0)
        (void)kill(child, SIGKILL);
    int status;
    pid_t reaped;
    do {
        reaped = waitpid(child, &status, 0);
    } while (reaped < 0 && errno == EINTR);
    if (reaped < 0 && error == 0)
        error = errno;
    if (pidfd >= 0)
        close(pidfd);
    if (error == 0 && (!WIFEXITED(status) || WEXITSTATUS(status) != 0))
        error = EPROTO;
    if (error != 0) {
        errno = error;
        return -1;
    }
    return 0;
}

int exchange_fixed_alternate(const struct fixed_relay_pipes *relay,
                             int64_t deadline, void *context)
{
    (void)context;
    char response[sizeof(alternate_response) - 1];
    if (write_before(relay->request, alternate_request, sizeof(alternate_request) - 1,
                     deadline) < 0 ||
        read_before(relay->response, response, sizeof(response), deadline) < 0)
        return -1;
    if (memcmp(response, alternate_response, sizeof(response)) != 0) {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

static int observe_fixed_relay(const struct connect4_worker *worker,
                              struct fixed_relay_pipes *relay,
                              int64_t deadline, fixed_relay_exchange exchange,
                              void *context, struct fixed_relay_result *observed)
{
    if (read_fixed_relay_connect_errno(relay, deadline, &observed->connect_errno) < 0)
        return -1;
    int error = 0;
    if (observed->connect_errno == 0) {
        errno = 0;
        if (exchange == NULL || exchange(relay, deadline, context) < 0)
            error = errno != 0 ? errno : EPROTO;
    }
    /* Close the supervisor's write end so an interrupted client produces EOF. */
    close(relay->request);
    close(relay->response);
    relay->request = -1;
    relay->response = -1;
    if (observe_fixed_relay_exit(worker, deadline, &observed->relay_exit) < 0)
        return -1;
    if (error != 0) {
        errno = error;
        return -1;
    }
    return 0;
}

int run_fixed_relay_control(uint16_t port, int alternate, int controller_pidfd,
                            int64_t deadline, fixed_relay_exchange exchange,
                            void *context, struct fixed_relay_result *observed)
{
    *observed = (struct fixed_relay_result){-1, -1};
    struct connect4_worker worker;
    struct fixed_relay_pipes relay;
    int spawned = alternate ? spawn_fixed_alternate_worker(port, deadline, &worker, &relay)
                            : spawn_fixed_relay_worker(port, deadline, &worker, &relay);
    if (spawned < 0)
        return -1;

    int result = release_fixed_relay_control(&worker, &relay, controller_pidfd);
    int error = result < 0 ? errno : 0;
    close(worker.gate);
    close(worker.ready);
    if (result == 0) {
        result = observe_fixed_relay(&worker, &relay, deadline, exchange, context, observed);
        error = result < 0 ? errno : 0;
    }
    if (relay.request >= 0)
        close(relay.request);
    if (relay.response >= 0)
        close(relay.response);
    close(relay.status);

    /* Sole reaper, holding the original pidfd until the child is reaped. */
    if (observed->relay_exit < 0 &&
        syscall(SYS_pidfd_send_signal, worker.pidfd, SIGKILL, NULL, 0) < 0 && errno != ESRCH)
        error = errno;
    siginfo_t status = {0};
    int reaped;
    do {
        reaped = waitid(P_PIDFD, (id_t)worker.pidfd, &status, WEXITED);
    } while (reaped < 0 && errno == EINTR);
    if (reaped < 0)
        error = errno;
    close(worker.pidfd);
    if (error != 0) {
        errno = error;
        return -1;
    }
    return result;
}

/* The caller retains the pidfd and must finish or recover the worker on
 * failure as well as on success. The upper owner must already know its PID. */
int place_and_release_fixed_relay(const struct connect4_trial *trial,
                                  const struct connect4_worker *worker,
                                  const struct fixed_relay_pipes *relay,
                                  int controller_pidfd, int handoff_channel,
                                  int *pinned)
{
    *pinned = 0;
    if (handoff_channel < 0) {
        errno = EINVAL;
        return -1;
    }
    if (controller_is_live(controller_pidfd) < 0 ||
        place_connect4_worker(trial->state_fd, trial->cgroup_fd, trial->device,
                              trial->cgroup_id, worker->pid, worker->pidfd) < 0 ||
        handoff_connect4_worker_fd(handoff_channel, worker->pid, worker->pidfd) < 0)
        return -1;

    struct worker_pipe pipes[FIXED_RELAY_PIPE_COUNT];
    describe_fixed_relay_pipes(worker, relay, pipes);
    return release_connect4_worker(trial->state_fd, worker->ready,
                                   pipes, FIXED_RELAY_PIPE_COUNT, controller_pidfd,
                                   worker->pid, worker->pidfd, trial->link_fd,
                                   trial->pin_path, trial->cgroup_fd, trial->device,
                                   trial->cgroup_id, trial->link_id, trial->program_id,
                                   pinned, 0);
}

int run_restricted_fixed_relay(
    const struct connect4_trial *trial, uint16_t port, int alternate,
    int controller_pidfd, int handoff_channel, atomic_int *known_worker,
    int64_t deadline, fixed_relay_exchange exchange, void *context,
    struct fixed_relay_result *observed, struct connect4_pending_recovery *pending)
{
    *observed = (struct fixed_relay_result){-1, -1};
    *pending = (struct connect4_pending_recovery){-1, -1, CONNECT4_PIN_UNKNOWN};
    if (handoff_channel < 0 || known_worker == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (controller_is_live(controller_pidfd) < 0 || record_connect4_trial(trial) < 0)
        return -1;

    /* Do not infer absence if the supervisor dies during fork. */
    atomic_store_explicit(known_worker, -1, memory_order_release);
    struct connect4_worker worker;
    struct fixed_relay_pipes relay;
    int spawned = alternate ? spawn_fixed_alternate_worker(port, deadline, &worker, &relay)
                            : spawn_fixed_relay_worker(port, deadline, &worker, &relay);
    if (spawned < 0) {
        atomic_store_explicit(known_worker, 0, memory_order_release);
        return -1;
    }
    atomic_store_explicit(known_worker, worker.pid, memory_order_release);

    int pinned;
    int result = place_and_release_fixed_relay(trial, &worker, &relay, controller_pidfd,
                                                handoff_channel, &pinned);
    int saved = result < 0 ? errno : 0;
    close(worker.gate);
    close(worker.ready);
    if (result == 0) {
        result = observe_fixed_relay(&worker, &relay, deadline, exchange, context, observed);
        if (result == 0)
            result = controller_is_live(controller_pidfd);
        saved = result < 0 ? errno : 0;
    }
    if (relay.request >= 0)
        close(relay.request);
    if (relay.response >= 0)
        close(relay.response);
    close(relay.status);
    return finish_connect4_worker(trial, &worker, pinned, saved, pending);
}

int run_connect4_trial(const struct connect4_trial *trial, int controller_pidfd,
                       int handoff_channel, atomic_int *known_worker,
                       int supervisor_fault,
                       int stop_before_release, atomic_int *release_seen,
                       int allowed_listener, uint16_t allowed_port,
                       int denied_listener, uint16_t denied_port,
                       struct connect4_phase phases[static 3],
                       struct connect4_pending_recovery *pending)
{
    *pending = (struct connect4_pending_recovery){-1, -1, CONNECT4_PIN_UNKNOWN};
    for (unsigned i = 0; i < 3; ++i)
        phases[i] = (struct connect4_phase){-1, -1, -1, -1};
    if (controller_is_live(controller_pidfd) < 0 ||
        measure_connect4_control(allowed_listener, allowed_port, denied_listener,
                                 denied_port, &phases[0]) < 0)
        return -1;

    if (record_connect4_trial(trial) < 0)
        return -1;

    /* Zero means fork has not been attempted. A death during fork or
     * before PID publication leaves an explicit unresolved state. */
    if (known_worker != NULL)
        atomic_store_explicit(known_worker, -1, memory_order_release);
    struct connect4_worker worker;
    if (spawn_connect4_worker(allowed_port, denied_port, &worker, release_seen) < 0)
        return -1;
    if (known_worker != NULL)
        atomic_store_explicit(known_worker, worker.pid, memory_order_release);
    int pinned = 0;
    int result = place_connect4_worker(trial->state_fd, trial->cgroup_fd,
                                         trial->device, trial->cgroup_id,
                                         worker.pid, worker.pidfd);
    const char *failure_stage = "place";
    if (result == 0 && supervisor_fault == 1) {
        failure_stage = "supervisor-before-handoff";
        result = confirm_connect4_ready(worker.ready);
        if (result == 0) {
            fputs("fault=supervisor-before-handoff ready=1\n", stderr);
            result = kill(getpid(), SIGKILL);
        }
    }
    if (result == 0 && handoff_channel >= 0) {
        failure_stage = "recovery-handoff";
        result = handoff_connect4_worker_fd(handoff_channel, worker.pid, worker.pidfd);
    }
    if (result == 0) {
        failure_stage = "prepare-or-release";
        const struct worker_pipe gate = {3, O_RDONLY, worker.gate, O_WRONLY};
        result = release_connect4_worker(trial->state_fd, worker.ready, &gate, 1,
                                            controller_pidfd,
                                            worker.pid, worker.pidfd,
                                            trial->link_fd, trial->pin_path,
                                            trial->cgroup_fd, trial->device,
                                            trial->cgroup_id, trial->link_id,
                                            trial->program_id, &pinned, stop_before_release);
    }
    if (result < 0) {
        int error = errno;
        fprintf(stderr, "connect4 stage=%s errno=%d pin_created=%d\n",
                failure_stage, error, pinned);
        errno = error;
    }
    if (result == 0 && release_seen != NULL) {
        const struct timespec interval = { .tv_nsec = 10000000 };
        unsigned checks = 0;
        while (!atomic_load_explicit(release_seen, memory_order_acquire) &&
               checks++ < 100)
            nanosleep(&interval, NULL);
        if (!atomic_load_explicit(release_seen, memory_order_acquire)) {
            errno = ETIMEDOUT;
            result = -1;
        } else if (supervisor_fault == 2) {
            fputs("fault=supervisor-after-release token_read=1\n", stderr);
            result = kill(getpid(), SIGKILL);
        } else if (stop_test_controller(controller_pidfd) < 0) {
            result = -1;
        } else {
            struct pollfd child = { .fd = worker.pidfd, .events = POLLIN };
            int ready = poll(&child, 1, 0);
            if (ready == 0)
                fputs("fault=after-release token_read=1 controller_exit_observed=1 worker_live=1\n",
                      stderr);
            if (ready >= 0)
                errno = ready == 0 ? ECANCELED : EPROTO;
            result = -1;
        }
    }
    close(worker.gate);
    close(worker.ready);
    if (result == 0)
        result = measure_connect4_worker(worker.pidfd, controller_pidfd, allowed_listener,
                                            denied_listener, &phases[1]);

    int saved = result < 0 ? errno : 0;
    if (finish_connect4_worker(trial, &worker, pinned, saved, pending) < 0)
        return -1;
    return measure_connect4_control(allowed_listener, allowed_port, denied_listener,
                                      denied_port, &phases[2]);
}

/* Resolve unknown state only from the verified pin or the existing
 * pre-release absence checks. A missing pin after release stays unknown. */
static int resolve_connect4_pin_phase(const struct connect4_trial *trial,
                                      struct connect4_pending_recovery *pending)
{
    int link = reopen_connect4_link(trial->pin_path, trial->link_id,
                                     trial->program_id, trial->cgroup_id);
    if (link >= 0) {
        close(link);
        pending->phase = CONNECT4_PIN_HELD;
        return 0;
    }
    if (errno != ENOENT || confirm_worker_exit(pending->pidfd) < 0 ||
        confirm_unpinned_connect4_trial(trial) < 0)
        return -1;
    pending->phase = CONNECT4_PIN_ABSENT;
    return 0;
}

/* The same manager keeps the original trial and remains the sole reaper. */
int retry_connect4_recovery(const struct connect4_trial *trial,
                            struct connect4_pending_recovery *pending)
{
    if (pending->pid <= 0 || pending->pidfd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (pending->phase == CONNECT4_PIN_UNKNOWN && trial != NULL &&
        resolve_connect4_pin_phase(trial, pending) < 0)
        return -1;
    switch (pending->phase) {
    case CONNECT4_PIN_UNKNOWN:
        errno = ESTALE;
        return -1;
    case CONNECT4_PIN_HELD:
        if (recover_connect4_pin(trial->state_fd, trial->pin_path, pending->pidfd,
                                 trial->cgroup_fd, trial->device, trial->cgroup_id,
                                 trial->link_id, trial->program_id) < 0)
            return -1;
        pending->phase = CONNECT4_PIN_REMOVED;
        break;
    case CONNECT4_PIN_REMOVED:
    case CONNECT4_PIN_ABSENT:
        break;
    default:
        errno = EINVAL;
        return -1;
    }
    if (confirm_worker_exit(pending->pidfd) < 0)
        return -1;
    siginfo_t status = {0};
    if (waitid(P_PIDFD, (id_t)pending->pidfd, &status, WEXITED | WNOHANG) < 0)
        return -1;
    if (status.si_pid != pending->pid) {
        errno = ESTALE;
        return -1;
    }
    close(pending->pidfd);
    *pending = (struct connect4_pending_recovery){-1, -1, CONNECT4_PIN_UNKNOWN};
    return 0;
}

/* The manager owns an already registered, dedicated empty cgroup and the
 * private trial directory. Keep the original link FD through recovery. */
int prepare_connect4_trial(int state_fd, int cgroup_fd, const char *pin_path,
                            uint16_t allowed_port, struct connect4_trial *trial)
{
    struct connect4_trial candidate = {
        .state_fd = state_fd, .cgroup_fd = cgroup_fd, .link_fd = -1,
        .pin_path = pin_path,
    };
    if (pin_path == NULL || *pin_path != '/') {
        errno = EINVAL;
        return -1;
    }
    if (read_connect4_cgroup_identity(cgroup_fd, &candidate.device,
                                     &candidate.cgroup_id) < 0 ||
        confirm_unpinned_connect4_trial(&candidate) < 0)
        return -1;

    int program = load_connect4_policy(allowed_port);
    if (program < 0)
        return -1;
    if (read_connect4_program_id(program, &candidate.program_id) == 0)
        candidate.link_fd = attach_connect4_policy(program, cgroup_fd);
    int error = errno;
    close(program);
    if (candidate.link_fd < 0) {
        errno = error;
        return -1;
    }
    if (read_connect4_link_id(candidate.link_fd, candidate.program_id,
                              candidate.cgroup_id, &candidate.link_id) < 0) {
        error = errno;
        close(candidate.link_fd);
        errno = error;
        return -1;
    }
    *trial = candidate;
    return 0;
}

/* The manager records the attachment before it creates or releases a child.
 * The per-trial directory already identifies the dedicated cgroup and pin
 * names. A partial record deliberately prevents admission until inspected. */
static int record_connect4_trial(const struct connect4_trial *trial)
{
    int lease = acquire_connect4_lease(trial->state_fd);
    if (lease < 0)
        return -1;

    int result = -1;
    if (check_connect4_link(trial->link_fd, trial->link_id, trial->program_id,
                            trial->cgroup_id) < 0)
        goto done;
    char record[256];
    int length = snprintf(record, sizeof(record),
                          "version=1\ndevice=%ju\ncgroup=%ju\nlink=%u\nprogram=%u\n",
                          (uintmax_t)trial->device, (uintmax_t)trial->cgroup_id,
                          trial->link_id, trial->program_id);
    if (length <= 0 || (size_t)length >= sizeof(record)) {
        errno = EOVERFLOW;
        goto done;
    }
    int fd = openat(trial->state_fd, "trial-identity",
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        goto done;
    ssize_t written = write(fd, record, (size_t)length);
    if (written != length) {
        if (written >= 0)
            errno = EIO;
    } else if (fsync(fd) == 0 && fsync(trial->state_fd) == 0) {
        result = 0;
    }
    int write_error = errno;
    if (close(fd) < 0 && result == 0)
        result = -1;
    else
        errno = write_error;

done:;
    int error = errno;
    close(lease);
    if (result < 0)
        errno = error;
    return result;
}

#ifndef CONNECT4_CASE
#define CONNECT4_CASE 0
#endif
#if CONNECT4_CASE == 0
#define CONNECT4_TRIAL_NAME "tempest-connect4-fixture-001"
#elif CONNECT4_CASE == 1
#define CONNECT4_TRIAL_NAME "tempest-connect4-fixture-before-001"
#elif CONNECT4_CASE == 2
#define CONNECT4_TRIAL_NAME "tempest-connect4-fixture-after-001"
#elif CONNECT4_CASE == 3
#define CONNECT4_TRIAL_NAME "tempest-connect4-fixture-diagnostic-001"
#elif CONNECT4_CASE == 4
#define CONNECT4_TRIAL_NAME "tempest-connect4-fixture-normal-002"
#elif CONNECT4_CASE == 5
#define CONNECT4_TRIAL_NAME "tempest-connect4-fixture-subreaper-001"
#elif CONNECT4_CASE == 6
#define CONNECT4_TRIAL_NAME "tempest-connect4-fixture-supervisor-before-001"
#elif CONNECT4_CASE == 7
#define CONNECT4_TRIAL_NAME "tempest-connect4-fixture-supervisor-after-001"
#elif CONNECT4_CASE == 8
#define CONNECT4_TRIAL_NAME "tempest-fixed-relay-denial-001"
#elif CONNECT4_CASE == 9
#define CONNECT4_TRIAL_NAME "tempest-fixed-vm-relay-allow-001"
#elif CONNECT4_CASE == 10
#define CONNECT4_TRIAL_NAME "tempest-fixed-vm-relay-deny-001"
#else
#error "unknown connect4 fixture case"
#endif
#define CONNECT4_PIN_PATH "/sys/fs/bpf/" CONNECT4_TRIAL_NAME

/* Keep failed setup directories for inspection. A second invocation must
 * stop at the original entry, even if it never reached worker admission. */
int create_connect4_trial_directory(int parent, const char *name)
{
    struct stat parent_info, child_info, entry_info;
    if (fstat(parent, &parent_info) < 0)
        return -1;
    if (!S_ISDIR(parent_info.st_mode) || parent_info.st_uid != 0 ||
        (parent_info.st_mode & 0022) != 0 || name == NULL ||
        *name == '\0' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0 ||
        strchr(name, '/') != NULL) {
        errno = EINVAL;
        return -1;
    }
    if (mkdirat(parent, name, 0700) < 0) {
        int error = errno;
        fprintf(stderr, "fixture directory %s: mkdir failed (%d)\n", name, error);
        errno = error;
        return -1;
    }
    int child = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (child < 0) {
        int error = errno;
        fprintf(stderr, "fixture directory %s: created but open failed (%d)\n",
                name, error);
        errno = error;
        return -1;
    }
    if (fstat(child, &child_info) < 0 ||
        fstatat(parent, name, &entry_info, AT_SYMLINK_NOFOLLOW) < 0) {
        int error = errno;
        close(child);
        fprintf(stderr, "fixture directory %s: created but stat failed (%d)\n",
                name, error);
        errno = error;
        return -1;
    }
    if (!S_ISDIR(child_info.st_mode) || child_info.st_uid != 0 ||
        (child_info.st_mode & 07777) != 0700 ||
        child_info.st_dev != parent_info.st_dev ||
        child_info.st_dev != entry_info.st_dev ||
        child_info.st_ino != entry_info.st_ino) {
        close(child);
        fprintf(stderr, "fixture directory %s: created but identity mismatch\n", name);
        errno = ESTALE;
        return -1;
    }
    return child;
}

static int open_connect4_parent(const char *path, long magic)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    struct stat metadata;
    struct statfs filesystem;
    int error = 0;
    if (fstat(fd, &metadata) < 0 || fstatfs(fd, &filesystem) < 0)
        error = errno;
    else if (metadata.st_uid != 0 || (metadata.st_mode & 0022) != 0 ||
             (magic != 0 && filesystem.f_type != magic))
        error = ESTALE;
    if (error != 0) {
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

int retire_connect4_fixture_state(int state_fd);

int create_connect4_fixture_state(int *state_fd, int *cgroup_fd)
{
    *state_fd = -1;
    *cgroup_fd = -1;
    int state_parent = open_connect4_parent("/var/lib", 0);
    if (state_parent < 0)
        return -1;
    int cgroup_parent = open_connect4_parent("/sys/fs/cgroup", CGROUP2_SUPER_MAGIC);
    int bpffs = open_connect4_parent("/sys/fs/bpf", BPF_FS_MAGIC);
    int state = -1, cgroup = -1, result = -1;
    if (cgroup_parent < 0 || bpffs < 0)
        goto done;
    struct stat existing;
    if (fstatat(bpffs, CONNECT4_TRIAL_NAME, &existing, AT_SYMLINK_NOFOLLOW) == 0) {
        errno = EEXIST;
        goto done;
    }
    if (errno != ENOENT)
        goto done;
    if (fstatat(state_parent, CONNECT4_TRIAL_NAME ".retired", &existing,
                AT_SYMLINK_NOFOLLOW) == 0) {
        errno = EEXIST;
        goto done;
    }
    if (errno != ENOENT)
        goto done;
    state = create_connect4_trial_directory(state_parent, CONNECT4_TRIAL_NAME);
    if (state < 0)
        goto done;
    int lock = openat(state, "admission.lock",
                      O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (lock < 0)
        goto done;
    if (close(lock) < 0 || fsync(state) < 0 || fsync(state_parent) < 0)
        goto done;
    cgroup = create_connect4_trial_directory(cgroup_parent, CONNECT4_TRIAL_NAME);
    if (cgroup < 0) {
        int setup_error = errno;
        /* We own the fresh ledger, but did not obtain a verified cgroup
         * handle. Do not delete or modify any cgroup at the fixed path. */
        if (retire_connect4_fixture_state(state) < 0)
            perror("retire failed fixture initialization");
        errno = setup_error;
        goto done;
    }
    *state_fd = state;
    *cgroup_fd = cgroup;
    result = 0;

done:;
    int error = errno;
    if (result < 0) {
        if (state >= 0)
            close(state);
        if (cgroup >= 0)
            close(cgroup);
    }
    close(state_parent);
    if (cgroup_parent >= 0)
        close(cgroup_parent);
    if (bpffs >= 0)
        close(bpffs);
    if (result < 0)
        errno = error;
    return result;
}

/* Call after the worker is reaped and the original link FD is closed.
 * Retain state on discrepancy so another invocation cannot overwrite it. */
int remove_connect4_fixture_cgroup(int state_fd, int cgroup_fd)
{
    int lease = acquire_connect4_lease(state_fd);
    if (lease < 0)
        return -1;
    int parent = open_connect4_parent("/sys/fs/cgroup", CGROUP2_SUPER_MAGIC);
    int result = -1;
    dev_t device;
    uint64_t id;
    struct stat entry;
    struct stat pin;
    if (lstat(CONNECT4_PIN_PATH, &pin) == 0) {
        errno = EEXIST;
    } else if (errno == ENOENT && parent >= 0 &&
        read_connect4_cgroup_identity(cgroup_fd, &device, &id) == 0 &&
        check_connect4_cgroup_empty(cgroup_fd, device, id) == 0 &&
        fstatat(parent, CONNECT4_TRIAL_NAME, &entry, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISDIR(entry.st_mode) || entry.st_dev != device || entry.st_ino != id)
            errno = ESTALE;
        else
            result = unlinkat(parent, CONNECT4_TRIAL_NAME, AT_REMOVEDIR);
    }
    int error = errno;
    if (parent >= 0)
        close(parent);
    close(lease);
    if (result < 0)
        errno = error;
    return result;
}

/* Called by the fixture after verified cgroup removal. Preserve the ledger
 * and lock inode together, using a single non-replacing rename. */
int retire_connect4_fixture_state(int state_fd)
{
    int lease = acquire_connect4_lease(state_fd);
    if (lease < 0)
        return -1;
    int parent = open_connect4_parent("/var/lib", 0);
    int result = -1;
    struct stat opened, entry;
    if (parent >= 0 &&
        fstat(state_fd, &opened) == 0 &&
        fstatat(parent, CONNECT4_TRIAL_NAME, &entry, AT_SYMLINK_NOFOLLOW) == 0) {
        if (opened.st_dev != entry.st_dev || opened.st_ino != entry.st_ino) {
            errno = ESTALE;
        } else if (renameat2(parent, CONNECT4_TRIAL_NAME, parent,
                             CONNECT4_TRIAL_NAME ".retired", RENAME_NOREPLACE) == 0) {
            result = fsync(parent);
        }
    }
    int error = errno;
    if (parent >= 0)
        close(parent);
    close(lease);
    if (result < 0)
        errno = error;
    return result;
}

/* The subreaper owns both original pidfds. Keep the supervisor waitable
 * during adoption so an unrelated readable descriptor cannot stand in for it. */
int stop_adopted_connect4_worker(int supervisor_pidfd, pid_t worker, int worker_pidfd)
{
    if (supervisor_pidfd < 0 || worker_pidfd < 0 || worker <= 0) {
        errno = EINVAL;
        return -1;
    }
    siginfo_t supervisor_status = {0};
    if (waitid(P_PIDFD, (id_t)supervisor_pidfd, &supervisor_status,
               WEXITED | WNOHANG | WNOWAIT) < 0)
        return -1;
    if (supervisor_status.si_pid == 0) {
        errno = EBUSY;
        return -1;
    }

    siginfo_t worker_status = {0};
    if (waitid(P_PIDFD, (id_t)worker_pidfd, &worker_status,
               WEXITED | WNOHANG | WNOWAIT) < 0)
        return -1;
    if (worker_status.si_pid != 0) {
        if (worker_status.si_pid == worker)
            return 0;
        errno = ESTALE;
        return -1;
    }

    if (check_connect4_pidfd_pid(worker_pidfd, worker) < 0)
        return -1;
    if (syscall(SYS_pidfd_send_signal, worker_pidfd, SIGKILL, NULL, 0) < 0 &&
        errno != ESRCH)
        return -1;
    struct pollfd exited = { .fd = worker_pidfd, .events = POLLIN };
    int ready = poll(&exited, 1, 2000);
    if (ready < 0)
        return -1;
    if (ready == 0) {
        errno = ETIMEDOUT;
        return -1;
    }
    return confirm_worker_exit(worker_pidfd);
}

/* Retain the supervisor pidfd and the trial resources until this succeeds.
 * The caller is the sole reaper and records reap before attempting unlink. */
int recover_adopted_connect4_worker(const struct connect4_trial *trial,
                                     int supervisor_pidfd,
                                     struct connect4_pending_recovery *pending,
                                     int *worker_reaped)
{
    int lease = acquire_connect4_lease(trial->state_fd);
    if (lease < 0)
        return -1;
    int result = -1;
    int link = -1;
    if (!*worker_reaped) {
        if (stop_adopted_connect4_worker(supervisor_pidfd, pending->pid,
                                         pending->pidfd) < 0)
            goto done;
        siginfo_t worker = {0};
        if (waitid(P_PIDFD, (id_t)pending->pidfd, &worker,
                   WEXITED | WNOHANG) < 0)
            goto done;
        if (worker.si_pid != pending->pid) {
            errno = ESTALE;
            goto done;
        }
        *worker_reaped = 1;
    }

    link = reopen_connect4_link(trial->pin_path, trial->link_id,
                                 trial->program_id, trial->cgroup_id);
    if (link < 0) {
        if (errno != ENOENT)
            goto done;
        struct stat marker;
        if (fstatat(trial->state_fd, "release-intent", &marker,
                    AT_SYMLINK_NOFOLLOW) == 0) {
            errno = ESTALE;
            goto done;
        }
        if (errno != ENOENT)
            goto done;
    }
    if (check_connect4_cgroup_empty(trial->cgroup_fd, trial->device,
                                     trial->cgroup_id) < 0)
        goto done;
    if (link >= 0 && unlink(trial->pin_path) < 0)
        goto done;
    pending->phase = link >= 0 ? CONNECT4_PIN_REMOVED : CONNECT4_PIN_ABSENT;
    result = 0;

done:;
    int error = errno;
    if (link >= 0)
        close(link);
    close(lease);
    if (result < 0)
        errno = error;
    return result;
}

/* A private SOCK_SEQPACKET pair binds the message to the supervisor.
 * The subreaper still verifies the descriptor against the announced PID. */
int receive_connect4_worker_fd(int channel, pid_t *worker)
{
    pid_t candidate = 0;
    struct iovec payload = { .iov_base = &candidate, .iov_len = sizeof(candidate) };
    union {
        struct cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(int) * 2)];
    } control = {0};
    struct msghdr message = {
        .msg_iov = &payload, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes),
    };
    ssize_t count = recvmsg(channel, &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    if (count < 0)
        return -1;
    int descriptor = -1;
    int valid = count == sizeof(candidate) &&
        !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC));
    for (struct cmsghdr *header = CMSG_FIRSTHDR(&message); header != NULL;
         header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS ||
            header->cmsg_len < CMSG_LEN(0)) {
            valid = 0;
            continue;
        }
        size_t bytes = header->cmsg_len - CMSG_LEN(0);
        if (bytes != sizeof(int) || descriptor >= 0)
            valid = 0;
        for (size_t offset = 0; offset + sizeof(int) <= bytes; offset += sizeof(int)) {
            int fd;
            memcpy(&fd, CMSG_DATA(header) + offset, sizeof(fd));
            if (descriptor < 0)
                descriptor = fd;
            else
                close(fd);
        }
    }
    if (!valid || descriptor < 0 || check_connect4_pidfd_pid(descriptor, candidate) < 0) {
        if (descriptor >= 0)
            close(descriptor);
        errno = EPROTO;
        return -1;
    }
    *worker = candidate;
    return descriptor;
}

/* The worker gate remains closed until the independent owner acknowledges
 * the original worker pidfd and the resources required for recovery. */
int handoff_connect4_worker_fd(int channel, pid_t worker, int worker_pidfd)
{
    if (check_connect4_pidfd_pid(worker_pidfd, worker) < 0)
        return -1;
    struct iovec payload = { .iov_base = &worker, .iov_len = sizeof(worker) };
    union {
        struct cmsghdr align;
        char bytes[CMSG_SPACE(sizeof(int))];
    } control = {0};
    struct msghdr message = {
        .msg_iov = &payload, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes),
    };
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(worker_pidfd));
    memcpy(CMSG_DATA(header), &worker_pidfd, sizeof(worker_pidfd));
    ssize_t count = sendmsg(channel, &message, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (count < 0)
        return -1;
    if (count != sizeof(worker)) {
        errno = EPROTO;
        return -1;
    }
    struct pollfd reply = { .fd = channel, .events = POLLIN };
    int ready = poll(&reply, 1, 1000);
    if (ready < 0)
        return -1;
    if (ready == 0) {
        errno = ETIMEDOUT;
        return -1;
    }
    char ack;
    count = recv(channel, &ack, sizeof(ack), MSG_TRUNC | MSG_DONTWAIT);
    if (count < 0)
        return -1;
    if (count != sizeof(ack) || ack != 'A') {
        errno = EPROTO;
        return -1;
    }
    return 0;
}

/* Retain the received worker identity even if validation prevents ACK, so
 * the upper owner can still identify its adopted child on supervisor loss. */
int acknowledge_connect4_handoff(int channel, const struct connect4_trial *trial,
                                  pid_t expected_worker,
                                  struct connect4_pending_recovery *pending)
{
    if (pending->pidfd >= 0) {
        errno = EALREADY;
        return -1;
    }
    pid_t worker;
    int worker_fd = receive_connect4_worker_fd(channel, &worker);
    if (worker_fd < 0)
        return -1;
    if (worker != expected_worker || expected_worker <= 0) {
        close(worker_fd);
        errno = ESTALE;
        return -1;
    }
    *pending = (struct connect4_pending_recovery){
        worker, worker_fd, CONNECT4_PIN_UNKNOWN,
    };

    dev_t device;
    uint64_t cgroup_id;
    if (read_connect4_cgroup_identity(trial->cgroup_fd, &device, &cgroup_id) < 0)
        return -1;
    if (device != trial->device || cgroup_id != trial->cgroup_id) {
        errno = ESTALE;
        return -1;
    }
    if (check_connect4_link(trial->link_fd, trial->link_id, trial->program_id,
                            cgroup_id) < 0)
        return -1;
    int lease = acquire_connect4_lease(trial->state_fd);
    if (lease < 0)
        return -1;
    close(lease);

    const char ack = 'A';
    ssize_t count = send(channel, &ack, sizeof(ack), MSG_NOSIGNAL | MSG_DONTWAIT);
    if (count == sizeof(ack))
        return 0;
    if (count >= 0)
        errno = EPROTO;
    return -1;
}
