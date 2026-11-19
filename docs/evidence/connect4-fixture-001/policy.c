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

/* The fixed worker retains only gate read end 3 at this stage. */
static int check_connect4_worker_fds(pid_t child, int gate_fd)
{
    const struct worker_pipe gate = {3, O_RDONLY, gate_fd, O_WRONLY};
    return check_worker_pipes(child, &gate, 1);
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

int release_connect4_worker(int state_fd, int gate_fd, int ready_fd,
                            int controller_pidfd,
                            pid_t child, int worker_pidfd,
                            int link_fd,
                            const char *path, int cgroup_fd, dev_t device,
                            uint64_t cgroup_id, uint32_t link_id,
                            uint32_t program_id, int *pinned,
                            int stop_before_release)
{
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
    if (check_connect4_worker_fds(child, gate_fd) < 0)
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
    const char token = 'R';
    ssize_t sent = write(gate_fd, &token, sizeof(token));
    if (sent == 1)
        result = 0;
    else if (sent == 0)
        errno = EIO;

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
    for (unsigned cap = 0; cap <= CAP_LAST_CAP; ++cap) {
        if (prctl(PR_CAPBSET_DROP, (unsigned long)cap, 0UL, 0UL, 0UL) < 0)
            return -1;
    }
    if (setgroups(0, NULL) < 0 || setresgid(62004, 62004, 62004) < 0 ||
        setresuid(62004, 62004, 62004) < 0)
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

#define GUARD_SYSCALL(number) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, number, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
#define FILTER_ARG(index) \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[index]))
#define FILTER_DENY BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)

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
static int connect4_loopback(uint16_t port, int *connected_fd)
{
    *connected_fd = -1;
    const struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
    };
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

/* The manager calls this before taking the lease. Forked child remaps the
 * pipe ends from temporary numbers to avoid collisions with FD 3 or 4. */
int spawn_connect4_worker(uint16_t allowed, uint16_t denied,
                           struct connect4_worker *worker, atomic_int *release_seen)
{
    int gate[2], ready[2];
    *worker = (struct connect4_worker){-1, -1, -1, -1};
    if (pipe2(gate, O_CLOEXEC) < 0)
        return -1;
    if (pipe2(ready, O_CLOEXEC) < 0) {
        int error = errno;
        close(gate[0]);
        close(gate[1]);
        errno = error;
        return -1;
    }
    pid_t child = fork();
    if (child == 0) {
        int gate_read = fcntl(gate[0], F_DUPFD_CLOEXEC, 5);
        int ready_write = fcntl(ready[1], F_DUPFD_CLOEXEC, 5);
        if (gate_read < 0 || ready_write < 0)
            _exit(69);
        int gate_target = dup3(gate_read, 3, O_CLOEXEC);
        if (gate_target < 0)
            _exit(69);
        int ready_target = dup3(ready_write, 4, O_CLOEXEC);
        if (ready_target < 0) {
            close(gate_target);
            _exit(69);
        }
        close(gate_read);
        close(ready_write);
        int status = run_connect4_worker(allowed, denied, release_seen);
        close(gate_target);
        /* The worker closes the readiness end after its notification.
         * On a setup failure it may still be open. */
        close(ready_target);
        _exit(status);
    }

    int error = errno;
    close(gate[0]);
    close(ready[1]);
    if (child > 0) {
        int pidfd = retain_connect4_worker(child);
        if (pidfd >= 0) {
            *worker = (struct connect4_worker){child, pidfd, gate[1], ready[0]};
            return 0;
        }
        error = errno;
    }
    close(gate[1]);
    close(ready[0]);
    if (child > 0) {
        /* This manager is the sole reaper. The PID cannot have been reused. */
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
    }
    errno = error;
    return -1;
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
        result = release_connect4_worker(trial->state_fd, worker.gate,
                                            worker.ready, controller_pidfd,
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
    if (syscall(SYS_pidfd_send_signal, worker.pidfd, SIGKILL, NULL, 0) < 0 &&
        errno != ESRCH)
        saved = errno;
    struct pollfd exited = { .fd = worker.pidfd, .events = POLLIN };
    if (poll(&exited, 1, 2000) == 1 && confirm_worker_exit(worker.pidfd) == 0) {
        int recovered = pinned ? recover_connect4_pin(trial->state_fd, trial->pin_path, worker.pidfd,
                                 trial->cgroup_fd, trial->device, trial->cgroup_id,
                                 trial->link_id, trial->program_id)
            : confirm_unpinned_connect4_trial(trial);
        if (recovered < 0) {
            *pending = (struct connect4_pending_recovery){worker.pid, worker.pidfd,
                CONNECT4_PIN_UNKNOWN};
            return -1;
        }
        *pending = (struct connect4_pending_recovery){worker.pid, worker.pidfd,
            pinned ? CONNECT4_PIN_REMOVED : CONNECT4_PIN_ABSENT};
        if (retry_connect4_recovery(trial, pending) < 0)
            return -1;
        fputs("worker_exit_observed=1 worker_reaped_by_pidfd=1\n", stderr);
    } else {
        *pending = (struct connect4_pending_recovery){worker.pid, worker.pidfd,
            pinned ? CONNECT4_PIN_HELD : CONNECT4_PIN_UNKNOWN};
        errno = ETIMEDOUT;
        return -1;
    }
    if (saved != 0) {
        errno = saved;
        return -1;
    }
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
