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
            if ((seen & (1U << field)) || strcmp(line, required[field]) != 0)
                goto done;
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

static int worker_gate_is_read_end(pid_t child)
{
    char path[64], line[128];
    snprintf(path, sizeof(path), "/proc/%ld/fdinfo/3", (long)child);
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
                (flags & (O_PATH | O_ACCMODE)) != O_RDONLY)
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

/* The fixed worker retains only gate read end 3 at this stage. */
static int check_connect4_worker_fds(pid_t child, int gate_fd)
{
    struct stat writer, reader;
    int flags = fcntl(gate_fd, F_GETFL);
    if (flags < 0 || fstat(gate_fd, &writer) < 0)
        return -1;
    if ((flags & (O_PATH | O_ACCMODE)) != O_WRONLY || !S_ISFIFO(writer.st_mode)) {
        errno = ESTALE;
        return -1;
    }
    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/fd", (long)child);
    DIR *table = opendir(path);
    if (!table)
        return -1;
    int found = 0;
    int verified = 0;
    for (unsigned i = 0; i < 8; ++i) {
        errno = 0;
        struct dirent *entry = readdir(table);
        if (!entry) {
            verified = errno == 0 && found;
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        if (found || strcmp(entry->d_name, "3") != 0 ||
            fstatat(dirfd(table), "3", &reader, 0) < 0 ||
            !S_ISFIFO(reader.st_mode) || reader.st_dev != writer.st_dev ||
            reader.st_ino != writer.st_ino)
            break;
        found = 1;
    }
    closedir(table);
    if (!verified) {
        errno = ESTALE;
        return -1;
    }
    return worker_gate_is_read_end(child);
}

/* The manager has closed its own copy of the readiness write end. */
static int confirm_connect4_ready(int ready_fd)
{
    if (ready_fd < 0) {
        errno = EBADF;
        return -1;
    }
    struct pollfd ready = { .fd = ready_fd, .events = POLLIN };
    for (unsigned phase = 0; phase < 2; ++phase) {
        int result = poll(&ready, 1, 1000);
        if (result < 0)
            return -1;
        if (result == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
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

/* The manager owns the worker and holds its original pidfd. Gate FD is
 * a private pipe write end that only the manager can use. */
int release_connect4_worker(int state_fd, int gate_fd, int ready_fd,
                            pid_t child, int worker_pidfd,
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
    } else if (confirm_connect4_ready(ready_fd) == 0 &&
               waitid(P_PIDFD, (id_t)worker_pidfd, &status,
                      WEXITED | WNOHANG | WNOWAIT) == 0) {
        if (status.si_pid != 0)
            errno = ESRCH;
        else if (check_connect4_pidfd_pid(worker_pidfd, child) == 0 &&
                 check_connect4_worker_membership(cgroup_fd, child) == 0)
            verified = pin_and_verify_connect4_link(link_fd, path, cgroup_fd,
                                                     device, cgroup_id, link_id,
                                                     program_id);
    }
    int result = -1;
    if (verified >= 0 &&
        check_connect4_worker_privileges(child) == 0 &&
        check_connect4_worker_fds(child, gate_fd) == 0 &&
        check_connect4_worker_membership(cgroup_fd, child) == 0 &&
        waitid(P_PIDFD, (id_t)worker_pidfd, &status,
               WEXITED | WNOHANG | WNOWAIT) == 0) {
        if (status.si_pid != 0) {
            errno = ESRCH;
            goto done;
        }
        if (record_release_intent(state_fd) < 0)
            goto done;
        const char token = 'R';
        ssize_t sent = write(gate_fd, &token, sizeof(token));
        if (sent == 1)
            result = 0;
        else if (sent == 0)
            errno = EIO;
    }
done:;
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
    if (sent != sizeof(ready) || closed < 0)
        return -1;
    return await_connect4_release(3);
}

static int try_connect4_loopback(uint16_t port)
{
    const struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) },
    };
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (fd < 0)
        return -1;
    int result = connect(fd, (const struct sockaddr *)&address, sizeof(address));
    int error = result < 0 ? errno : 0;
    close(fd);
    return error;
}

/* Call in the dedicated child. The manager observes the actual exit status
 * and separately counts accepted connections on both listeners. */
static int run_connect4_worker(uint16_t allowed, uint16_t denied)
{
    if (allowed == 0 || denied == 0 || allowed == denied ||
        connect4_worker_wait() < 0)
        return 70;
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
int measure_connect4_worker(int pidfd, int allowed_listener, int denied_listener,
                            struct connect4_phase *phase)
{
    *phase = (struct connect4_phase){-1, -1, -1, -1};
    struct pollfd worker = { .fd = pidfd, .events = POLLIN };
    int ready = poll(&worker, 1, 2000);
    if (ready < 0)
        return -1;
    if (ready == 0) {
        errno = ETIMEDOUT;
        return -1;
    }
    if (confirm_worker_exit(pidfd) < 0)
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
                           struct connect4_worker *worker)
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
        int status = run_connect4_worker(allowed, denied);
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

/* The manager supplies a fresh, registered trial and retains ownership of
 * its cgroup and original link FD, including on recovery failure. */
int run_connect4_trial(const struct connect4_trial *trial,
                       int allowed_listener, uint16_t allowed_port,
                       int denied_listener, uint16_t denied_port,
                       struct connect4_phase phases[static 3],
                       struct connect4_worker *pending)
{
    *pending = (struct connect4_worker){-1, -1, -1, -1};
    for (unsigned i = 0; i < 3; ++i)
        phases[i] = (struct connect4_phase){-1, -1, -1, -1};
    if (measure_connect4_control(allowed_listener, allowed_port, denied_listener,
                                 denied_port, &phases[0]) < 0)
        return -1;

    struct connect4_worker worker;
    if (spawn_connect4_worker(allowed_port, denied_port, &worker) < 0)
        return -1;
    int result = place_connect4_worker(trial->state_fd, trial->cgroup_fd,
                                         trial->device, trial->cgroup_id,
                                         worker.pid, worker.pidfd);
    if (result == 0)
        result = release_connect4_worker(trial->state_fd, worker.gate,
                                            worker.ready, worker.pid, worker.pidfd,
                                            trial->link_fd, trial->pin_path,
                                            trial->cgroup_fd, trial->device,
                                            trial->cgroup_id, trial->link_id,
                                            trial->program_id);
    close(worker.gate);
    close(worker.ready);
    if (result == 0)
        result = measure_connect4_worker(worker.pidfd, allowed_listener,
                                            denied_listener, &phases[1]);

    int saved = result < 0 ? errno : 0;
    if (syscall(SYS_pidfd_send_signal, worker.pidfd, SIGKILL, NULL, 0) < 0 &&
        errno != ESRCH)
        saved = errno;
    struct pollfd exited = { .fd = worker.pidfd, .events = POLLIN };
    if (poll(&exited, 1, 2000) == 1 && confirm_worker_exit(worker.pidfd) == 0) {
        if (recover_connect4_pin(trial->state_fd, trial->pin_path, worker.pidfd,
                                 trial->cgroup_fd, trial->device, trial->cgroup_id,
                                 trial->link_id, trial->program_id) < 0) {
            *pending = (struct connect4_worker){worker.pid, worker.pidfd, -1, -1};
            return -1;
        }
        if (waitpid(worker.pid, NULL, WNOHANG) != worker.pid) {
            *pending = (struct connect4_worker){worker.pid, worker.pidfd, -1, -1};
            errno = ECHILD;
            return -1;
        }
    } else {
        *pending = (struct connect4_worker){worker.pid, worker.pidfd, -1, -1};
        errno = ETIMEDOUT;
        return -1;
    }
    close(worker.pidfd);
    if (saved != 0) {
        errno = saved;
        return -1;
    }
    return measure_connect4_control(allowed_listener, allowed_port, denied_listener,
                                      denied_port, &phases[2]);
}
