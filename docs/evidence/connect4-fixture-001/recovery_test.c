/* Unprivileged recovery regression. This test does not load BPF. */
#include "policy.c"
#include <assert.h>

static void check_controller_death(void)
{
    int control[2];
    assert(pipe(control) == 0);
    pid_t controller = fork();
    assert(controller >= 0);
    if (controller == 0) {
        close(control[1]);
        char byte;
        _exit(read(control[0], &byte, 1) != 0);
    }
    close(control[0]);
    int fd = retain_connect4_worker(controller);
    assert(fd >= 0 && controller_is_live(fd) == 0);
    assert(syscall(SYS_pidfd_send_signal, fd, SIGKILL, NULL, 0) == 0);
    struct pollfd exited = { .fd = fd, .events = POLLIN };
    assert(poll(&exited, 1, 2000) == 1);
    assert(controller_is_live(fd) == -1 && errno == ECANCELED);
    int status;
    assert(waitpid(controller, &status, 0) == controller);
    assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    close(fd);
    close(control[1]);
    puts("controller_killed=ECANCELED");
}

static unsigned count_open_descriptors(void)
{
    DIR *table = opendir("/proc/self/fd");
    assert(table != NULL);
    unsigned count = 0;
    while (readdir(table) != NULL)
        ++count;
    assert(closedir(table) == 0);
    return count;
}

static void check_invalid_handoff(void)
{
    int channel[2];
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) == 0);
    int original = (int)syscall(SYS_pidfd_open, getpid(), 0);
    assert(original >= 0);
    const unsigned baseline = count_open_descriptors();
    for (unsigned n = 2; n <= 3; ++n) {
        int descriptors[] = {original, original, original};
        pid_t pid = getpid();
        struct iovec payload = {.iov_base = &pid, .iov_len = sizeof(pid)};
        union {
            struct cmsghdr align;
            char bytes[CMSG_SPACE(sizeof(descriptors))];
        } control = {0};
        struct msghdr message = {
            .msg_iov = &payload, .msg_iovlen = 1,
            .msg_control = control.bytes,
            .msg_controllen = CMSG_SPACE(n * sizeof(int)),
        };
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(n * sizeof(int));
        memcpy(CMSG_DATA(header), descriptors, n * sizeof(int));
        assert(sendmsg(channel[0], &message, 0) == sizeof(pid));
        struct connect4_pending_recovery pending = {-1, -1, CONNECT4_PIN_UNKNOWN};
        assert(acknowledge_connect4_handoff(channel[1], NULL, pid, &pending) < 0);
        assert(errno == EPROTO && pending.pidfd == -1);
        char ack;
        assert(recv(channel[0], &ack, sizeof(ack), MSG_DONTWAIT) < 0);
        assert(errno == EAGAIN || errno == EWOULDBLOCK);
        assert(count_open_descriptors() == baseline);
    }
    close(original);
    close(channel[0]);
    close(channel[1]);
    puts("extra_or_truncated_fds=rejected-and-closed ack=absent");
}

int main(void)
{
    assert(empty_supplementary_groups("\t \n"));
    assert(!empty_supplementary_groups("\t 62004 \n"));
    assert(!empty_supplementary_groups("\t "));
    check_controller_death();
    check_invalid_handoff();
    int gate[2];
    assert(pipe(gate) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(gate[1]);
        char byte;
        _exit(read(gate[0], &byte, 1) != 0);
    }
    close(gate[0]);
    int fd = retain_connect4_worker(child);
    assert(fd >= 0);
    struct connect4_pending_recovery pending = {
        child, fd, CONNECT4_PIN_REMOVED,
    };
    assert(retry_connect4_recovery(NULL, &pending) == -1 && errno == EBUSY);
    close(gate[1]);
    struct pollfd exited = { .fd = fd, .events = POLLIN };
    assert(poll(&exited, 1, 2000) == 1);
    pending.phase = CONNECT4_PIN_UNKNOWN;
    assert(retry_connect4_recovery(NULL, &pending) == -1 && errno == ESTALE);
    pending.phase = CONNECT4_PIN_REMOVED;
    assert(retry_connect4_recovery(NULL, &pending) == 0 && pending.pidfd == -1);
    assert(waitpid(child, NULL, WNOHANG) == -1 && errno == ECHILD);
    puts("live=EBUSY unknown=ESTALE exited=reaped");
}
