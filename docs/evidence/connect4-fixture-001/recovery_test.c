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

static void check_worker_pipe_identity(void)
{
    int gate[2], response[2], unrelated[2];
    assert(pipe2(gate, O_CLOEXEC) == 0);
    assert(pipe2(response, O_CLOEXEC) == 0);
    assert(pipe2(unrelated, O_CLOEXEC) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        int gate_end = fcntl(gate[0], F_DUPFD_CLOEXEC, 8);
        int response_end = fcntl(response[1], F_DUPFD_CLOEXEC, 8);
        if (gate_end < 0 || response_end < 0 ||
            dup3(gate_end, 3, O_CLOEXEC) < 0 || dup3(response_end, 4, O_CLOEXEC) < 0 ||
            syscall(SYS_close_range, 0U, 2U, 0U) < 0 ||
            syscall(SYS_close_range, 5U, ~0U, 0U) < 0)
            _exit(1);
        char byte = 'Y';
        if (write(4, &byte, 1) != 1)
            _exit(2);
        _exit(read(3, &byte, 1) != 0);
    }
    close(gate[0]);
    close(response[1]);
    struct pollfd ready = {.fd = response[0], .events = POLLIN};
    char byte;
    int synchronized = poll(&ready, 1, 2000) == 1 && read(response[0], &byte, 1) == 1 && byte == 'Y';
    struct worker_pipe pipes[] = {
        {3, O_RDONLY, gate[1], O_WRONLY},
        {4, O_WRONLY, response[0], O_RDONLY},
    };
    int valid = synchronized && check_worker_pipes(child, pipes, 2) == 0;
    int extra = valid && check_worker_pipes(child, pipes, 1) < 0 && errno == ESTALE;
    pipes[1].parent_fd = unrelated[0];
    int wrong_inode = valid && check_worker_pipes(child, pipes, 2) < 0 && errno == ESTALE;
    close(gate[1]);
    close(response[0]);
    close(unrelated[0]);
    close(unrelated[1]);
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(valid && extra && wrong_inode && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void check_worker_owned_connection(void)
{
    uint16_t port;
    int listener = open_connect4_listener(&port);
    assert(listener >= 0);
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(listener);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) < 0 ||
            restrict_connect4_worker() < 0)
            _exit(1);
        if (socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0) != -1 || errno != EPERM)
            _exit(2);
        int connected;
        if (connect4_loopback(port, &connected) != 0)
            _exit(3);
        char marker;
        _exit(read(connected, &marker, sizeof(marker)) != sizeof(marker) || marker != 'T');
    }
    struct pollfd ready = {.fd = listener, .events = POLLIN};
    int event = poll(&ready, 1, 2000);
    int peer = event == 1 ? accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK) : -1;
    close(listener);
    ssize_t sent = -1;
    if (peer >= 0) {
        const char marker = 'T';
        sent = send(peer, &marker, sizeof(marker), MSG_NOSIGNAL);
        close(peer);
    } else {
        kill(child, SIGKILL);
    }
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(sent == 1 && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void check_fixed_transfer(void)
{
    int input[2], output[2];
    assert(pipe2(input, O_CLOEXEC | O_NONBLOCK) == 0);
    assert(pipe2(output, O_CLOEXEC | O_NONBLOCK) == 0);
    assert(write(input[1], "test", 4) == 4);
    int64_t now = monotonic_ns();
    assert(now >= 0);
    assert(transfer_fixed_bytes(input[0], output[1], 4, now) < 0 && errno == ETIMEDOUT);
    int64_t deadline = now + 1000000000;
    assert(transfer_fixed_bytes(input[0], output[1], 4, deadline) == 0);
    char result[4];
    assert(read(output[0], result, sizeof(result)) == sizeof(result));
    assert(memcmp(result, "test", sizeof(result)) == 0);
    close(input[1]);
    assert(transfer_fixed_bytes(input[0], output[1], 1, deadline) < 0 && errno == EPIPE);
    close(input[0]);
    close(output[0]);
    close(output[1]);
}

int main(void)
{
    assert(empty_supplementary_groups("\t \n"));
    assert(!empty_supplementary_groups("\t 62004 \n"));
    assert(!empty_supplementary_groups("\t "));
    check_controller_death();
    check_invalid_handoff();
    check_worker_pipe_identity();
    check_worker_owned_connection();
    check_fixed_transfer();
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
