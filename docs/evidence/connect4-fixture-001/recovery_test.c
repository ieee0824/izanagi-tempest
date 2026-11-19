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
    const unsigned char frame[7 + 4 + 40] = {0xff, 3, 1, 4, 0, 0, 0, 't', 'e', 's', 't'};
    assert(write(input[1], frame, sizeof(frame)) == sizeof(frame));
    int64_t now = monotonic_ns();
    assert(now >= 0);
    assert(transfer_authenticated_frame(input[0], output[1], 1, now) < 0 && errno == ETIMEDOUT);
    int64_t deadline = now + 1000000000;
    assert(transfer_authenticated_frame(input[0], output[1], 1, deadline) == 0);
    unsigned char result[sizeof(frame)];
    assert(read(output[0], result, sizeof(result)) == sizeof(result));
    assert(memcmp(result, frame, sizeof(result)) == 0);
    const unsigned char oversized[] = {0xff, 3, 1, 1, 16, 0, 0};
    assert(write(input[1], oversized, sizeof(oversized)) == sizeof(oversized));
    assert(transfer_authenticated_frame(input[0], output[1], 1, deadline) < 0 && errno == EMSGSIZE);
    assert(read(output[0], result, sizeof(result)) < 0 && errno == EAGAIN);
    assert(write(input[1], frame, 7) == 7);
    close(input[1]);
    assert(transfer_authenticated_frame(input[0], output[1], 1, deadline) < 0 && errno == EPIPE);
    assert(read(output[0], result, sizeof(result)) < 0 && errno == EAGAIN);
    close(input[0]);
    close(output[0]);
    close(output[1]);
}

static void check_fixed_agent_exchange(void)
{
    int input[2], output[2], connect_status[2], gate[2], readiness[2];
    assert(pipe2(input, O_CLOEXEC | O_NONBLOCK) == 0);
    assert(pipe2(output, O_CLOEXEC | O_NONBLOCK) == 0);
    assert(pipe2(connect_status, O_CLOEXEC | O_NONBLOCK) == 0);
    assert(pipe2(gate, O_CLOEXEC) == 0);
    assert(pipe2(readiness, O_CLOEXEC) == 0);
    uint16_t port;
    int listener = open_connect4_listener(&port);
    assert(listener >= 0);
    unsigned char request[2][47] = {{0xff, 3, 5}, {0xff, 3, 6}};
    unsigned char response[3][47] = {{0xff, 3, 5}, {0xff, 3, 3}, {0xff, 3, 7}};
    int64_t now = monotonic_ns();
    assert(now >= 0);
    int64_t deadline = now + 2000000000;
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        const int inherited[] = {gate[0], readiness[1], input[0], output[1], connect_status[1]};
        int temporary[sizeof(inherited) / sizeof(inherited[0])];
        for (size_t i = 0; i < sizeof(temporary) / sizeof(temporary[0]); ++i) {
            temporary[i] = fcntl(inherited[i], F_DUPFD_CLOEXEC, 8);
            if (temporary[i] < 0)
                _exit(7);
        }
        for (size_t i = 0; i < sizeof(temporary) / sizeof(temporary[0]); ++i) {
            if (dup3(temporary[i], 3 + (int)i, O_CLOEXEC) < 0)
                _exit(7);
        }
        if (syscall(SYS_close_range, 0U, 2U, 0U) < 0 ||
            syscall(SYS_close_range, 8U, ~0U, 0U) < 0)
            _exit(7);
        if (prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) < 0 ||
            restrict_fixed_relay_setup() < 0 ||
            socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0) != -1 ||
            errno != EPERM)
            _exit(6);
        if (write(4, "Y", 1) != 1 || close(4) < 0 || await_connect4_release(3) < 0)
            _exit(7);
        close(3);
        int socket_fd = open_fixed_relay_connection(port, deadline);
        int connect_errno = socket_fd < 0 ? errno : 0;
        if (write(7, &connect_errno, sizeof(connect_errno)) != sizeof(connect_errno))
            _exit(5);
        close(7);
        if (socket_fd < 0)
            _exit(1);
        if (restrict_fixed_relay_io(5, 6, socket_fd) < 0)
            _exit(3);
        if (write(STDERR_FILENO, "", 0) != -1 || errno != EPERM ||
            socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP) != -1 ||
            errno != EPERM)
            _exit(4);
        if (relay_fixed_agent_request(5, 6, socket_fd, deadline) < 0)
            _exit(2);
        _exit(relay_fixed_agent_request(5, 6, socket_fd, deadline) == 0 ||
              errno != EPROTO);
    }
    close(input[0]);
    close(output[1]);
    close(connect_status[1]);
    close(gate[0]);
    close(readiness[1]);
    const struct worker_pipe pipes[] = {
        {3, O_RDONLY, gate[1], O_WRONLY},
        {5, O_RDONLY, input[1], O_WRONLY},
        {6, O_WRONLY, output[0], O_RDONLY},
        {7, O_WRONLY, connect_status[0], O_RDONLY},
    };
    assert(confirm_connect4_ready(readiness[0]) == 0);
    close(readiness[0]);
    assert(check_worker_pipes(child, pipes, sizeof(pipes) / sizeof(pipes[0])) == 0);
    assert(count_connect4_accepts(listener) == 0);
    assert(write(gate[1], "R", 1) == 1);
    close(gate[1]);
    int connect_errno;
    assert(read_before(connect_status[0], &connect_errno, sizeof(connect_errno), deadline) == 0);
    assert(connect_errno == 0);
    close(connect_status[0]);
    struct pollfd ready = {.fd = listener, .events = POLLIN};
    assert(poll_before(&ready, deadline) == 0);
    int peer = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    assert(peer >= 0);
    close(listener);
    assert(write_before(input[1], request, sizeof(request), deadline) == 0);
    assert(write_before(peer, response, sizeof(response), deadline) == 0);
    unsigned char observed[sizeof(response)];
    assert(read_before(peer, observed, sizeof(request), deadline) == 0);
    assert(memcmp(observed, request, sizeof(request)) == 0);
    assert(read_before(output[0], observed, sizeof(response), deadline) == 0);
    assert(memcmp(observed, response, sizeof(response)) == 0);
    assert(write_before(input[1], request[1], sizeof(request[1]), deadline) == 0);
    ready = (struct pollfd){.fd = peer, .events = POLLIN};
    assert(poll_before(&ready, deadline) == 0);
    assert(read(peer, observed, sizeof(observed)) == 0);
    int status;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(peer);
    close(input[1]);
    close(output[0]);
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
    check_fixed_agent_exchange();
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
