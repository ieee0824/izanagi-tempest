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

static void check_fixed_agent_exchange(int early_exec, int close_gate)
{
    int privileged = geteuid() == 0;
    uint16_t port;
    int listener = open_connect4_listener(&port);
    assert(listener >= 0);
    unsigned char request[2][47] = {{0xff, 3, 5}, {0xff, 3, 6}};
    unsigned char response[3][47] = {{0xff, 3, 5}, {0xff, 3, 3}, {0xff, 3, 7}};
    int64_t now = monotonic_ns();
    assert(now >= 0);
    int64_t deadline = now + 2000000000;
    struct connect4_worker worker;
    struct fixed_relay_pipes relay;
    assert(spawn_fixed_relay_worker(port, deadline, &worker, &relay) == 0);
    pid_t child = worker.pid;
    struct worker_pipe pipes[FIXED_RELAY_PIPE_COUNT];
    describe_fixed_relay_pipes(&worker, &relay, pipes);
    assert(confirm_connect4_ready(worker.ready) == 0);
    close(worker.ready);
    if (privileged)
        assert(check_connect4_worker_privileges(child) == 0);
    assert(check_worker_pipes(child, pipes, sizeof(pipes) / sizeof(pipes[0])) == 0);
    assert(count_connect4_accepts(listener) == 0);
    if (!close_gate)
        assert(write(worker.gate, "R", 1) == 1);
    close(worker.gate);
    int connect_errno;
    if (close_gate) {
        assert(read_fixed_relay_connect_errno(&relay, deadline, &connect_errno) < 0 &&
               errno == EPIPE);
        int status;
        assert(waitpid(child, &status, 0) == child);
        close(worker.pidfd);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 1);
        assert(count_connect4_accepts(listener) == 0);
        close(relay.status);
        close(listener);
        close(relay.request);
        close(relay.response);
        return;
    }
    assert(read_fixed_relay_connect_errno(&relay, deadline, &connect_errno) == 0);
    assert(connect_errno == 0);
    close(relay.status);
    struct pollfd ready = {.fd = listener, .events = POLLIN};
    assert(poll_before(&ready, deadline) == 0);
    int peer = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    assert(peer >= 0);
    close(listener);
    unsigned char observed[sizeof(response)];
    if (early_exec) {
        assert(write_before(relay.request, request[1], sizeof(request[1]), deadline) == 0);
    } else {
        assert(write_before(relay.request, request, sizeof(request), deadline) == 0);
        assert(write_before(peer, response, sizeof(response), deadline) == 0);
        assert(read_before(peer, observed, sizeof(request), deadline) == 0);
        assert(memcmp(observed, request, sizeof(request)) == 0);
        assert(read_before(relay.response, observed, sizeof(response), deadline) == 0);
        assert(memcmp(observed, response, sizeof(response)) == 0);
    }
    ready = (struct pollfd){.fd = peer, .events = POLLIN};
    assert(poll_before(&ready, deadline) == 0);
    assert(read(peer, observed, sizeof(observed)) == 0);
    int relay_exit;
    assert(observe_fixed_relay_exit(&worker, deadline, &relay_exit) == 0);
    assert(relay_exit == (early_exec ? 2 : 0));
    int status;
    assert(waitpid(child, &status, 0) == child);
    close(worker.pidfd);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == (early_exec ? 2 : 0));
    close(peer);
    close(relay.request);
    close(relay.response);
}

static void check_fixed_alternate_exchange(int wrong_token)
{
    uint16_t port;
    int listener = open_connect4_listener(&port);
    assert(listener >= 0);
    int64_t deadline = monotonic_ns() + 2000000000;
    struct connect4_worker worker;
    struct fixed_relay_pipes relay;
    assert(spawn_fixed_alternate_worker(port, deadline, &worker, &relay) == 0);
    assert(confirm_connect4_ready(worker.ready) == 0);
    assert(write(worker.gate, "R", 1) == 1);
    int connect_errno;
    assert(read_fixed_relay_connect_errno(&relay, deadline, &connect_errno) == 0);
    assert(connect_errno == 0);
    struct pollfd ready = {.fd = listener, .events = POLLIN};
    assert(poll_before(&ready, deadline) == 0);
    int peer = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    assert(peer >= 0);

    char token[sizeof(alternate_request)];
    memcpy(token, alternate_request, sizeof(token));
    if (wrong_token)
        token[0] = 'X';
    assert(write_before(relay.request, token, sizeof(token) - 1, deadline) == 0);
    if (wrong_token) {
        assert(read_before(peer, token, 1, deadline) < 0 && errno == EPIPE);
    } else {
        assert(read_before(peer, token, sizeof(token) - 1, deadline) == 0);
        assert(memcmp(token, alternate_request, sizeof(token) - 1) == 0);
        assert(write_before(peer, alternate_response, sizeof(alternate_response) - 1,
                            deadline) == 0);
        assert(read_before(relay.response, token, sizeof(alternate_response) - 1,
                           deadline) == 0);
        assert(memcmp(token, alternate_response, sizeof(alternate_response) - 1) == 0);
    }

    int worker_exit;
    assert(observe_fixed_relay_exit(&worker, deadline, &worker_exit) == 0);
    assert(worker_exit == (wrong_token ? 2 : 0));
    assert(waitpid(worker.pid, NULL, 0) == worker.pid);
    close(worker.pidfd);
    close(worker.ready);
    close(worker.gate);
    close(relay.request);
    close(relay.response);
    close(relay.status);
    close(peer);
    close(listener);
}

static void check_fixed_relay_refused_connection(void)
{
    int reserved = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    assert(reserved >= 0);
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)},
    };
    assert(bind(reserved, (struct sockaddr *)&address, sizeof(address)) == 0);
    socklen_t size = sizeof(address);
    assert(getsockname(reserved, (struct sockaddr *)&address, &size) == 0);

    int64_t now = monotonic_ns();
    assert(now >= 0);
    int64_t deadline = now + 2000000000;
    struct connect4_worker worker;
    struct fixed_relay_pipes relay;
    assert(spawn_fixed_relay_worker(ntohs(address.sin_port), deadline, &worker, &relay) == 0);
    assert(confirm_connect4_ready(worker.ready) == 0);
    assert(write(worker.gate, "R", 1) == 1);
    int connect_errno, relay_exit;
    assert(read_fixed_relay_connect_errno(&relay, deadline, &connect_errno) == 0);
    assert(connect_errno == ECONNREFUSED);
    assert(observe_fixed_relay_exit(&worker, deadline, &relay_exit) == 0);
    assert(relay_exit == 1);
    assert(waitpid(worker.pid, NULL, 0) == worker.pid);
    close(worker.pidfd);
    close(worker.ready);
    close(worker.gate);
    close(relay.request);
    close(relay.response);
    close(relay.status);
    close(reserved);
}

static void check_adopted_relay(void)
{
    assert(prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0);
    uint16_t port;
    int listener = open_connect4_listener(&port);
    int channel[2], gate[2], ready[2], input[2], output[2], connect_status[2];
    assert(listener >= 0);
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) == 0);
    assert(pipe2(gate, O_CLOEXEC) == 0);
    assert(pipe2(ready, O_CLOEXEC) == 0);
    assert(pipe2(input, O_CLOEXEC | O_NONBLOCK) == 0);
    assert(pipe2(output, O_CLOEXEC | O_NONBLOCK) == 0);
    assert(pipe2(connect_status, O_CLOEXEC | O_NONBLOCK) == 0);
    int64_t now = monotonic_ns();
    assert(now >= 0);
    int64_t deadline = now + 3000000000;
    pid_t supervisor = fork();
    assert(supervisor >= 0);
    if (supervisor == 0) {
        close(channel[0]);
        pid_t worker = fork();
        if (worker == 0) {
            const int inherited[] = {gate[0], ready[1], input[0], output[1], connect_status[1]};
            if (map_worker_pipes(inherited, 5) < 0 ||
                prctl(PR_SET_NO_NEW_PRIVS, 1UL, 0UL, 0UL, 0UL) < 0)
                _exit(9);
            _exit(run_fixed_relay_worker(port, deadline));
        }
        close(ready[1]);
        int worker_fd = retain_connect4_worker(worker);
        if (worker_fd < 0 || confirm_connect4_ready(ready[0]) < 0 ||
            handoff_connect4_worker_fd(channel[1], worker, worker_fd) < 0 ||
            write(gate[1], "R", 1) != 1)
            _exit(10);
        pause();
        _exit(11);
    }

    close(channel[1]);
    close(gate[0]);
    close(gate[1]);
    close(ready[0]);
    close(ready[1]);
    close(input[0]);
    close(output[1]);
    close(connect_status[1]);

    int supervisor_fd = retain_connect4_worker(supervisor);
    assert(supervisor_fd >= 0);
    struct pollfd handoff = {.fd = channel[0], .events = POLLIN};
    assert(poll_before(&handoff, deadline) == 0);
    pid_t worker;
    int worker_fd = receive_connect4_worker_fd(channel[0], &worker);
    assert(worker_fd >= 0 && send(channel[0], "A", 1, MSG_NOSIGNAL) == 1);
    int connect_errno;
    assert(read_before(connect_status[0], &connect_errno, sizeof(connect_errno), deadline) == 0);
    assert(connect_errno == 0 && count_connect4_accepts(listener) == 1);

    assert(syscall(SYS_pidfd_send_signal, supervisor_fd, SIGKILL, NULL, 0) == 0);
    siginfo_t status = {0};
    assert(waitid(P_PIDFD, supervisor_fd, &status, WEXITED | WNOWAIT) == 0);
    assert(status.si_pid == supervisor && status.si_code == CLD_KILLED);
    assert(stop_adopted_connect4_worker(supervisor_fd, worker, worker_fd) == 0);
    assert(waitid(P_PIDFD, worker_fd, &status, WEXITED) == 0);
    assert(status.si_pid == worker && status.si_code == CLD_KILLED && status.si_status == SIGKILL);
    assert(waitid(P_PIDFD, supervisor_fd, &status, WEXITED) == 0);
    close(worker_fd);
    close(supervisor_fd);
    close(channel[0]);
    close(listener);
    close(input[1]);
    close(output[0]);
    close(connect_status[0]);
    puts("connected relay adopted and reaped after supervisor SIGKILL");
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
    check_fixed_agent_exchange(0, 0);
    check_fixed_agent_exchange(1, 0);
    check_fixed_agent_exchange(0, 1);
    check_fixed_relay_refused_connection();
    check_fixed_alternate_exchange(0);
    check_fixed_alternate_exchange(1);
    check_adopted_relay();
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
