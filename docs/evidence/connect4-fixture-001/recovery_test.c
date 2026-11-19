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

int main(void)
{
    check_controller_death();
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
