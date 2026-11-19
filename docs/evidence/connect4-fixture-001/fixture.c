/* Fixed-host fixture entry under review. */
#include "policy.c"

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1 || geteuid() != 0) {
        fputs("requires root and no arguments\n", stderr);
        return 2;
    }
    umask(0077);
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        return 2;

    int control[2];
    if (pipe2(control, O_CLOEXEC) < 0)
        return 1;
    pid_t controller = fork();
    if (controller < 0)
        return 1;
    if (controller == 0) {
        close(control[1]);
        char byte;
        _exit(read(control[0], &byte, 1) != 0);
    }
    close(control[0]);
    int controller_pidfd = retain_connect4_worker(controller);
    if (controller_pidfd < 0) {
        close(control[1]);
        waitpid(controller, NULL, 0);
        return 1;
    }

    int state, cgroup;
    if (create_connect4_fixture_state(&state, &cgroup) < 0) {
        perror("fixture state");
        close(control[1]);
        waitpid(controller, NULL, 0);
        return 1;
    }
    int result = -1;
    int denied = -1;
    struct connect4_trial trial = { .link_fd = -1 };
    uint16_t allowed_port, denied_port;
    int allowed = open_connect4_listener(&allowed_port);
    if (allowed < 0) {
        perror("allowed listener");
        goto done;
    }
    denied = open_connect4_listener(&denied_port);
    if (denied < 0) {
        perror("denied listener");
        goto done;
    }
    if (prepare_connect4_trial(state, cgroup, CONNECT4_PIN_PATH,
                               allowed_port, &trial) < 0) {
        perror("prepare trial");
        goto done;
    }
    struct connect4_pending_recovery pending;
    struct connect4_phase phases[3];
    atomic_int *release_seen = NULL;
    if (CONNECT4_CASE == 2) {
        release_seen = mmap(NULL, sizeof(*release_seen), PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (release_seen == MAP_FAILED) {
            perror("release synchronization");
            goto done;
        }
        atomic_init(release_seen, 0);
    }
    result = run_connect4_trial(&trial, controller_pidfd, CONNECT4_CASE == 1,
                                release_seen, allowed, allowed_port,
                                    denied, denied_port, phases, &pending);
    if (result < 0)
        perror("connect4 trial");
    if (release_seen != NULL)
        munmap(release_seen, sizeof(*release_seen));
    if (pending.pidfd >= 0) {
        result = -1;
        while (retry_connect4_recovery(&trial, &pending) < 0) {
            if (errno != EBUSY && errno != EWOULDBLOCK && errno != EINTR) {
                perror("connect4 recovery held for inspection");
                /* Preserve the original pidfd, link and cgroup until a
                 * recovery supervisor can take ownership. */
                for (;;)
                    pause();
            }
            sleep(1);
        }
    }
    for (unsigned i = 0; i < 3; ++i)
        printf("phase=%u allowed=%d denied=%d code=%d status=%d\n",
               i, phases[i].allowed_accepts, phases[i].denied_accepts,
               phases[i].worker_code, phases[i].worker_status);
done:
    if (trial.link_fd >= 0)
        close(trial.link_fd);
    if (allowed >= 0)
        close(allowed);
    if (denied >= 0)
        close(denied);
    if (remove_connect4_fixture_cgroup(state, cgroup) < 0) {
        perror("fixture cgroup cleanup");
        result = -1;
    } else if (retire_connect4_fixture_state(state) < 0) {
        perror("fixture state retirement");
        result = -1;
    }
    close(cgroup);
    close(state);
    close(control[1]);
    close(controller_pidfd);
    waitpid(controller, NULL, 0);
    return result == 0 ? 0 : 1;
}
