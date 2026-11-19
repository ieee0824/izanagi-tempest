/* Fixed-host fixture entry under review. */
#include "policy.c"

static int reap_unreleased_worker(const struct connect4_trial *trial, pid_t worker)
{
    if (worker <= 0) {
        errno = ESTALE;
        return -1;
    }
    const struct timespec interval = { .tv_nsec = 10000000 };
    for (unsigned attempts = 0; attempts < 200; ++attempts) {
        siginfo_t status = {0};
        if (waitid(P_PID, (id_t)worker, &status,
                   WEXITED | WNOHANG | WNOWAIT) < 0)
            return -1;
        if (status.si_pid == worker) {
            if (status.si_code != CLD_EXITED || status.si_status != 75) {
                errno = EPROTO;
                return -1;
            }
            if (confirm_unpinned_connect4_trial(trial) < 0 ||
                waitid(P_PID, (id_t)worker, &status, WEXITED | WNOHANG) < 0)
                return -1;
            return status.si_pid == worker ? 0 : -1;
        }
        nanosleep(&interval, NULL);
    }
    errno = ETIMEDOUT;
    return -1;
}

/* The upper owner created all trial resources before this fork. */
static int run_with_subreaper(const struct connect4_trial *trial,
                              int controller_pidfd, int allowed, uint16_t allowed_port,
                              int denied, uint16_t denied_port)
{
    if (prctl(PR_SET_CHILD_SUBREAPER, 1UL, 0UL, 0UL, 0UL) < 0)
        return -1;
    int channel[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) < 0)
        return -1;
    atomic_int *known_worker = mmap(NULL, 2 * sizeof(*known_worker),
                                     PROT_READ | PROT_WRITE,
                                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (known_worker == MAP_FAILED) {
        int error = errno;
        close(channel[0]);
        close(channel[1]);
        errno = error;
        return -1;
    }
    atomic_init(known_worker, 0);
    atomic_int *release_seen = known_worker + 1;
    atomic_init(release_seen, 0);
    pid_t supervisor = fork();
    if (supervisor < 0) {
        int error = errno;
        close(channel[0]);
        close(channel[1]);
        munmap(known_worker, 2 * sizeof(*known_worker));
        errno = error;
        return -1;
    }
    if (supervisor == 0) {
        close(channel[0]);
        struct connect4_phase phases[3];
        struct connect4_pending_recovery pending;
        int result = run_connect4_trial(trial, controller_pidfd, channel[1], known_worker,
                                        CONNECT4_CASE == 6 ? 1 : CONNECT4_CASE == 7 ? 2 : 0,
                                        0, CONNECT4_CASE == 7 ? release_seen : NULL, allowed, allowed_port, denied,
                                        denied_port, phases, &pending);
        for (unsigned i = 0; i < 3; ++i)
            fprintf(stderr, "phase=%u allowed=%d denied=%d code=%d status=%d\n",
                    i, phases[i].allowed_accepts, phases[i].denied_accepts,
                    phases[i].worker_code, phases[i].worker_status);
        _exit(result == 0 ? 0 : pending.pidfd >= 0 ? 2 : 1);
    }

    close(channel[1]);
    int supervisor_fd = (int)syscall(SYS_pidfd_open, supervisor, 0);
    struct connect4_pending_recovery worker = {-1, -1, CONNECT4_PIN_UNKNOWN};
    struct pollfd request = { .fd = channel[0], .events = POLLIN };
    if (supervisor_fd >= 0 && poll(&request, 1, 3000) == 1 &&
        (request.revents & POLLIN))
        (void)acknowledge_connect4_handoff(channel[0], trial,
            atomic_load_explicit(known_worker, memory_order_acquire), &worker);
    close(channel[0]);

    /* Keep the supervisor waitable until the upper owner has recovered
     * the adopted worker. A readable pidfd alone is insufficient. */
    siginfo_t status = {0};
    if (supervisor_fd < 0 ||
        waitid(P_PIDFD, (id_t)supervisor_fd, &status, WEXITED | WNOWAIT) < 0) {
        perror("supervisor identity unresolved");
        for (;;)
            pause();
    }
    int normal = status.si_code == CLD_EXITED && status.si_status == 0;
    if (!normal && worker.pidfd >= 0) {
        int reaped = 0;
        if (recover_adopted_connect4_worker(trial, supervisor_fd, &worker,
                                             &reaped) < 0) {
            perror("upper recovery held for inspection");
            for (;;)
                pause();
        }
        fprintf(stderr, "supervisor_exit_observed=1 adopted_worker_reaped=1 pin=%s\n",
                worker.phase == CONNECT4_PIN_REMOVED ? "removed" : "absent");
    } else if (!normal) {
        pid_t known = atomic_load_explicit(known_worker, memory_order_acquire);
        if (reap_unreleased_worker(trial, known) < 0) {
            perror("unreleased recovery held for inspection");
            for (;;)
                pause();
        }
        fputs("supervisor_exit_observed=1 unreleased_worker_reaped=1 gate_eof=1\n",
              stderr);
    }
    munmap(known_worker, 2 * sizeof(*known_worker));
    if (worker.pidfd >= 0)
        close(worker.pidfd);
    if (waitid(P_PIDFD, (id_t)supervisor_fd, &status, WEXITED) < 0) {
        close(supervisor_fd);
        return -1;
    }
    close(supervisor_fd);
    if (normal)
        return 0;
    errno = ECANCELED;
    return -1;
}

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
    if (CONNECT4_CASE >= 5) {
        result = run_with_subreaper(&trial, controller_pidfd, allowed, allowed_port,
                                    denied, denied_port);
        if (result < 0)
            perror("subreaper trial");
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
    result = run_connect4_trial(&trial, controller_pidfd, -1, NULL, 0, CONNECT4_CASE == 1,
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
