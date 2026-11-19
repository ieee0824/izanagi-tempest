/* Fixed-host fixture entry under review. */
#include "policy.c"

static int reap_unreleased_worker(const struct connect4_trial *trial, pid_t worker,
                                  int gate_eof_status)
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
            if (status.si_code != CLD_EXITED || status.si_status != gate_eof_status) {
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

typedef int (*supervised_trial)(const struct connect4_trial *, int, int,
                                atomic_int *, atomic_int *, void *);

/* The upper owner created all trial resources before this fork. */
static int supervise_trial(const struct connect4_trial *trial, int controller_pidfd,
                            int gate_eof_status, int expect_connected_fault,
                            supervised_trial execute, void *context)
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
        _exit(execute(trial, controller_pidfd, channel[1], known_worker,
                      release_seen, context));
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
    /* Exit 1 reports a failed trial with no pending worker recovery.
     * In particular, a failed post-control follows successful worker reap. */
    int clean_exit = status.si_code == CLD_EXITED &&
        (status.si_status == 0 || status.si_status == 1);
    int trial_passed = !expect_connected_fault && clean_exit && status.si_status == 0;
    int expected_fault = expect_connected_fault && status.si_code == CLD_KILLED &&
        status.si_status == SIGKILL &&
        atomic_load_explicit(release_seen, memory_order_acquire) == 1;
    if (!clean_exit && worker.pidfd >= 0) {
        int reaped = 0;
        if (recover_adopted_connect4_worker(trial, supervisor_fd, &worker,
                                             &reaped) < 0) {
            perror("upper recovery held for inspection");
            for (;;)
                pause();
        }
        if (expected_fault && reaped && worker.phase == CONNECT4_PIN_REMOVED)
            trial_passed = 1;
        fprintf(stderr, "supervisor_exit_observed=1 adopted_worker_reaped=1 pin=%s\n",
                worker.phase == CONNECT4_PIN_REMOVED ? "removed" : "absent");
    } else if (!clean_exit) {
        pid_t known = atomic_load_explicit(known_worker, memory_order_acquire);
        int recovered = known == 0 ? confirm_unpinned_connect4_trial(trial)
                                   : reap_unreleased_worker(trial, known, gate_eof_status);
        if (recovered < 0) {
            perror("unreleased recovery held for inspection");
            for (;;)
                pause();
        }
        if (known == 0)
            fputs("supervisor_exit_observed=1 worker_not_spawned=1\n", stderr);
        else
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
    if (trial_passed)
        return 0;
    errno = clean_exit ? EIO : ECANCELED;
    return -1;
}

struct probe_trial {
    int allowed;
    uint16_t allowed_port;
    int denied;
    uint16_t denied_port;
};

static int execute_probe_trial(const struct connect4_trial *trial, int controller_pidfd,
                               int channel, atomic_int *known_worker,
                               atomic_int *release_seen, void *context)
{
    const struct probe_trial *probe = context;
    struct connect4_phase phases[3];
    struct connect4_pending_recovery pending;
    int fault = CONNECT4_CASE == 6 ? 1 : CONNECT4_CASE == 7 ? 2 : 0;
    int result = run_connect4_trial(trial, controller_pidfd, channel, known_worker, fault,
                                    0, CONNECT4_CASE == 7 ? release_seen : NULL,
                                    probe->allowed, probe->allowed_port, probe->denied,
                                    probe->denied_port, phases, &pending);
    for (unsigned i = 0; i < 3; ++i)
        fprintf(stderr, "phase=%u allowed=%d denied=%d code=%d status=%d\n",
                i, phases[i].allowed_accepts, phases[i].denied_accepts,
                phases[i].worker_code, phases[i].worker_status);
    return result == 0 ? 0 : pending.pidfd >= 0 ? 2 : 1;
}

static int execute_relay_denial(const struct connect4_trial *trial, int controller_pidfd,
                                int channel, atomic_int *known_worker,
                                atomic_int *release_seen, void *context)
{
    (void)release_seen;
    const struct probe_trial *probe = context;
    int64_t now = monotonic_ns();
    if (now < 0)
        return 1;
    struct fixed_relay_result observed;
    struct connect4_pending_recovery pending;
    int result = run_restricted_fixed_relay(trial, probe->denied_port, 1,
        controller_pidfd, channel, known_worker, now + 5000000000LL,
        NULL, NULL, &observed, &pending);
    int alternate_accepts = count_connect4_accepts(probe->denied);
    int agent_accepts = count_connect4_accepts(probe->allowed);
    fprintf(stderr, "connect_errno=%d relay_exit=%d alternate_accepts=%d agent_accepts=%d\n",
            observed.connect_errno, observed.relay_exit, alternate_accepts, agent_accepts);
    if (pending.pidfd >= 0)
        return 2;
    return result == 0 && observed.connect_errno == EPERM && observed.relay_exit == 1 &&
        alternate_accepts == 0 && agent_accepts == 0 ? 0 : 1;
}

struct vm_relay_trial {
    uint16_t port;
    int alternate;
    struct fixed_relay_client client;
};

static int report_vm_relay(const struct fixed_relay_result *result, int denied)
{
    fprintf(stderr, "fixed_relay connect_errno=%d relay_exit=%d\n",
            result->connect_errno, result->relay_exit);
    return result->connect_errno == (denied ? EPERM : 0) &&
        result->relay_exit == denied ? 0 : 1;
}

static int stop_connected_relay_supervisor(const struct fixed_relay_pipes *relay,
                                           int64_t deadline, void *context)
{
    (void)relay;
    (void)deadline;
    atomic_int *connected = context;
    atomic_store_explicit(connected, 1, memory_order_release);
    fputs("fault=relay-supervisor-after-connect connect_errno=0\n", stderr);
    return kill(getpid(), SIGKILL);
}

static int execute_vm_relay(const struct connect4_trial *trial, int controller,
                            int channel, atomic_int *known_worker,
                            atomic_int *release_seen, void *context)
{
    struct vm_relay_trial *vm = context;
    int64_t now = monotonic_ns();
    if (now < 0)
        return 1;
    struct fixed_relay_result observed;
    struct connect4_pending_recovery pending;
    fixed_relay_exchange exchange = vm->alternate ? NULL : exchange_fixed_relay_client;
    void *exchange_context = &vm->client;
    if (CONNECT4_CASE == 11) {
        exchange = stop_connected_relay_supervisor;
        exchange_context = release_seen;
    }
    int result = run_restricted_fixed_relay(trial, vm->port, vm->alternate,
        controller, channel, known_worker, now + 12000000000LL,
        exchange, exchange_context, &observed, &pending);
    int status = report_vm_relay(&observed, vm->alternate);
    return pending.pidfd >= 0 ? 2 : result < 0 ? 1 : status;
}

static uint16_t parse_relay_port(const char *value)
{
    unsigned port = 0;
    for (; *value; ++value) {
        if (*value < '0' || *value > '9')
            return 0;
        port = port * 10 + (unsigned)(*value - '0');
        if (port > UINT16_MAX)
            return 0;
    }
    return (uint16_t)port;
}

/* This root-only entry consumes ports and private paths from the trusted
 * VM controller. Run identity and listener ownership are checked by it. */
static int run_vm_relay_entry(int argc, char **argv)
{
    if (argc != 9 || geteuid() != 0 || argv[6][0] != '/' ||
        strncmp(argv[7], "IZANAGI_SECRET_FILE=/", sizeof("IZANAGI_SECRET_FILE=/") - 1) != 0 ||
        strncmp(argv[8], "IZANAGI_FIXED_SESSION_DIR=/",
                sizeof("IZANAGI_FIXED_SESSION_DIR=/") - 1) != 0)
        return 2;
    const char *phase = argv[1];
    int alternate = strcmp(argv[2], "alternate") == 0;
    int control = strcmp(phase, "control_before") == 0 || strcmp(phase, "control_after") == 0;
    int allow = CONNECT4_CASE == 9 && !alternate && strcmp(phase, "allow_same_run") == 0;
    int deny = CONNECT4_CASE == 10 && alternate && strcmp(phase, "deny_other") == 0;
    int recover = CONNECT4_CASE == 11 && !alternate && strcmp(phase, "fault_recovery") == 0;
    uint16_t agent_port = parse_relay_port(argv[3]);
    uint16_t alternate_port = parse_relay_port(argv[4]);
    if ((!alternate && strcmp(argv[2], "agent") != 0) || (!control && !allow && !deny && !recover) ||
        agent_port == 0 || alternate_port == 0 || agent_port == alternate_port ||
        strlen(argv[5]) != 32 || strspn(argv[5], "0123456789abcdef") != 32)
        return 2;
    umask(0077);
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        return 1;
    int controller = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (controller < 0)
        return 1;
    struct vm_relay_trial vm = {
        .port = alternate ? alternate_port : agent_port,
        .alternate = alternate,
        .client = {argv[6], argv[5], phase, argv[7], argv[8]},
    };
    if (control) {
        int64_t now = monotonic_ns();
        struct fixed_relay_result observed;
        int result = now < 0 ? -1 : run_fixed_relay_control(vm.port, alternate, controller,
            now + 12000000000LL, alternate ? exchange_fixed_alternate : exchange_fixed_relay_client,
            &vm.client, &observed);
        close(controller);
        return result < 0 ? 1 : report_vm_relay(&observed, 0);
    }

    int state, cgroup;
    if (create_connect4_fixture_state(&state, &cgroup) < 0) {
        perror("fixed VM relay state");
        close(controller);
        return 1;
    }
    struct connect4_trial trial = {.link_fd = -1};
    int result = prepare_connect4_trial(state, cgroup, CONNECT4_PIN_PATH, agent_port, &trial);
    if (result == 0)
        result = supervise_trial(&trial, controller, 1, recover, execute_vm_relay, &vm);
    if (trial.link_fd >= 0)
        close(trial.link_fd);
    if (remove_connect4_fixture_cgroup(state, cgroup) < 0 ||
        retire_connect4_fixture_state(state) < 0)
        result = -1;
    close(cgroup);
    close(state);
    close(controller);
    return result == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (CONNECT4_CASE >= 9)
        return run_vm_relay_entry(argc, argv);
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
    if (CONNECT4_CASE == 8) {
        struct probe_trial probe = {allowed, allowed_port, denied, denied_port};
        result = supervise_trial(&trial, controller_pidfd, 1, 0, execute_relay_denial, &probe);
        if (result < 0)
            perror("fixed relay denial");
        goto done;
    }
    if (CONNECT4_CASE >= 5) {
        struct probe_trial probe = {allowed, allowed_port, denied, denied_port};
        result = supervise_trial(&trial, controller_pidfd, 75, 0, execute_probe_trial, &probe);
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
