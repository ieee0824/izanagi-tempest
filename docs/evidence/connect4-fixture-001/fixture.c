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

    int state, cgroup;
    if (create_connect4_fixture_state(&state, &cgroup) < 0) {
        perror("fixture state");
        return 1;
    }
    uint16_t allowed_port, denied_port;
    int allowed = open_connect4_listener(&allowed_port);
    if (allowed < 0) {
        perror("allowed listener");
        return 1;
    }
    int denied = open_connect4_listener(&denied_port);
    if (denied < 0) {
        perror("denied listener");
        return 1;
    }
    struct connect4_trial trial;
    if (prepare_connect4_trial(state, cgroup, CONNECT4_PIN_PATH,
                               allowed_port, &trial) < 0) {
        perror("prepare trial");
        return 1;
    }
    struct connect4_pending_recovery pending;
    struct connect4_phase phases[3];
    int result = run_connect4_trial(&trial, allowed, allowed_port,
                                    denied, denied_port, phases, &pending);
    if (result < 0)
        perror("connect4 trial");
    if (pending.pidfd >= 0 && retry_connect4_recovery(&trial, &pending) < 0) {
        perror("connect4 recovery pending");
        result = -1;
    }
    for (unsigned i = 0; i < 3; ++i)
        printf("phase=%u allowed=%d denied=%d code=%d status=%d\n",
               i, phases[i].allowed_accepts, phases[i].denied_accepts,
               phases[i].worker_code, phases[i].worker_status);
    return result == 0 ? 0 : 1;
}
