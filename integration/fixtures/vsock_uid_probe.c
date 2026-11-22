#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <linux/vm_sockets.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void probe(int private_network) {
    if ((private_network && unshare(CLONE_NEWNET)) || setgroups(0, NULL) || setgid(988) || setuid(999)) {
        perror("probe setup"); _exit(2);
    }
    int fd = socket(AF_VSOCK, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    int socket_error = fd < 0 ? errno : 0;
    int connection_error = 0;
    int connected = 0;
    if (fd >= 0) {
        struct sockaddr_vm address = { .svm_family = AF_VSOCK, .svm_cid = VMADDR_CID_HOST, .svm_port = 23104 };
        if (!connect(fd, (struct sockaddr *)&address, sizeof(address))) connected = 1;
        else if (errno == EINPROGRESS) {
            struct pollfd event = { .fd = fd, .events = POLLOUT };
            if (poll(&event, 1, 500) > 0) {
                socklen_t length = sizeof(connection_error);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &connection_error, &length)) connection_error = errno;
                else connected = connection_error == 0;
            } else connection_error = ETIMEDOUT;
        } else connection_error = errno;
        close(fd);
    }
    printf("VSOCK_UID_RESULT {\"private_network\":%s,\"uid\":%u,\"socket_errno\":%d,\"connect_errno\":%d,\"connected\":%s}\n",
        private_network ? "true" : "false", (unsigned)getuid(), socket_error, connection_error,
        connected ? "true" : "false");
    fflush(stdout);
    _exit(0);
}
int main(void) {
    for (int private_network = 0; private_network < 2; ++private_network) {
        pid_t child = fork();
        if (child < 0) return 1;
        if (!child) probe(private_network);
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 1;
    }
    puts("VSOCK_UID_PROBE_COMPLETE");
    return 0;
}
