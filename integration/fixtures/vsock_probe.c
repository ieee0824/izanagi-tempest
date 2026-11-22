#include <linux/vm_sockets.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <string.h>
static double monotonic_seconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return now.tv_sec + now.tv_nsec / 1000000000.0;
}
static int connect_port(unsigned port) {
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    struct sockaddr_vm address = { .svm_family = AF_VSOCK, .svm_port = port, .svm_cid = VMADDR_CID_HOST };
    if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof(address))) {
        perror("vsock");
        return -1;
    }
    return fd;
}
static int closed_within(int fd, int milliseconds) {
    struct pollfd event = { .fd = fd, .events = POLLIN };
    char byte;
    if (poll(&event, 1, milliseconds) <= 0) return 0;
    ssize_t result = read(fd, &byte, 1);
    return result == 0 || (result < 0 && errno == ECONNRESET);
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--broker-limit")) {
        double started = monotonic_seconds();
        int first = connect_port(23100);
        if (first < 0 || write(first, "{", 1) != 1) return 10;
        struct pollfd event = { .fd = first, .events = POLLIN };
        if (poll(&event, 1, 150) != 0) return 11;
        double parallel_started = monotonic_seconds();
        int second = connect_port(23100);
        if (second < 0 || !closed_within(second, 500)) return 12;
        double parallel_elapsed = monotonic_seconds() - parallel_started;
        close(second);
        if (!closed_within(first, 3000)) return 13;
        close(first);
        double elapsed = monotonic_seconds() - started;
        if (elapsed > 2.5) return 14;
        printf("BROKER_LIMIT_RECOVERY_OK parallel_ms=%.0f timeout_ms=%.0f\n",
               parallel_elapsed * 1000, elapsed * 1000);
        return 0;
    }
    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    struct sockaddr_vm address = { .svm_family = AF_VSOCK, .svm_port = 23101, .svm_cid = VMADDR_CID_HOST };
    if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof(address))) { perror("vsock"); return 1; }
    const char message[] = "tempest-channel-probe\n";
    if (write(fd, message, sizeof(message)-1) != sizeof(message)-1) return 2;
    char answer[64] = {0};
    ssize_t length = read(fd, answer, sizeof(answer)-1);
    close(fd);
    if (length != 3 || memcmp(answer, "ok\n", 3)) return 3;
    puts("VSOCK_PROBE_OK");
    return 0;
}
