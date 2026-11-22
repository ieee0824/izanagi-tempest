#include <linux/vm_sockets.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
int main(void) {
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
