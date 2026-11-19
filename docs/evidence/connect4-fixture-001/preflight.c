#define _GNU_SOURCE
#include <linux/magic.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/vfs.h>

static int check_mount(const char *path, long filesystem)
{
    struct stat identity;
    struct statfs mount;
    if (lstat(path, &identity) < 0 || statfs(path, &mount) < 0) {
        perror(path);
        return -1;
    }
    if (!S_ISDIR(identity.st_mode) || identity.st_uid != 0 ||
        (identity.st_mode & 0022) != 0 || mount.f_type != filesystem) {
        fprintf(stderr, "%s: unexpected filesystem or ownership\n", path);
        return -1;
    }
    printf("%s: filesystem and owner verified\n", path);
    return 0;
}

int main(void)
{
    int cgroup = check_mount("/sys/fs/cgroup", CGROUP2_SUPER_MAGIC);
    int bpf = check_mount("/sys/fs/bpf", BPF_FS_MAGIC);
    return cgroup != 0 || bpf != 0;
}
