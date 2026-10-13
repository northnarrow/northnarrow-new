/*
 * Lab probe for tamper-check C44-C45 (external audit EBPF-008): change an
 * inode flag through the fsxattr interface (FS_IOC_FSSETXATTR), the way
 * `xfs_io -c 'chattr -i'` does, and put it back at once if the kernel
 * allowed it.
 *
 *   fsxattr-probe <path> <+i|-i|+a|-a>
 *
 * Output: "<path>: flag changed (restored)" or the errno text ("Operation
 * not permitted" is what the check reads as a refusal).
 *
 * build: cc -O2 -o nn-fsxattr-probe fsxattr-probe.c
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 3 || strlen(argv[2]) != 2) {
        fprintf(stderr, "usage: %s <path> <+i|-i|+a|-a>\n", argv[0]);
        return 2;
    }
    unsigned int flag = argv[2][1] == 'i' ? FS_XFLAG_IMMUTABLE : FS_XFLAG_APPEND;
    int set = argv[2][0] == '+';
    int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("%s: open: %s\n", argv[1], strerror(errno));
        return 1;
    }
    struct fsxattr fa;
    if (ioctl(fd, FS_IOC_FSGETXATTR, &fa) != 0) {
        printf("%s: FSGETXATTR: %s\n", argv[1], strerror(errno));
        return 1;
    }
    struct fsxattr want = fa;
    want.fsx_xflags = set ? (fa.fsx_xflags | flag) : (fa.fsx_xflags & ~flag);
    if (ioctl(fd, FS_IOC_FSSETXATTR, &want) != 0) {
        printf("%s: FSSETXATTR %s: %s\n", argv[1], argv[2], strerror(errno));
        return 1;
    }
    /* allowed: put the flags back as they were */
    int back = ioctl(fd, FS_IOC_FSSETXATTR, &fa);
    printf("%s: flag changed (%s)\n", argv[1], back == 0 ? "restored" : "NOT restored");
    return 0;
}
