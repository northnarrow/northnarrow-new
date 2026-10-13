/*
 * Lab probe for tamper-check C39/C40 (external audit EBPF-010): take a
 * handle on one of the agent's pinned links through PATH (a pin, a path
 * padded past the hook's buffer, a symlink to a pin), then ask the kernel
 * to detach it and to replace its program with the one it runs (a no-op
 * swap where supported). Prints what the kernel answers; nothing else is
 * touched. "Operation not permitted" is what the check reads as a refusal.
 *
 * usage: nn-link-probe PATH
 */
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int sys_bpf(int cmd, union bpf_attr *a)
{
    return syscall(SYS_bpf, cmd, a, sizeof(*a));
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s PATH\n", argv[0]);
        return 2;
    }
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.pathname = (unsigned long)argv[1];
    int fd = sys_bpf(BPF_OBJ_GET, &a);
    printf("handle (%zu-byte path): %s\n", strlen(argv[1]), fd >= 0 ? "granted" : strerror(errno));
    if (fd < 0)
        return 1;
    memset(&a, 0, sizeof(a));
    a.link_detach.link_fd = fd;
    printf("detach: %s\n", sys_bpf(BPF_LINK_DETACH, &a) == 0 ? "DETACHED" : strerror(errno));
    struct bpf_link_info info;
    memset(&info, 0, sizeof(info));
    memset(&a, 0, sizeof(a));
    a.info.bpf_fd = fd;
    a.info.info_len = sizeof(info);
    a.info.info = (unsigned long)&info;
    int pfd = -1;
    if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &a) == 0) {
        memset(&a, 0, sizeof(a));
        a.prog_id = info.prog_id;
        pfd = sys_bpf(BPF_PROG_GET_FD_BY_ID, &a);
    }
    if (pfd >= 0) {
        memset(&a, 0, sizeof(a));
        a.link_update.link_fd = fd;
        a.link_update.new_prog_fd = pfd;
        printf("update: %s\n", sys_bpf(BPF_LINK_UPDATE, &a) == 0 ? "UPDATED" : strerror(errno));
        close(pfd);
    } else {
        printf("update: not tried (no program handle)\n");
    }
    close(fd);
    return 0;
}
