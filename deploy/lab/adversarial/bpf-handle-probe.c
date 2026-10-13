/*
 * Lab probe for tamper-check C34-C37 (external audit EBPF-002): a library
 * preloaded into one of NorthNarrow's own binaries, the way root would run
 * its code inside a process the BPF self-defence used to exempt by
 * executable. It only ASKS for handles and reports the answer; nothing is
 * read or modified, and the binary's own main() never runs.
 *
 *   NNX_TARGET=<pin path>  BPF_OBJ_GET with read-write access on that pin
 *                          (default: the agent's PROTECTED_PIDS)
 *   NNX_SLEEP=<seconds>    instead: stay alive that long, so the case can
 *                          try ptrace on a process running the binary
 *
 * Output: "granted" or the errno text ("Operation not permitted" is what
 * the check reads as a refusal).
 *
 * build: cc -shared -fPIC -O2 -o nn-bpf-probe.so bpf-handle-probe.c
 */
#include <errno.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

__attribute__((constructor)) static void probe(void)
{
    const char *nap = getenv("NNX_SLEEP");
    if (nap) {
        sleep((unsigned)atoi(nap));
        _exit(0);
    }
    const char *path = getenv("NNX_TARGET");
    if (!path)
        path = "/sys/fs/bpf/northnarrow/PROTECTED_PIDS";
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (unsigned long)path;
    attr.file_flags = 0; /* read-write */
    int fd = syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
    if (fd >= 0) {
        printf("%s: granted\n", path);
        close(fd);
    } else {
        printf("%s: %s\n", path, strerror(errno));
    }
    fflush(stdout);
    _exit(0);
}
