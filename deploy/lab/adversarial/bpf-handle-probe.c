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
 *   NNX_RINGS=1            instead (tamper-check C43, external audit
 *                          ATP-013): find the agent's ring buffers,
 *                          RING_DROPS and (lab PR 215) DENY_FAIL_OPEN by
 *                          name among every map of the host and ask for a
 *                          read-write handle on each by id
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

/* The agent's ring buffers, its drop counters and (lab PR 215) its deny
 * hooks' fail-open counters (kernel names are cut at 15 bytes). */
static const char *const RINGS[] = {
    "NET_FLOW_CLOSE_EVENTS", "NET_LISTEN_EVENTS", "NET_UDP_EVENTS", "EVENTS",
    "FILE_OPEN_EVENTS", "EXEC_CHECK_EVENTS", "TCP_CONNECT_EVENTS",
    "DNS_QUERY_EVENTS", "FS_PROTECT_EVENTS", "MODULE_LOAD_EVENTS",
    "IOURING_EVENTS", "BPF_SYSCALL_EVENTS", "RING_DROPS", "DENY_FAIL_OPEN", NULL,
};

static int is_ring(const char *name)
{
    for (int i = 0; RINGS[i]; i++) {
        size_t n = strlen(RINGS[i]);
        if (n >= BPF_OBJ_NAME_LEN - 1) {
            if (strncmp(name, RINGS[i], BPF_OBJ_NAME_LEN - 1) == 0)
                return 1;
        } else if (strcmp(name, RINGS[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int map_fd_by_id(unsigned int id, unsigned int flags)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_id = id;
    attr.open_flags = flags;
    return syscall(SYS_bpf, BPF_MAP_GET_FD_BY_ID, &attr, sizeof(attr));
}

/* Prints "write handle granted on: ..." when any ring answered, else one
 * line with the refusal (what the check reads). */
static void probe_rings(void)
{
    char granted[1024] = "";
    int refused = 0, refused_read = 0;
    unsigned int id = 0;
    for (;;) {
        union bpf_attr next;
        memset(&next, 0, sizeof(next));
        next.start_id = id;
        if (syscall(SYS_bpf, BPF_MAP_GET_NEXT_ID, &next, sizeof(next)) != 0)
            break;
        id = next.next_id;
        int fd = map_fd_by_id(id, BPF_F_RDONLY);
        if (fd < 0) {
            if (errno == EPERM)
                refused_read++;
            continue;
        }
        struct bpf_map_info info;
        memset(&info, 0, sizeof(info));
        union bpf_attr ia;
        memset(&ia, 0, sizeof(ia));
        ia.info.bpf_fd = fd;
        ia.info.info_len = sizeof(info);
        ia.info.info = (unsigned long)&info;
        int ok = syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &ia, sizeof(ia)) == 0;
        close(fd);
        if (!ok || !is_ring(info.name))
            continue;
        int rw = map_fd_by_id(id, 0);
        if (rw >= 0) {
            close(rw);
            if (strlen(granted) + strlen(info.name) + 3 < sizeof(granted)) {
                strcat(granted, granted[0] ? ", " : "");
                strcat(granted, info.name);
            }
        } else {
            refused++;
        }
    }
    if (granted[0])
        printf("write handle granted on: %s\n", granted);
    else
        printf("rings: %d write handles refused, %d maps refused even read-only: "
               "Operation not permitted\n", refused, refused_read);
}

__attribute__((constructor)) static void probe(void)
{
    if (getenv("NNX_RINGS")) {
        probe_rings();
        fflush(stdout);
        _exit(0);
    }
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
