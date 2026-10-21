/*
 * Lab probe for tamper-check C39/C40 (external audit EBPF-010) and C63/C64
 * (lab PR 215). Every command number comes from <linux/bpf.h>: the probe
 * holds no bpf_cmd number of its own (the agent's wrong copy is what C63
 * and C64 check).
 *
 *   nn-link-probe PATH
 *       take a handle on one of the agent's pinned links through PATH (a
 *       pin, a path padded past the hook's buffer, a symlink to a pin),
 *       then ask the kernel to detach it and to replace its program with
 *       the one it runs (a no-op swap where supported)
 *   nn-link-probe --own
 *       print the ids of the agent's links ("own links: 12 40 41"), read
 *       from its OWN_BPF_IDS map through READ-ONLY map handles (the BPF
 *       guard refuses write handles only); takes no link handle
 *   nn-link-probe --handle-by-id ID
 *       BPF_LINK_GET_FD_BY_ID on link ID (the handle is closed at once)
 *   nn-link-probe --next-from ID[,ID...]
 *       BPF_LINK_GET_NEXT_ID starting from each ID (the step `bpftool link
 *       list` takes before each entry), then a walk of every link id on the
 *       host from 0; takes no handle
 *
 * Prints what the kernel answers; nothing else is touched. "Operation not
 * permitted" is what the check reads as a refusal.
 */
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MAX_OWN 256

static int sys_bpf(int cmd, union bpf_attr *a)
{
    return syscall(SYS_bpf, cmd, a, sizeof(*a));
}

static int usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s PATH | --own | --handle-by-id ID | --next-from ID[,ID...]\n",
            argv0);
    return 2;
}

/* A decimal id, 1..UINT32_MAX, nothing else. */
static int parse_id(const char *s, uint32_t *out)
{
    if (!s || !*s || strlen(s) > 10)
        return -1;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9')
            return -1;
    unsigned long long v = strtoull(s, NULL, 10);
    if (v == 0 || v > UINT32_MAX)
        return -1;
    *out = (uint32_t)v;
    return 0;
}

static int by_path(const char *path)
{
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.pathname = (unsigned long)path;
    int fd = sys_bpf(BPF_OBJ_GET, &a);
    printf("handle (%zu-byte path): %s\n", strlen(path), fd >= 0 ? "granted" : strerror(errno));
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

/* The agent's link ids: keys (kind << 32 | id) of kind 3 in every map
 * named OWN_BPF_IDS, read through read-only handles. */
static int own_links(void)
{
    uint32_t ids[MAX_OWN];
    int n = 0, maps = 0;
    unsigned int id = 0;
    for (;;) {
        union bpf_attr a;
        memset(&a, 0, sizeof(a));
        a.start_id = id;
        if (sys_bpf(BPF_MAP_GET_NEXT_ID, &a) != 0) {
            if (errno != ENOENT) {
                printf("setup: cannot enumerate the maps (%s); no link id read\n", strerror(errno));
                return 2;
            }
            break;
        }
        id = a.next_id;
        memset(&a, 0, sizeof(a));
        a.map_id = id;
        a.open_flags = BPF_F_RDONLY;
        int fd = sys_bpf(BPF_MAP_GET_FD_BY_ID, &a);
        if (fd < 0)
            continue;
        struct bpf_map_info info;
        memset(&info, 0, sizeof(info));
        memset(&a, 0, sizeof(a));
        a.info.bpf_fd = fd;
        a.info.info_len = sizeof(info);
        a.info.info = (unsigned long)&info;
        if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &a) != 0 || strcmp(info.name, "OWN_BPF_IDS") != 0
            || info.key_size != 8) {
            close(fd);
            continue;
        }
        maps++;
        uint64_t key = 0, next = 0;
        int first = 1;
        for (;;) {
            memset(&a, 0, sizeof(a));
            a.map_fd = fd;
            a.key = first ? 0 : (unsigned long)&key;
            a.next_key = (unsigned long)&next;
            if (sys_bpf(BPF_MAP_GET_NEXT_KEY, &a) != 0)
                break;
            first = 0;
            key = next;
            if ((key >> 32) == 3 && n < MAX_OWN) {
                uint32_t link = (uint32_t)key;
                int seen = 0;
                for (int i = 0; i < n; i++)
                    seen |= ids[i] == link;
                if (!seen)
                    ids[n++] = link;
            }
        }
        close(fd);
    }
    if (maps == 0) {
        printf("setup: no OWN_BPF_IDS map readable on this host; no link id read\n");
        return 2;
    }
    if (n == 0) {
        printf("setup: OWN_BPF_IDS (%d map(s)) lists no link\n", maps);
        return 2;
    }
    printf("own links:");
    for (int i = 0; i < n; i++)
        printf(" %u", ids[i]);
    printf("\n");
    return 0;
}

static int handle_by_id(uint32_t id)
{
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.link_id = id;
    int fd = sys_bpf(BPF_LINK_GET_FD_BY_ID, &a);
    if (fd < 0) {
        printf("BPF_LINK_GET_FD_BY_ID %u: %s\n", id, strerror(errno));
        return 1;
    }
    close(fd);
    printf("BPF_LINK_GET_FD_BY_ID %u: granted (handle closed at once)\n", id);
    return 0;
}

/* 0: the next id in *next; 1: the end of the list; -1: refused/failed. */
static int next_id(uint32_t start, uint32_t *next)
{
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.start_id = start;
    if (sys_bpf(BPF_LINK_GET_NEXT_ID, &a) == 0) {
        *next = a.next_id;
        return 0;
    }
    return errno == ENOENT ? 1 : -1;
}

static int next_from(char *list)
{
    uint32_t want[MAX_OWN];
    int n = 0, bad = 0;
    for (char *tok = strtok(list, ","); tok; tok = strtok(NULL, ",")) {
        uint32_t id;
        if (parse_id(tok, &id) != 0 || n == MAX_OWN)
            return -2;
        want[n++] = id;
    }
    if (n == 0)
        return -2;
    for (int i = 0; i < n; i++) {
        uint32_t next = 0;
        switch (next_id(want[i], &next)) {
        case 0:
            printf("BPF_LINK_GET_NEXT_ID after %u: %u\n", want[i], next);
            break;
        case 1:
            printf("BPF_LINK_GET_NEXT_ID after %u: end of the list\n", want[i]);
            break;
        default:
            printf("BPF_LINK_GET_NEXT_ID after %u: %s\n", want[i], strerror(errno));
            bad = 1;
        }
    }
    /* the whole enumeration from 0: every one of the given ids is in it */
    uint32_t cur = 0, links = 0;
    int found = 0, rc;
    while ((rc = next_id(cur, &cur)) == 0) {
        links++;
        for (int i = 0; i < n; i++)
            found += want[i] == cur;
    }
    if (rc < 0) {
        printf("walk: stopped after %u link(s): %s\n", links, strerror(errno));
        bad = 1;
    } else if (found < n) {
        /* an id that is not a live link: the case did not test the agent's */
        printf("walk: %u link(s) enumerated, only %d of the %d given among them: "
               "errno=ENOENT\n", links, found, n);
        bad = 1;
    } else {
        printf("walk: %u link(s) enumerated, the %d given among them\n", links, n);
    }
    return bad;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return usage(argv[0]);
    if (strcmp(argv[1], "--own") == 0)
        return argc == 2 ? own_links() : usage(argv[0]);
    if (strcmp(argv[1], "--handle-by-id") == 0) {
        uint32_t id;
        if (argc != 3 || parse_id(argv[2], &id) != 0)
            return usage(argv[0]);
        return handle_by_id(id);
    }
    if (strcmp(argv[1], "--next-from") == 0) {
        if (argc != 3)
            return usage(argv[0]);
        int rc = next_from(argv[2]);
        return rc == -2 ? usage(argv[0]) : rc;
    }
    if (argv[1][0] == '-')
        return usage(argv[0]);
    return by_path(argv[1]);
}
