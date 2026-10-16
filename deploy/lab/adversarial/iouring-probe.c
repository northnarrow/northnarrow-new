/*
 * Lab probe for tamper-check C22 — the "blind channel" shape (RingReaper,
 * ARMO "Curing" 2025): open + read a file and connect a TCP socket THROUGH
 * an io_uring ring, so userland issues no openat/read/connect syscall.
 * Raw io_uring syscalls, no liburing (not installed on the lab guests).
 * Output is numeric on purpose (the check reads "Permission denied" as a
 * refusal).
 *
 * External audit LAB-004: the same ring aimed at a protected path, for
 * tamper-check C59a-C59c. The deny hooks sit in the VFS, so a request the
 * ring executes must be refused like the syscall. These modes print
 * "errno=<NAME>" for the operation under test (the check reads the errno,
 * not a message); a rename that goes through is renamed back at once.
 *
 * usage: nn-iou-probe <file> <ipv4> <port>
 *        nn-iou-probe --open-write <file>   open O_WRONLY|O_APPEND, write nothing
 *        nn-iou-probe --unlink <path>
 *        nn-iou-probe --rename <old> <new>
 *        nn-iou-probe --modes               list the tamper modes
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

struct ring {
    int fd;
    unsigned *sq_tail, *sq_mask, *sq_array;
    unsigned *cq_head, *cq_tail, *cq_mask;
    struct io_uring_sqe *sqes;
    struct io_uring_cqe *cqes;
};

static int ring_init(struct ring *r, unsigned entries)
{
    struct io_uring_params p;
    memset(&p, 0, sizeof p);
    r->fd = (int)syscall(__NR_io_uring_setup, entries, &p);
    if (r->fd < 0)
        return -1;
    size_t sq_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cq_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    char *sq = mmap(NULL, sq_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r->fd,
                    IORING_OFF_SQ_RING);
    char *cq = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, r->fd,
                    IORING_OFF_CQ_RING);
    r->sqes = mmap(NULL, p.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQES);
    if (sq == MAP_FAILED || cq == MAP_FAILED || r->sqes == MAP_FAILED)
        return -1;
    r->sq_tail = (unsigned *)(sq + p.sq_off.tail);
    r->sq_mask = (unsigned *)(sq + p.sq_off.ring_mask);
    r->sq_array = (unsigned *)(sq + p.sq_off.array);
    r->cq_head = (unsigned *)(cq + p.cq_off.head);
    r->cq_tail = (unsigned *)(cq + p.cq_off.tail);
    r->cq_mask = (unsigned *)(cq + p.cq_off.ring_mask);
    r->cqes = (struct io_uring_cqe *)(cq + p.cq_off.cqes);
    return 0;
}

/* Submit one SQE, wait for its completion, return cqe->res. */
static int ring_run(struct ring *r, const struct io_uring_sqe *in)
{
    unsigned tail = *r->sq_tail;
    unsigned idx = tail & *r->sq_mask;
    r->sqes[idx] = *in;
    r->sq_array[idx] = idx;
    __atomic_store_n(r->sq_tail, tail + 1, __ATOMIC_RELEASE);
    if (syscall(__NR_io_uring_enter, r->fd, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) < 0)
        return -10000 - errno;
    unsigned head = *r->cq_head;
    while (head == __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE))
        ; /* GETEVENTS already waited for one completion */
    int res = r->cqes[head & *r->cq_mask].res;
    __atomic_store_n(r->cq_head, head + 1, __ATOMIC_RELEASE);
    return res;
}

/* Opcode numbers are io_uring UAPI (stable): spelled out so that an older
 * <linux/io_uring.h> without them still builds the C22 probe. */
#define NN_IORING_OP_RENAMEAT 35
#define NN_IORING_OP_UNLINKAT 36

static const char *errno_name(int e)
{
    static char buf[16];
    switch (e) {
    case EPERM: return "EPERM";
    case ENOENT: return "ENOENT";
    case EACCES: return "EACCES";
    case EBUSY: return "EBUSY";
    case EEXIST: return "EEXIST";
    case EXDEV: return "EXDEV";
    case EINVAL: return "EINVAL";
    case ETXTBSY: return "ETXTBSY";
    case EROFS: return "EROFS";
    case ENOSYS: return "ENOSYS";
    case EOPNOTSUPP: return "EOPNOTSUPP";
    default: snprintf(buf, sizeof buf, "E%d", e); return buf;
    }
}

/* One tamper request through the ring; returns the process exit code. */
static int tamper_mode(int argc, char **argv)
{
    const char *mode = argv[1];
    if (strcmp(mode, "--modes") == 0) {
        printf("open-write unlink rename\n");
        return 0;
    }
    int is_rename = strcmp(mode, "--rename") == 0;
    if (argc != (is_rename ? 4 : 3)) {
        fprintf(stderr, "usage: %s --open-write <file> | --unlink <path> | --rename <old> <new>\n",
                argv[0]);
        return 2;
    }
    struct ring r;
    if (ring_init(&r, 8) < 0) {
        printf("setup: io_uring_setup failed (%s)\n", errno_name(errno));
        return 2;
    }
    struct io_uring_sqe sqe;
    memset(&sqe, 0, sizeof sqe);
    sqe.fd = AT_FDCWD;
    sqe.addr = (uint64_t)(uintptr_t)argv[2];
    int res;
    if (strcmp(mode, "--open-write") == 0) {
        sqe.opcode = IORING_OP_OPENAT;
        sqe.open_flags = O_WRONLY | O_APPEND | O_NOFOLLOW | O_NONBLOCK;
        res = ring_run(&r, &sqe);
        if (res >= 0) {
            close(res); /* nothing is written */
            printf("open-write %s through the ring: opened (nothing written)\n", argv[2]);
            return 0;
        }
    } else if (strcmp(mode, "--unlink") == 0) {
        sqe.opcode = NN_IORING_OP_UNLINKAT; /* unlink_flags (= open_flags slot) 0 */
        res = ring_run(&r, &sqe);
        if (res == 0) {
            printf("unlink %s through the ring: unlinked\n", argv[2]);
            return 0;
        }
    } else if (is_rename) {
        sqe.opcode = NN_IORING_OP_RENAMEAT;
        sqe.len = (uint32_t)AT_FDCWD;                /* new dirfd */
        sqe.off = (uint64_t)(uintptr_t)argv[3];      /* addr2: the new path */
        res = ring_run(&r, &sqe);                    /* rename_flags 0 */
        if (res == 0) {
            int back = rename(argv[3], argv[2]);
            printf("rename %s through the ring: renamed (%s)\n", argv[2],
                   back == 0 ? "renamed back" : "NOT renamed back");
            return 0;
        }
    } else {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
    if (res <= -10000) {
        printf("setup: io_uring_enter failed (%s)\n", errno_name(-res - 10000));
        return 2;
    }
    printf("%s %s through the ring: errno=%s\n", mode + 2, argv[2], errno_name(-res));
    return 1;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strncmp(argv[1], "--", 2) == 0)
        return tamper_mode(argc, argv);
    if (argc != 4) {
        fprintf(stderr, "usage: %s <file> <ipv4> <port>\n", argv[0]);
        return 2;
    }
    struct ring r;
    if (ring_init(&r, 8) < 0) {
        printf("io_uring_setup errno=%d\n", errno);
        return 1;
    }
    struct io_uring_sqe sqe;
    char buf[64];

    memset(&sqe, 0, sizeof sqe);
    sqe.opcode = IORING_OP_OPENAT;
    sqe.fd = AT_FDCWD;
    sqe.addr = (uint64_t)(uintptr_t)argv[1];
    sqe.open_flags = O_RDONLY;
    int ffd = ring_run(&r, &sqe);

    int rd = 0;
    if (ffd >= 0) {
        memset(&sqe, 0, sizeof sqe);
        sqe.opcode = IORING_OP_READ;
        sqe.fd = ffd;
        sqe.addr = (uint64_t)(uintptr_t)buf;
        sqe.len = sizeof buf;
        rd = ring_run(&r, &sqe);
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)atoi(argv[3]));
    inet_pton(AF_INET, argv[2], &sa.sin_addr);
    memset(&sqe, 0, sizeof sqe);
    sqe.opcode = IORING_OP_CONNECT;
    sqe.fd = s;
    sqe.addr = (uint64_t)(uintptr_t)&sa;
    sqe.off = sizeof sa;
    int cn = ring_run(&r, &sqe);

    printf("openat=%d read=%d connect=%d\n", ffd, rd, cn);
    return 0;
}
