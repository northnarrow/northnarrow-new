/*
 * The performance baseline's own probes (lab PR 228, deploy/lab/perf/
 * perf-run.sh, docs/PERFORMANCE.md §2). The hooked-operation workloads the
 * overhead check already measures come from deploy/lab/overhead/nn-bench.c;
 * these are the three the baseline adds:
 *
 *   ropen    <iterations> <file>...  open(O_RDONLY|O_NOFOLLOW) + read(64) +
 *            close, cycling over the files: the same files in a directory
 *            the agent watches (FIM-listed files of /etc) and as copies in a
 *            scratch directory it does not, so the two figures differ only
 *            by the watch
 *   dnsq     <iterations> <ipv4> [port]  one A query for "localhost" to the
 *            resolver (default port 53) and its answer awaited, 2 s at most
 *            (systemd-resolved answers it locally, RFC 6761)
 *   credread <file>  the event -> verdict latency probe: CLOCK_REALTIME just
 *            before open(O_RDONLY|O_NOFOLLOW) + read + close of the file
 *            (perf-run.sh passes a `.aws/credentials` fixture in its own
 *            scratch directory: NN-L-FIM-011, recorded, never acted on for
 *            root's read)
 *
 * ropen and dnsq print "<mode> <ops/s>"; credread prints "<t0 ns> <pid>".
 * Exit 0, 1 when an operation failed (perror), 2 on a usage error.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static int read_once(const char *path)
{
    char buf[64];
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    ssize_t r = read(fd, buf, sizeof buf);
    close(fd);
    return r < 0 ? -1 : 0;
}

static int bench_ropen(long n, char **files, int nfiles)
{
    for (long i = 0; i < n; i++) {
        if (read_once(files[i % nfiles]) != 0) {
            perror(files[i % nfiles]);
            return -1;
        }
    }
    return 0;
}

/* header (id, RD, QDCOUNT 1), localhost, A, IN */
static size_t dns_query(unsigned char *q, unsigned id)
{
    static const unsigned char tail[] = "\x09" "localhost" "\x00" "\x00\x01" "\x00\x01";
    q[0] = id >> 8;
    q[1] = id & 0xff;
    q[2] = 0x01; /* RD */
    q[3] = 0x00;
    q[4] = 0x00;
    q[5] = 0x01; /* QDCOUNT */
    memset(q + 6, 0, 6);
    memcpy(q + 12, tail, sizeof tail - 1);
    return 12 + sizeof tail - 1;
}

static int bench_dnsq(long n, const char *server, int port)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, server, &sa.sin_addr) != 1) {
        fprintf(stderr, "dnsq: not an IPv4 address: %s\n", server);
        return -1;
    }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0 || connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
        perror("dnsq: socket");
        return -1;
    }
    struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    unsigned char q[64], a[512];
    unsigned base = (unsigned)getpid() * 2654435761u;
    for (long i = 0; i < n; i++) {
        unsigned id = (base + (unsigned)i) & 0xffff;
        size_t len = dns_query(q, id);
        if (send(s, q, len, 0) != (ssize_t)len) {
            perror("dnsq: send");
            close(s);
            return -1;
        }
        for (;;) {
            ssize_t r = recv(s, a, sizeof a, 0);
            if (r < 0) {
                perror(errno == EAGAIN || errno == EWOULDBLOCK ? "dnsq: no answer within 2 s" : "dnsq: recv");
                close(s);
                return -1;
            }
            /* an answer to this query (QR set, same id); a late answer to an
             * earlier one is skipped */
            if (r >= 12 && (a[2] & 0x80) && ((unsigned)a[0] << 8 | a[1]) == id)
                break;
        }
    }
    close(s);
    return 0;
}

static int credread(const char *path)
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    if (read_once(path) != 0) {
        perror(path);
        return -1;
    }
    printf("%lld %d\n", (long long)t.tv_sec * 1000000000LL + t.tv_nsec, (int)getpid());
    return 0;
}

static int usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s ropen <iterations> <file>... | dnsq <iterations> <ipv4> [port] | credread <file>\n",
            argv0);
    return 2;
}

int main(int argc, char **argv)
{
    if (argc < 3)
        return usage(argv[0]);
    const char *mode = argv[1];
    if (!strcmp(mode, "credread"))
        return argc == 3 && credread(argv[2]) == 0 ? 0 : (argc == 3 ? 1 : usage(argv[0]));
    long n = atol(argv[2]);
    if (n <= 0)
        return usage(argv[0]);
    double t0 = now();
    int rc;
    if (!strcmp(mode, "ropen") && argc >= 4)
        rc = bench_ropen(n, argv + 3, argc - 3);
    else if (!strcmp(mode, "dnsq") && (argc == 4 || argc == 5))
        rc = bench_dnsq(n, argv[3], argc == 5 ? atoi(argv[4]) : 53);
    else
        return usage(argv[0]);
    double dt = now() - t0;
    if (rc != 0)
        return 1;
    printf("%s %.0f\n", mode, n / dt);
    return 0;
}
