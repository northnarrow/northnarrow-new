/*
 * EXP-13's two loads (lab PR 267, R12a; deploy/lab/bus/exp13.sh): a flood of
 * file opens and a burst of refused tamper attempts, both benign.
 *
 *   flood <seconds> <threads> <file>...
 *       Read-only opens of the files (world-readable configuration files
 *       the file-open sensor reports, /etc/passwd), each by a new thread:
 *       the kernel drops a task's repeated read of one file within a
 *       second before its ring (review 75), so a flood that reaches the
 *       agent opens from new tasks. <threads> threads run at a time; each
 *       opens every file once and exits. Prints "flood <opens> <threads
 *       started>" at the end.
 *   tamper <bursts> <size> <gap-ms> <file>
 *       <bursts> bursts of <size> chmod()s of <file> to the mode it already
 *       has (the agent's deny hook refuses them: a no-op if it did not),
 *       <gap-ms> apart. Prints one line per burst, flushed:
 *       "burst <n> <t0 CLOCK_REALTIME ns> <t1 ns> <refused> <allowed>".
 *
 *   net <seconds> <connects-per-s> <port> <dns-per-s>
 *       EXP-13c (review #471 A2): the network load beside the flood — a
 *       listener on 127.0.0.1:<port> that accepts and closes, connects to it
 *       at <connects-per-s>, and DNS queries for names under .example
 *       (RFC 2606) sent to 127.0.0.1:53 at <dns-per-s> — no resolver there:
 *       the DNS sensor sees each query, nothing leaves the host. Prints
 *       "net <connected> <failed> <dns sent>".
 *   connect <ip> <port>
 *       One non-blocking connect (at most 300 ms), then exit: a probe the
 *       network rules judge. Prints "connect <t0 CLOCK_REALTIME ns> <pid>"
 *       before the connect (a kill at the connect ends it before any later
 *       line), then "result <pid> <errno or 0>".
 *
 * Exit 0, 2 on a usage error.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static long long now_ns(clockid_t c)
{
    struct timespec t;
    clock_gettime(c, &t);
    return (long long)t.tv_sec * 1000000000LL + t.tv_nsec;
}

static char **files;
static int nfiles;
static atomic_long opens;

static void *open_all(void *arg)
{
    (void)arg;
    for (int i = 0; i < nfiles; i++) {
        int fd = open(files[i], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0) {
            close(fd);
            atomic_fetch_add(&opens, 1);
        }
    }
    return NULL;
}

static int flood(int secs, int threads, char **f, int n)
{
    files = f;
    nfiles = n;
    long long end = now_ns(CLOCK_MONOTONIC) + (long long)secs * 1000000000LL;
    long started = 0;
    pthread_t *t = calloc((size_t)threads, sizeof *t);
    if (!t)
        return 1;
    while (now_ns(CLOCK_MONOTONIC) < end) {
        int k = 0;
        for (; k < threads; k++) {
            if (pthread_create(&t[k], NULL, open_all, NULL) != 0)
                break;
            started++;
        }
        for (int j = 0; j < k; j++)
            pthread_join(t[j], NULL);
    }
    printf("flood %ld %ld\n", atomic_load(&opens), started);
    free(t);
    return 0;
}

static int tamper(int bursts, int size, int gap_ms, const char *file)
{
    struct stat st;
    if (stat(file, &st) != 0) {
        perror(file);
        return 1;
    }
    mode_t mode = st.st_mode & 07777;
    for (int b = 1; b <= bursts; b++) {
        long refused = 0, allowed = 0;
        long long t0 = now_ns(CLOCK_REALTIME);
        for (int i = 0; i < size; i++) {
            if (chmod(file, mode) == 0)
                allowed++;
            else if (errno == EPERM || errno == EACCES)
                refused++;
        }
        long long t1 = now_ns(CLOCK_REALTIME);
        printf("burst %d %lld %lld %ld %ld\n", b, t0, t1, refused, allowed);
        fflush(stdout);
        if (b < bursts)
            usleep((useconds_t)gap_ms * 1000);
    }
    return 0;
}

static atomic_int net_stop;

static void *accept_loop(void *arg)
{
    int ls = *(int *)arg;
    while (!atomic_load(&net_stop)) {
        struct pollfd p = {.fd = ls, .events = POLLIN};
        if (poll(&p, 1, 100) > 0) {
            int c = accept4(ls, NULL, NULL, SOCK_CLOEXEC);
            if (c >= 0)
                close(c);
        }
    }
    return NULL;
}

/* A DNS query for nn-exp13-<n>.example, type A (RFC 1035 wire form). */
static size_t dns_query(unsigned char *b, unsigned n)
{
    char label[32];
    int l = snprintf(label, sizeof label, "nn-exp13-%u", n);
    size_t i = 0;
    b[i++] = (unsigned char)(n >> 8);
    b[i++] = (unsigned char)n;
    b[i++] = 0x01; /* RD */
    b[i++] = 0x00;
    b[i++] = 0; b[i++] = 1; /* QDCOUNT */
    for (int k = 0; k < 6; k++)
        b[i++] = 0;
    b[i++] = (unsigned char)l;
    memcpy(b + i, label, (size_t)l);
    i += (size_t)l;
    b[i++] = 7;
    memcpy(b + i, "example", 7);
    i += 7;
    b[i++] = 0;
    b[i++] = 0; b[i++] = 1; /* A */
    b[i++] = 0; b[i++] = 1; /* IN */
    return i;
}

static int net(int secs, int rate, int port, int dns_rate)
{
    int ls = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (ls < 0 || bind(ls, (struct sockaddr *)&a, sizeof a) != 0 || listen(ls, 4096) != 0) {
        perror("listen");
        return 1;
    }
    pthread_t acc;
    pthread_create(&acc, NULL, accept_loop, &ls);
    int us = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in stub = {.sin_family = AF_INET, .sin_port = htons(53)};
    stub.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    long connected = 0, failed = 0, dns = 0;
    long long t0 = now_ns(CLOCK_MONOTONIC), end = t0 + (long long)secs * 1000000000LL;
    long long step = rate > 0 ? 1000000000LL / rate : 0;
    long long dstep = dns_rate > 0 ? 1000000000LL / dns_rate : 0;
    long long next = t0, dnext = t0;
    unsigned char q[64];
    while (now_ns(CLOCK_MONOTONIC) < end) {
        long long t = now_ns(CLOCK_MONOTONIC);
        if (step && t >= next) {
            next += step;
            int c = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (c >= 0 && connect(c, (struct sockaddr *)&a, sizeof a) == 0)
                connected++;
            else
                failed++;
            if (c >= 0)
                close(c);
        }
        if (dstep && us >= 0 && t >= dnext) {
            dnext += dstep;
            size_t n = dns_query(q, (unsigned)dns);
            if (sendto(us, q, n, 0, (struct sockaddr *)&stub, sizeof stub) > 0)
                dns++;
        }
        long long wake = step ? next : end;
        if (dstep && dnext < wake)
            wake = dnext;
        long long now = now_ns(CLOCK_MONOTONIC);
        if (wake > now)
            usleep((useconds_t)((wake - now) / 1000 > 50000 ? 50000 : (wake - now) / 1000));
    }
    atomic_store(&net_stop, 1);
    pthread_join(acc, NULL);
    printf("net %ld %ld %ld\n", connected, failed, dns);
    return 0;
}

static int probe_connect(const char *ip, int port)
{
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((unsigned short)port)};
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1)
        return 2;
    int c = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    long long t0 = now_ns(CLOCK_REALTIME);
    printf("connect %lld %d\n", t0, (int)getpid());
    fflush(stdout);
    int err = 0;
    if (c < 0 || (connect(c, (struct sockaddr *)&a, sizeof a) != 0 && errno != EINPROGRESS))
        err = errno;
    else {
        struct pollfd p = {.fd = c, .events = POLLOUT};
        poll(&p, 1, 300);
    }
    printf("result %d %d\n", (int)getpid(), err);
    fflush(stdout);
    if (c >= 0)
        close(c);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 6 && strcmp(argv[1], "net") == 0)
        return net(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
    if (argc == 4 && strcmp(argv[1], "connect") == 0)
        return probe_connect(argv[2], atoi(argv[3]));
    if (argc >= 5 && strcmp(argv[1], "flood") == 0)
        return flood(atoi(argv[2]), atoi(argv[3]), argv + 4, argc - 4);
    if (argc == 6 && strcmp(argv[1], "tamper") == 0)
        return tamper(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), argv[5]);
    fprintf(stderr, "usage: %s flood <secs> <threads> <file>... | tamper <bursts> <size> <gap-ms> <file>"
                    " | net <secs> <connects/s> <port> <dns/s> | connect <ip> <port>\n", argv[0]);
    return 2;
}
