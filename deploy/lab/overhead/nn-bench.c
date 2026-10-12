/*
 * Overhead micro-benchmark (Tappa 10.8, "overhead misurato su host carico").
 * Measures the throughput of the operations the agent hooks, so the lab can
 * compare the same guest with the agent stopped (no hooks) and running:
 *
 *   open     open(O_RDONLY) + read(64) + close over 64 files  — sys_enter_openat,
 *            LSM file_open (inode protection + FIM watch lookups)
 *   wopen    open(O_WRONLY) + write(4 KiB) + close on one file — file_open with
 *            write intent, file_permission
 *   exec     fork + execve(/bin/true) + waitpid                — sched_process_exec,
 *            sys_enter_execve, the agent's userland rule pass
 *   connect  TCP connect/accept/close on 127.0.0.1             — tcp_v4_connect
 *            kprobe, tcp_close fexit, inet_csk_listen
 *   udp      sendto() of a 64-byte datagram to 127.0.0.1, drained — the
 *            udp_sendmsg_outbound kprobe and the DNS sensor's port check
 *            (udp_send_skb kprobe, Tappa 10.9 step 3)
 *   dns      sendto() of a DNS query (A, 30-byte name) to 127.0.0.1:53 — one
 *            DNS record per query and the agent's userland DNS pass
 *
 * usage: nn-bench <mode> <iterations> <workdir>   → prints "<mode> <ops/s>"
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static int bench_open(long n, const char *dir)
{
    char path[64][512];
    char buf[64];
    for (int i = 0; i < 64; i++) {
        snprintf(path[i], sizeof path[i], "%s/f%02d", dir, i);
        int fd = open(path[i], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0 || write(fd, "northnarrow-bench-northnarrow-bench-northnarrow-bench-0123456789", 64) != 64)
            return -1;
        close(fd);
    }
    for (long i = 0; i < n; i++) {
        int fd = open(path[i & 63], O_RDONLY);
        if (fd < 0)
            return -1;
        if (read(fd, buf, sizeof buf) < 0)
            return -1;
        close(fd);
    }
    return 0;
}

static int bench_wopen(long n, const char *dir)
{
    char path[512];
    static char block[4096];
    memset(block, 'n', sizeof block);
    snprintf(path, sizeof path, "%s/w", dir);
    for (long i = 0; i < n; i++) {
        int fd = open(path, O_WRONLY | O_CREAT, 0644);
        if (fd < 0)
            return -1;
        if (pwrite(fd, block, sizeof block, 0) != (ssize_t)sizeof block)
            return -1;
        close(fd);
    }
    return 0;
}

static int bench_exec(long n)
{
    char *const argv[] = {"true", NULL};
    char *const envp[] = {NULL};
    for (long i = 0; i < n; i++) {
        pid_t p = fork();
        if (p < 0)
            return -1;
        if (p == 0) {
            execve("/bin/true", argv, envp);
            _exit(127);
        }
        int st;
        if (waitpid(p, &st, 0) < 0)
            return -1;
    }
    return 0;
}

static int bench_connect(long n)
{
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int one = 1;
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(l, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(l, 128) < 0)
        return -1;
    socklen_t sl = sizeof sa;
    getsockname(l, (struct sockaddr *)&sa, &sl);
    for (long i = 0; i < n; i++) {
        int c = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(c, (struct sockaddr *)&sa, sizeof sa) < 0)
            return -1;
        int a = accept(l, NULL, NULL);
        if (a < 0)
            return -1;
        close(a);
        close(c);
    }
    close(l);
    return 0;
}

/* One datagram per iteration from an unconnected socket. `dns`: a query
 * to port 53 (nothing listens: the kernel answers ICMP, rate-limited, and
 * the datagram is built and sent all the same); otherwise a bound receiver
 * on an ephemeral port, drained after each send. */
static int bench_udp(long n, int dns)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    int r = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (s < 0 || r < 0 || bind(r, (struct sockaddr *)&sa, sizeof sa) < 0)
        return -1;
    socklen_t sl = sizeof sa;
    getsockname(r, (struct sockaddr *)&sa, &sl);
    if (dns)
        sa.sin_port = htons(53);
    /* header (id, RD, QDCOUNT 1), bench.nn-lab.invalid, A, IN */
    static const unsigned char q[] =
        "\x4e\x42\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        "\x05" "bench" "\x06" "nn-lab" "\x07" "invalid" "\x00\x00\x01\x00\x01";
    unsigned char buf[64];
    memset(buf, 'u', sizeof buf);
    const void *p = dns ? (const void *)q : (const void *)buf;
    size_t len = dns ? sizeof q - 1 : sizeof buf;
    for (long i = 0; i < n; i++) {
        if (sendto(s, p, len, 0, (struct sockaddr *)&sa, sizeof sa) < 0)
            return -1;
        if (!dns)
            while (recv(r, buf, sizeof buf, 0) > 0)
                ;
    }
    close(r);
    close(s);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s open|wopen|exec|connect|udp|dns <iterations> <workdir>\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    long n = atol(argv[2]);
    mkdir(argv[3], 0755);
    double t0 = now();
    int rc;
    if (!strcmp(mode, "open"))
        rc = bench_open(n, argv[3]);
    else if (!strcmp(mode, "wopen"))
        rc = bench_wopen(n, argv[3]);
    else if (!strcmp(mode, "exec"))
        rc = bench_exec(n);
    else if (!strcmp(mode, "connect"))
        rc = bench_connect(n);
    else if (!strcmp(mode, "udp"))
        rc = bench_udp(n, 0);
    else if (!strcmp(mode, "dns"))
        rc = bench_udp(n, 1);
    else
        return 2;
    double dt = now() - t0;
    if (rc != 0) {
        perror(mode);
        return 1;
    }
    printf("%s %.0f\n", mode, n / dt);
    return 0;
}
