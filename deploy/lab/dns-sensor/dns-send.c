/* Tappa 10.9 step 3 lab helper (`nn-lab.sh dns-sensor-check`): send one DNS
 * query for NAME to a local port 53 in one of the shapes the check needs,
 * then wait LINGER seconds (until external audit NETR-002 the agent killed
 * the sender on NN-L-NET-004; now it records it).
 *
 *   dns-send MODE NAME [LINGER]
 *
 *   connect4  connect() + send() to 127.0.0.1:53 (glibc's resolver shape)
 *   sendto4   sendto() on an unconnected socket
 *   connect6  connect() + send() to [::1]:53
 *   unfaulted the query in a file mapping the process has not touched yet:
 *             BPF cannot fault the page in, the kernel's copy does
 *   nul       a zero byte inside the first label (a string read stops there)
 *   cork      the header with MSG_MORE, then the rest: one datagram whose
 *             name lies outside the linear part of the socket buffer
 *
 * NAME is dotted; in `nul` mode its first label gets a zero byte after its
 * first character. Nothing listens on port 53: the datagram is sent all the
 * same. Exit 0 after LINGER (default 5) seconds. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

static size_t build(unsigned char *q, const char *name, int nul)
{
    size_t n = 0;
    memset(q, 0, 12);
    q[0] = 0x4e; q[1] = 0x4e;           /* id */
    q[2] = 0x01;                        /* RD */
    q[5] = 1;                           /* QDCOUNT */
    n = 12;
    const char *p = name;
    int first = 1;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (first && nul && len >= 2) {
            q[n++] = (unsigned char)(len + 1);
            q[n++] = (unsigned char)p[0];
            q[n++] = 0;                 /* the zero byte inside the label */
            memcpy(q + n, p + 1, len - 1);
            n += len - 1;
        } else {
            q[n++] = (unsigned char)len;
            memcpy(q + n, p, len);
            n += len;
        }
        first = 0;
        p += len;
        if (*p == '.')
            p++;
    }
    q[n++] = 0;                         /* root label */
    q[n++] = 0; q[n++] = 1;             /* QTYPE A */
    q[n++] = 0; q[n++] = 1;             /* QCLASS IN */
    return n;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s MODE NAME [LINGER]\n", argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    int linger = argc > 3 ? atoi(argv[3]) : 5;
    unsigned char q[600];
    size_t n = build(q, argv[2], strcmp(mode, "nul") == 0);

    struct sockaddr_in a4 = { .sin_family = AF_INET, .sin_port = htons(53) };
    inet_pton(AF_INET, "127.0.0.1", &a4.sin_addr);
    struct sockaddr_in6 a6 = { .sin6_family = AF_INET6, .sin6_port = htons(53) };
    inet_pton(AF_INET6, "::1", &a6.sin6_addr);

    int v6 = strcmp(mode, "connect6") == 0;
    int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    ssize_t r;
    if (strcmp(mode, "sendto4") == 0) {
        r = sendto(fd, q, n, 0, (struct sockaddr *)&a4, sizeof a4);
    } else if (strcmp(mode, "unfaulted") == 0) {
        /* Write the query to a file, map it, and send from the mapping
         * without reading it first: no page-table entry yet. */
        char path[] = "/tmp/nn-dns-sendXXXXXX";
        int f = mkstemp(path);
        if (f < 0 || write(f, q, n) != (ssize_t)n) {
            perror("tmpfile");
            return 1;
        }
        unlink(path);
        void *m = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, f, 0);
        if (m == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
        r = sendto(fd, m, n, 0, (struct sockaddr *)&a4, sizeof a4);
    } else if (strcmp(mode, "cork") == 0) {
        if (connect(fd, (struct sockaddr *)&a4, sizeof a4) < 0) {
            perror("connect");
            return 1;
        }
        /* The header and the rest from separate buffers, so that a read
         * of user memory past the header does not find the name. */
        unsigned char *rest = malloc(n);
        memcpy(rest, q + 12, n - 12);
        memset(q + 12, 0, n - 12);
        r = send(fd, q, 12, MSG_MORE);
        if (r >= 0)
            r = send(fd, rest, n - 12, 0);
    } else {
        struct sockaddr *sa = v6 ? (struct sockaddr *)&a6 : (struct sockaddr *)&a4;
        socklen_t sl = v6 ? sizeof a6 : sizeof a4;
        if (connect(fd, sa, sl) < 0) {
            perror("connect");
            return 1;
        }
        r = send(fd, q, n, 0);
    }
    if (r < 0) {
        perror("send");
        return 1;
    }
    sleep(linger);
    return 0;
}
