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
 * Exit 0, 2 on a usage error.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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

int main(int argc, char **argv)
{
    if (argc >= 5 && strcmp(argv[1], "flood") == 0)
        return flood(atoi(argv[2]), atoi(argv[3]), argv + 4, argc - 4);
    if (argc == 6 && strcmp(argv[1], "tamper") == 0)
        return tamper(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), argv[5]);
    fprintf(stderr, "usage: %s flood <secs> <threads> <file>... | tamper <bursts> <size> <gap-ms> <file>\n", argv[0]);
    return 2;
}
