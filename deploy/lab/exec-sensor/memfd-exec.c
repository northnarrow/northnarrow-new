// Tappa 10.9 step 2 lab helper (exec-sensor-check): run /bin/sleep from a
// memfd reached through an ordinary-looking symlink. The caller's string
// is the symlink, so only the kernel's view of the file (a memfd) tells
// R004 what ran.
// usage: memfd-exec <symlink path> <seconds>
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s <symlink> <seconds>\n", argv[0]);
        return 2;
    }
    int src = open("/bin/sleep", O_RDONLY);
    struct stat st;
    if (src < 0 || fstat(src, &st) < 0) { perror("/bin/sleep"); return 1; }
    int fd = memfd_create("nnexec", 0);
    if (fd < 0) { perror("memfd_create"); return 1; }
    off_t off = 0;
    while (off < st.st_size)
        if (sendfile(fd, src, &off, st.st_size - off) <= 0) { perror("sendfile"); return 1; }
    char target[64];
    snprintf(target, sizeof target, "/proc/self/fd/%d", fd);
    unlink(argv[1]);
    if (symlink(target, argv[1]) < 0) { perror("symlink"); return 1; }
    char *args[] = {"sleep", argv[2], NULL};
    execv(argv[1], args);
    perror("execv");
    return 1;
}
