/*
 * Lab PR 223 — the exec quarantine's harmless test binary (the "EICAR" of
 * execq-check.sh): its first action writes a marker file, so a run whose
 * process was killed before its first instruction leaves no marker. The
 * check builds it on the guest and puts its SHA-256 on a lab-only signed
 * block list. It does nothing else.
 *
 *   nn-execq-marker MARKER [SECONDS]
 */
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

static const char tag[] = "northnarrow lab PR 223 exec quarantine test binary, harmless";

int main(int argc, char **argv)
{
    if (argc > 1) {
        int fd = open(argv[1], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd >= 0) {
            (void)write(fd, "ran\n", 4);
            close(fd);
        }
    }
    if (argc > 2)
        sleep((unsigned)atoi(argv[2]));
    return tag[0] == 'n' ? 0 : 1;
}
