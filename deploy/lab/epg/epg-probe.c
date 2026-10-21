/*
 * Exploit post-condition guard — lab probe (lab PR 219). Lab guests only.
 *
 * It changes nothing and gains nothing. It names itself `nn-epg-probe`
 * (prctl PR_SET_NAME) and then does one thing; an agent built with
 * `debug-trigger` and started with NN_EPG_INJECT_COMM=nn-epg-probe reports
 * that one thing as an anomaly marked injected. Then it prints a line it can
 * only print if it is still running in user mode.
 *
 *   getppid  strict: the getppid() exit is the injected anomaly
 *            ("alive-after-getppid")
 *   capable  lite: a capable() that reaches the BPF LSM hook, the first use
 *            point ("alive-after-capable"). An unprivileged capable() is
 *            refused by commoncap, which runs before the BPF LSM, so the
 *            probe enters a user namespace of its own (unshare
 *            CLONE_NEWUSER: a legitimate change through commit_creds) and
 *            asks for CAP_SYS_ADMIN there (unshare CLONE_NEWUTS, an
 *            ns_capable() commoncap grants). Exit 3, "capable-not-reached",
 *            when the system refuses that before the hook (no unprivileged
 *            user namespaces, AppArmor's restriction of them): detect never
 *            refuses, and enforce kills, so a refusal seen here is not the
 *            guard's.
 *   exec     lite: execve(/bin/echo) passes bprm_check_security, the
 *            first use point ("alive-after-exec", printed by echo)
 *
 *   detect : the line is printed, exit 0, one signed NN-L-EPG-001 record
 *            whose response is "recorded only (…, caught at <point>)" (the
 *            journal's VERDICT line says "LAB INJECTION ...")
 *   enforce: killed before the return to user mode (exit status 137), the
 *            line is never printed; lite also refuses the use (-EPERM)
 *
 * usage: epg-probe getppid|capable|exec      build: cc -O2 -o epg-probe epg-probe.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s getppid|capable|exec\n", argv[0]);
        return 2;
    }
    if (prctl(PR_SET_NAME, "nn-epg-probe", 0, 0, 0) != 0) {
        perror("prctl");
        return 2;
    }
    if (!strcmp(argv[1], "getppid")) {
        (void)syscall(SYS_getppid);
        printf("alive-after-getppid\n");
    } else if (!strcmp(argv[1], "capable")) {
        if (unshare(CLONE_NEWUSER) != 0) {
            perror("unshare(CLONE_NEWUSER)");
            printf("capable-not-reached\n");
            return 3;
        }
        if (unshare(CLONE_NEWUTS) != 0) {
            perror("unshare(CLONE_NEWUTS)");
            printf("capable-not-reached\n");
            return 3;
        }
        printf("alive-after-capable\n");
    } else if (!strcmp(argv[1], "exec")) {
        execl("/bin/echo", "echo", "alive-after-exec", (char *)NULL);
        perror("execl"); /* refused (enforce): the kill is pending */
        return 1;
    } else {
        return 2;
    }
    fflush(stdout);
    return 0;
}
