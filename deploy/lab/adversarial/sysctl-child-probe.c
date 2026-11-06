/*
 * Lab probe of lot 280a (`nn-lab.sh sysctl-check`, case S5): a program
 * attached to a CHILD cgroup cannot get around the agent's cgroup/sysctl
 * judge on the root cgroup. Every number comes from <linux/bpf.h>.
 *
 *   nn-sysctl-child-probe CGROUP_DIR FLAGS SYSCTL WRITE REWRITE
 *
 * loads a cgroup/sysctl program that lets every access through (returns 1)
 * and, on a write, replaces the new value with REWRITE
 * (bpf_sysctl_set_new_value) — the two ways a child's program could try to
 * get around the root's: allowing, and changing the value after the root's
 * program judged it; attaches it to CGROUP_DIR (a new child of the root
 * cgroup) with FLAGS (none | override | multi: BPF_PROG_ATTACH's
 * attach_flags); forks a process that moves itself into CGROUP_DIR and
 * writes WRITE to /proc/sys/SYSCTL; prints the write's errno and the value
 * the sysctl holds after it; detaches the program. Nothing else is touched;
 * the caller puts SYSCTL back and removes CGROUP_DIR.
 *
 * Expected with the judge on the root cgroup (multi): for a guarded SYSCTL
 * and a harmful REWRITE, "errno=EPERM" and the value unchanged, whatever
 * FLAGS; for an unguarded SYSCTL (the control), "errno=0" and REWRITE in
 * place — the child's program runs and rewrites.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int sys_bpf(int cmd, union bpf_attr *a)
{
    return syscall(SYS_bpf, cmd, a, sizeof(*a));
}

#define INSN(c, d, s, o, i) ((struct bpf_insn){ .code = (c), .dst_reg = (d), .src_reg = (s), .off = (o), .imm = (i) })

static const char *ename(int e)
{
    return e == 0 ? "0" : e == EPERM ? "EPERM" : e == EINVAL ? "EINVAL" : strerror(e);
}

int main(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "usage: %s CGROUP_DIR none|override|multi SYSCTL WRITE REWRITE\n", argv[0]);
        return 2;
    }
    const char *cg = argv[1], *mode = argv[2], *sysctl = argv[3], *wr = argv[4], *rw = argv[5];
    uint32_t flags = !strcmp(mode, "override") ? BPF_F_ALLOW_OVERRIDE
                   : !strcmp(mode, "multi")    ? BPF_F_ALLOW_MULTI
                   : 0;
    char nl[16];
    size_t rlen = snprintf(nl, sizeof nl, "%s\n", rw);
    if (rlen > 8) {
        fprintf(stderr, "REWRITE: at most 7 characters\n");
        return 2;
    }
    uint64_t val = 0;
    memcpy(&val, nl, rlen);
    struct bpf_insn insns[] = {
        INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_6, BPF_REG_1, 0, 0),           /* r6 = ctx */
        INSN(BPF_LD | BPF_DW | BPF_IMM, BPF_REG_1, 0, 0, (int32_t)(uint32_t)val), /* r1 = value */
        INSN(0, 0, 0, 0, (int32_t)(uint32_t)(val >> 32)),
        INSN(BPF_STX | BPF_MEM | BPF_DW, BPF_REG_10, BPF_REG_1, -8, 0),          /* *(fp-8) = r1 */
        INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_1, BPF_REG_6, 0, 0),           /* r1 = ctx */
        INSN(BPF_ALU64 | BPF_MOV | BPF_X, BPF_REG_2, BPF_REG_10, 0, 0),          /* r2 = fp */
        INSN(BPF_ALU64 | BPF_ADD | BPF_K, BPF_REG_2, 0, 0, -8),                  /* r2 -= 8 */
        INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_3, 0, 0, (int32_t)rlen),       /* r3 = len */
        INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_sysctl_set_new_value),
        INSN(BPF_ALU64 | BPF_MOV | BPF_K, BPF_REG_0, 0, 0, 1),                   /* allow */
        INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
    };
    static char log[65536];
    union bpf_attr a;
    memset(&a, 0, sizeof a);
    a.prog_type = BPF_PROG_TYPE_CGROUP_SYSCTL;
    a.expected_attach_type = BPF_CGROUP_SYSCTL;
    a.insns = (uintptr_t)insns;
    a.insn_cnt = sizeof insns / sizeof insns[0];
    a.license = (uintptr_t)"GPL";
    a.log_buf = (uintptr_t)log;
    a.log_size = sizeof log;
    a.log_level = 1;
    int prog = sys_bpf(BPF_PROG_LOAD, &a);
    if (prog < 0) {
        printf("load: errno=%s\n%s\n", ename(errno), log);
        return 1;
    }
    int cgfd = open(cg, O_RDONLY | O_DIRECTORY);
    if (cgfd < 0) {
        printf("open %s: errno=%s\n", cg, ename(errno));
        return 1;
    }
    memset(&a, 0, sizeof a);
    a.target_fd = cgfd;
    a.attach_bpf_fd = prog;
    a.attach_type = BPF_CGROUP_SYSCTL;
    a.attach_flags = flags;
    if (sys_bpf(BPF_PROG_ATTACH, &a) < 0) {
        printf("attach (%s): errno=%s\n", mode, ename(errno));
        return 1;
    }
    char path[256], procs[256];
    snprintf(path, sizeof path, "/proc/sys/%s", sysctl);
    snprintf(procs, sizeof procs, "%s/cgroup.procs", cg);
    int pipefd[2];
    if (pipe(pipefd) < 0)
        return 1;
    pid_t c = fork();
    if (c == 0) {
        int e = 0;
        int p = open(procs, O_WRONLY);
        if (p < 0 || write(p, "0", 1) != 1)
            e = 1000 + errno;
        if (p >= 0)
            close(p);
        if (!e) {
            int f = open(path, O_WRONLY);
            char buf[64];
            int n = snprintf(buf, sizeof buf, "%s\n", wr);
            if (f < 0 || write(f, buf, n) != n)
                e = errno;
            if (f >= 0)
                close(f);
        }
        if (write(pipefd[1], &e, sizeof e) != sizeof e)
            _exit(1);
        _exit(0);
    }
    int e = -1;
    if (read(pipefd[0], &e, sizeof e) != sizeof e)
        e = -1;
    waitpid(c, NULL, 0);
    memset(&a, 0, sizeof a);
    a.target_fd = cgfd;
    a.attach_bpf_fd = prog;
    a.attach_type = BPF_CGROUP_SYSCTL;
    int det = sys_bpf(BPF_PROG_DETACH, &a);
    char now[64] = "";
    int f = open(path, O_RDONLY);
    if (f >= 0) {
        ssize_t n = read(f, now, sizeof now - 1);
        now[n > 0 ? n : 0] = 0;
        close(f);
        now[strcspn(now, "\n")] = 0;
    }
    if (e >= 1000)
        printf("mode=%s move into %s: errno=%s\n", mode, cg, ename(e - 1000));
    else
        printf("mode=%s %s write %s (child rewrites to %s): errno=%s; now %s; detach %s\n", mode, sysctl, wr, rw,
               e < 0 ? "?" : ename(e), now, det == 0 ? "ok" : ename(errno));
    return 0;
}
