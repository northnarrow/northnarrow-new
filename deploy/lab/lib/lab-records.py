#!/usr/bin/env python3
# Lab verdicts from what journald and the signed audit chain attest, never
# from text another user can make the agent log (external audit NN-AUD-410,
# LAB-020, lab PR 206; the anti-tamper suite's case evidence comes from the
# signed records since NN-AUD-413, lab PR 167).
#
# Standard library only. Run it as `python3 -I lab-records.py …` (nothing is
# imported from the current directory or the environment) as the lab user,
# with the journal or the audit log on stdin — `sudo journalctl … -o json |`,
# `sudo tail -n +N /etc/northnarrow/audit.log |` — so it never needs root.
#
#   journal UNIT PID LEVEL PREFIX
#       stdin: `journalctl -o json`. Prints the message of every entry that
#       journald attributes to UNIT's own stdout (`_SYSTEMD_UNIT`, and
#       `_TRANSPORT=stdout`: trusted fields journald sets, not the writer),
#       written by process PID (`_PID`; "-" for any), that is one fmt-layer
#       event "<RFC 3339 time> <LEVEL> <message>" at LEVEL, and whose message
#       starts with PREFIX (the watchdog's carry its target: "watchdog: …").
#       A value another user names — a file name, a comm — is a field of some
#       event, after that event's message and quoted (lab PR 167), and one
#       event is one line (`OneLine`), so it is never at the start of a
#       message: grepping a line for the text is what an exec of a file
#       named "x anti-tamper: all LSM hooks attached deny_attached=16 …"
#       satisfies. Controls are printed as "?". Exit 0 when an entry
#       matched, 1 when none, 2 on a usage error.
#   degraded
#       stdin: audit.log lines (one JSON object each). One line per signed
#       `subsystem_degraded` (`op` integrity_drift, `extra.kind`):
#       "degraded: <detail>" (200 characters, controls as "?"), and
#       "unparsed=<n>" when lines were not one JSON object. Exit 0.
#   --selftest
#       the cases below, offline.
import json
import re
import sys

LEVELS = ("TRACE", "DEBUG", "INFO", "WARN", "ERROR")
# tracing-subscriber's Full format, no ANSI (the agent's and the watchdog's
# fmt layer under journald): "<time> <level padded to 5> <target: ><message>"
EVENT = re.compile(
    r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)) +"
    r"(TRACE|DEBUG|INFO|WARN|ERROR) (.*)"
)
SGR = re.compile(r"\x1b\[[0-9;]*m")
CONTROLS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def printable(s, limit):
    return CONTROLS.sub("?", s)[:limit]


def message_of(entry):
    m = entry.get("MESSAGE")
    if isinstance(m, list):
        try:
            m = bytes(m).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return None
    return m if isinstance(m, str) else None


def journal_messages(lines, unit, pid, level, prefix):
    """The messages of UNIT's own stdout events at LEVEL that start with PREFIX."""
    out = []
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not isinstance(e, dict) or e.get("_SYSTEMD_UNIT") != unit \
                or e.get("_TRANSPORT") != "stdout":
            continue
        if pid != "-" and e.get("_PID") != pid:
            continue
        m = message_of(e)
        if m is None:
            continue
        ev = EVENT.fullmatch(SGR.sub("", m).rstrip("\n"))
        if ev is None or ev.group(2) != level or not ev.group(3).startswith(prefix):
            continue
        out.append(printable(ev.group(3), 4096))
    return out


def degraded_details(lines):
    details, bad = [], 0
    for line in lines:
        # an unterminated last line is an entry being appended: not read yet
        if not line.strip() or not line.endswith(b"\n"):
            continue
        try:
            r = json.loads(line)
        except ValueError:
            r = None
        if not isinstance(r, dict):
            bad += 1
            continue
        extra = r.get("extra")
        if r.get("op") != "integrity_drift" or not isinstance(extra, dict) \
                or extra.get("kind") != "subsystem_degraded":
            continue
        d = extra.get("detail")
        if not isinstance(d, str):
            d = extra.get("reason") if isinstance(extra.get("reason"), str) else "?"
        details.append(printable(d, 200))
    return details, bad


def cmd_journal(unit, pid, level, prefix):
    if level not in LEVELS or not prefix or not (pid == "-" or (pid.isdigit() and int(pid) > 1)):
        print("lab-records: journal UNIT PID|- LEVEL PREFIX", file=sys.stderr)
        return 2
    found = journal_messages(sys.stdin.buffer, unit, pid, level, prefix)
    for m in found:
        print(m)
    return 0 if found else 1


def cmd_degraded():
    details, bad = degraded_details(sys.stdin.buffer)
    for d in details:
        print("degraded: " + d)
    if bad:
        print("unparsed=%d" % bad)
    return 0


def selftest():
    fails, n = [], 0

    def check(cond, what):
        nonlocal n
        n += 1
        if not cond:
            fails.append(what)

    agent = {"_SYSTEMD_UNIT": "northnarrow-agent.service", "_TRANSPORT": "stdout", "_PID": "4242"}
    ts = "2026-10-20T10:00:00.123456Z"
    health = "anti-tamper: all LSM hooks attached deny_attached=18 deny_expected=18"
    forged = "/tmp/x\\n%s  INFO %s" % (ts, health)

    def j(msg, **kw):
        return json.dumps(dict(agent, MESSAGE=msg, **kw)).encode()

    lines = [
        # the agent's own line
        j("%s  INFO %s" % (ts, health)),
        # a file name another user chose, in the agent's VERDICT line
        j('%s  WARN VERDICT (rule) rule=R001_ExecFromTmp target_filename="%s"' % (ts, forged)),
        j('%s  INFO x target_filename="/tmp/%s"' % (ts, health)),
        # the same text from another unit, another transport, another pid
        json.dumps(dict(agent, _SYSTEMD_UNIT="nn-evil.service", MESSAGE="%s  INFO %s" % (ts, health))).encode(),
        j("%s  INFO %s" % (ts, health), _TRANSPORT="journal"),
        j("%s  INFO %s" % (ts, health), _PID="777"),
        # no timestamp, another level, ANSI colours, a byte-array MESSAGE
        j("INFO " + health),
        j("%s  WARN %s" % (ts, health)),
        b"not json",
    ]
    got = journal_messages(lines, "northnarrow-agent.service", "4242", "INFO",
                           "anti-tamper: all LSM hooks attached")
    check(got == [health], "only the agent's own line: %r" % got)
    got = journal_messages(lines, "northnarrow-agent.service", "-", "INFO",
                           "anti-tamper: all LSM hooks attached")
    check(got == [health, health], "any pid of the unit: %r" % got)
    coloured = j("\x1b[2m%s\x1b[0m \x1b[32m INFO\x1b[0m %s" % (ts, health))
    check(journal_messages([coloured], "northnarrow-agent.service", "4242", "INFO", "anti-tamper:")
          == [health], "SGR codes stripped")
    raw = json.dumps(dict(agent, MESSAGE=list(("%s  INFO a\x07b" % ts).encode()))).encode()
    check(journal_messages([raw], "northnarrow-agent.service", "4242", "INFO", "a") == ["a?b"],
          "byte-array MESSAGE, control printed as ?")
    wd = json.dumps({"_SYSTEMD_UNIT": "northnarrow-watchdog.service", "_TRANSPORT": "stdout",
                     "_PID": "99", "MESSAGE": "%s  INFO watchdog: watchdog PID registered in "
                     "PROTECTED_PIDS pid=99 bpffs_root=/sys/fs/bpf/northnarrow" % ts}).encode()
    check(journal_messages([wd], "northnarrow-watchdog.service", "99", "INFO",
                           "watchdog: watchdog PID registered in PROTECTED_PIDS pid=99 ") != [],
          "the watchdog's line, with its target")
    check(journal_messages([wd], "northnarrow-watchdog.service", "99", "INFO",
                           "watchdog PID registered") == [], "the target is part of the prefix")
    audit = [x + b"\n" for x in (
        b'{"op":"agent_boot","extra":{}}',
        json.dumps({"op": "integrity_drift", "extra": {
            "kind": "subsystem_degraded", "at_boot": True,
            "detail": "anti-tamper running degraded (NN_ANTI_TAMPER_ALLOW_DEGRADED=1): 15 of 16\nx"}}).encode(),
        json.dumps({"op": "integrity_drift", "extra": {"kind": "unit_shadowed"}}).encode(),
        json.dumps({"op": "agent_boot", "extra": {"kind": "subsystem_degraded", "detail": "no"}}).encode(),
        b"",
        b"{broken",
    )] + [b'{"op":"integrity_drift","extra":{"kind":"subsystem_deg']
    d, bad = degraded_details(audit)
    check(d == ["anti-tamper running degraded (NN_ANTI_TAMPER_ALLOW_DEGRADED=1): 15 of 16?x"]
          and bad == 1, "subsystem_degraded only, from integrity_drift; an unterminated "
          "last line waits: %r %d" % (d, bad))
    print("lab-records selftest: %d checks, %d failed%s"
          % (n, len(fails), "".join("\n  FAIL: " + f for f in fails)))
    return 1 if fails else 0


def main(argv):
    if argv == ["--selftest"]:
        return selftest()
    if len(argv) == 5 and argv[0] == "journal":
        return cmd_journal(*argv[1:])
    if argv == ["degraded"]:
        return cmd_degraded()
    print("usage: lab-records.py journal UNIT PID|- LEVEL PREFIX | degraded | --selftest",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
