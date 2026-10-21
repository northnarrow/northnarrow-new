#!/usr/bin/env python3
# nn-ms: benign network simulations and record reader for
# deploy/lab/malsim/net-check.sh (lab PR 224, CM-02/03/14).
#
# Standard library only. Run it as `python3 -I nn-ms-net.py …` (nothing is
# imported from the current directory or the environment). Every simulation
# talks to loopback only (127.0.0.0/8) and carries no payload of interest:
# connects that are closed at once, a listener that holds or echoes, a shell
# on a pseudo-terminal whose only input is `exit`.
#
#   listen HOST PORT MODE SECS READY [TEXT]
#       bind HOST:PORT, write "nn-ms ready" to READY, then for SECS seconds:
#       MODE hold  = accept and keep every connection open;
#       MODE close = accept and close at once;
#       MODE send  = accept, send TEXT (\n allowed), read until EOF.
#   hold HOST PORT SECS          one connection kept open SECS seconds
#   beacon HOST PORT COUNT IVL   COUNT connections, one every IVL seconds,
#                                each closed at once
#   sweep FIRST-LAST PORT [DELAY]   one non-blocking connect per address of
#                                the IPv4 range, closed at once
#   ports HOST FIRST-LAST [DELAY]   one per port of HOST
#   brute HOST PORT COUNT IVL    COUNT connects to one service, each closed
#   pty-shell HOST PORT          connect, put the socket on fds 0-2, run
#                                /bin/sh on a pty (the python pty reverse
#                                shell shape; the listener sends `exit`)
#   burst HOST PORT COUNT        COUNT connections open together, then closed
#   once HOST PORT TEXT          connect, send TEXT, print the reply
#   records count [--rule ID]… [--severity S] [--action A]
#                 [--network-prefix P] [--pid N]
#       stdin: detections.jsonl lines. Prints how many records match.
#   records list
#       one line per record: rule_id severity action pid network
#   json-get KEY                 stdin: one JSON object; prints KEY's value
#                                (empty when absent)
#   selftest                     the cases below, offline
import ipaddress
import json
import os
import socket
import sys
import time

MARK = "nn-ms"


def parse_range(text):
    first, _, last = text.partition("-")
    a = int(ipaddress.IPv4Address(first))
    b = int(ipaddress.IPv4Address(last or first))
    if b < a or b - a > 4096:
        raise ValueError("range %r" % text)
    return [str(ipaddress.IPv4Address(i)) for i in range(a, b + 1)]


def parse_ports(text):
    first, _, last = text.partition("-")
    a, b = int(first), int(last or first)
    if not (1 <= a <= b <= 65535):
        raise ValueError("ports %r" % text)
    return list(range(a, b + 1))


def quick_connect(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    try:
        s.connect_ex((host, port))
    finally:
        s.close()


def cmd_listen(host, port, mode, secs, ready, text=""):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, int(port)))
    srv.listen(128)
    with open(ready, "w") as fh:
        fh.write(MARK + " ready\n")
    deadline = time.monotonic() + float(secs)
    held = []
    payload = text.replace("\\n", "\n").encode()
    while time.monotonic() < deadline:
        srv.settimeout(max(0.1, deadline - time.monotonic()))
        try:
            c, _ = srv.accept()
        except OSError:
            break
        if mode == "hold":
            held.append(c)
        elif mode == "close":
            c.close()
        else:
            try:
                c.settimeout(max(0.1, deadline - time.monotonic()))
                c.sendall(payload)
                while c.recv(4096):
                    pass
            except OSError:
                pass
            c.close()
    for c in held:
        c.close()
    srv.close()
    return 0


def cmd_hold(host, port, secs):
    s = socket.create_connection((host, int(port)), timeout=5)
    time.sleep(float(secs))
    s.close()
    return 0


def cmd_beacon(host, port, count, ivl):
    for i in range(int(count)):
        if i:
            time.sleep(float(ivl))
        try:
            socket.create_connection((host, int(port)), timeout=2).close()
        except OSError:
            pass
    return 0


def cmd_sweep(rng, port, delay="0.001"):
    for host in parse_range(rng):
        quick_connect(host, int(port))
        time.sleep(float(delay))
    return 0


def cmd_ports(host, rng, delay="0.001"):
    for port in parse_ports(rng):
        quick_connect(host, port)
        time.sleep(float(delay))
    return 0


def cmd_brute(host, port, count, ivl):
    for i in range(int(count)):
        try:
            socket.create_connection((host, int(port)), timeout=1).close()
        except OSError:
            pass
        time.sleep(float(ivl))
    return 0


def cmd_pty_shell(host, port):
    import pty
    s = socket.create_connection((host, int(port)), timeout=5)
    for fd in (0, 1, 2):
        os.dup2(s.fileno(), fd)
    pty.spawn("/bin/sh")
    return 0


def cmd_burst(host, port, count):
    conns = []
    for _ in range(int(count)):
        try:
            conns.append(socket.create_connection((host, int(port)), timeout=2))
        except OSError:
            pass
    time.sleep(0.5)
    for c in conns:
        c.close()
    print(len(conns))
    return 0


def cmd_once(host, port, text):
    s = socket.create_connection((host, int(port)), timeout=5)
    s.sendall(text.replace("\\n", "\n").encode())
    s.shutdown(socket.SHUT_WR)
    out = b""
    try:
        while True:
            b = s.recv(4096)
            if not b:
                break
            out += b
    except OSError:
        pass
    s.close()
    sys.stdout.write(out.decode("utf-8", "replace"))
    return 0


# ── the signed detections log ───────────────────────────────────────────


def records(lines):
    """The detection records among `lines` (envelope and rotation lines and
    anything that is not one JSON object skipped)."""
    out = []
    for line in lines:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict) and isinstance(r.get("rule_id"), str):
            out.append(r)
    return out


def action_of(r):
    v = r.get("verdict")
    if isinstance(v, dict):
        a = v.get("Rule")
        return a if isinstance(a, str) else "?"
    return "?"


def pid_of(r):
    p = r.get("principal")
    if isinstance(p, dict) and isinstance(p.get("pid"), int):
        return p["pid"]
    return -1


def network_of(r):
    n = r.get("network")
    return n if isinstance(n, str) else ""


def printable(s):
    return "".join(c if c.isprintable() and c != " " else "_" for c in s)


def matches(r, rules, severity, action, prefix, pid):
    if rules and r["rule_id"] not in rules:
        return False
    if severity and r.get("severity") != severity:
        return False
    if action and action_of(r) != action:
        return False
    if prefix and not network_of(r).startswith(prefix):
        return False
    if pid is not None and pid_of(r) != pid:
        return False
    return True


def cmd_records(argv, stdin):
    if not argv or argv[0] not in ("count", "list"):
        print("usage: records count|list …", file=sys.stderr)
        return 2
    sub, rest = argv[0], argv[1:]
    rules, severity, action, prefix, pid = [], None, None, None, None
    i = 0
    while i < len(rest):
        flag = rest[i]
        if i + 1 >= len(rest):
            print("missing value for %s" % flag, file=sys.stderr)
            return 2
        val = rest[i + 1]
        if flag == "--rule":
            rules.append(val)
        elif flag == "--severity":
            severity = val
        elif flag == "--action":
            action = val
        elif flag == "--network-prefix":
            prefix = val
        elif flag == "--pid":
            pid = int(val)
        else:
            print("unknown flag %s" % flag, file=sys.stderr)
            return 2
        i += 2
    recs = records(stdin)
    if sub == "count":
        print(sum(1 for r in recs if matches(r, rules, severity, action, prefix, pid)))
        return 0
    for r in recs:
        if matches(r, rules, severity, action, prefix, pid):
            print("%s %s %s %d %s" % (printable(r["rule_id"]), printable(str(r.get("severity"))),
                                      printable(action_of(r)), pid_of(r),
                                      printable(network_of(r)) or "-"))
    return 0


def cmd_json_get(key, stdin):
    text = "".join(stdin)
    try:
        obj = json.loads(text)
    except ValueError:
        # nn-admin may print a line before the object
        start = text.find("{")
        try:
            obj = json.loads(text[start:]) if start >= 0 else None
        except ValueError:
            obj = None
    if isinstance(obj, dict) and key in obj and obj[key] is not None:
        print(obj[key])
    return 0


def selftest():
    fails = []

    def check(cond, what):
        if not cond:
            fails.append(what)

    lines = [
        "not json",
        '{"rotate": true, "entry_hash": "ab"}',
        json.dumps({"rule_id": "NN-L-NET-010_OutboundToHighRiskC2Port", "severity": "High",
                    "verdict": {"Rule": "KillProcess"}, "principal": {"pid": 41, "uid": 1000, "comm": "python3"},
                    "response": "KillProcess", "network": "tcp 127.0.0.1:4444 connect",
                    "prev_hash": "x", "entry_hash": "y", "agent_sig": "z"}),
        json.dumps({"rule_id": "NN-L-NET-010_OutboundToHighRiskC2Port", "severity": "High",
                    "verdict": {"Rule": "KillProcess"}, "principal": {"pid": 41}, "response": "KillProcess (already gone)"}),
        json.dumps({"rule_id": "R020_ShellWithSocketStdio", "severity": "Critical",
                    "verdict": {"Rule": "KillProcessTree"}, "principal": {"pid": 77},
                    "network": "stdio tcp 127.0.0.1:44401 outbound"}),
        json.dumps({"rule_id": "NN-L-NET-026_ScanFanOut", "severity": "High",
                    "verdict": {"Rule": "Log"}, "principal": {"pid": 90}, "network": "tcp 127.0.0.64:9 attempt"}),
        json.dumps(["rule_id", "list, not an object"]),
        json.dumps({"rule_id": 5}),
    ]
    recs = records(lines)
    check(len(recs) == 4, "records: 4 of 8 lines are records (%d)" % len(recs))

    def count(*a):
        rules, sev, act, pre, pid = a
        return sum(1 for r in recs if matches(r, rules, sev, act, pre, pid))

    check(count(["NN-L-NET-010_OutboundToHighRiskC2Port"], None, None, None, None) == 2, "count by rule")
    check(count(["NN-L-NET-010_OutboundToHighRiskC2Port"], None, None, "tcp 127.0.0.1:4444 connect", None) == 1,
          "count by rule and network phase")
    check(count([], "Critical", None, None, None) == 1, "count by severity")
    check(count([], None, "Log", None, None) == 1, "count by action")
    check(count([], None, None, None, 41) == 2, "count by pid")
    check(count(["R020_ShellWithSocketStdio"], None, None, "stdio tcp 127.0.0.1:44401 outbound", 77) == 1,
          "count by every filter")
    check(count(["NN-L-NET-027_OutboundAuthBruteforce"], None, None, None, None) == 0, "no such rule")
    check(action_of({"verdict": "Log"}) == "?", "a verdict that is not an object")
    check(network_of({"network": 3}) == "", "a network that is not a string")
    check(printable("a b\x1b[31m") == "a_b_[31m", "printable")
    r = parse_range("127.0.1.1-127.0.3.88")
    check(len(r) == 600 and r[0] == "127.0.1.1" and r[-1] == "127.0.3.88", "600 addresses (%d)" % len(r))
    check(len(parse_range("127.0.0.2-127.0.0.200")) == 199, "199 addresses")
    check(parse_ports("1-400")[-1] == 400 and len(parse_ports("1-400")) == 400, "ports 1-400")
    for bad in ("127.0.0.9-127.0.0.2", "127.0.0.1-127.1.0.0", "x-y"):
        try:
            parse_range(bad)
            check(False, "parse_range refuses %r" % bad)
        except ValueError:
            pass
    for bad in ("0-5", "5-1", "1-70000"):
        try:
            parse_ports(bad)
            check(False, "parse_ports refuses %r" % bad)
        except ValueError:
            pass

    import io
    from contextlib import redirect_stderr, redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_json_get("net_flow_snapshots_total", ['{"net_flow_snapshots_total": 3, "x": null}'])
        cmd_json_get("x", ['{"net_flow_snapshots_total": 3, "x": null}'])
        cmd_json_get("missing", ['{"a": 1}'])
        cmd_json_get("a", ['note: signed\n', '{"a": 7}'])
    check(buf.getvalue() == "3\n7\n", "json-get (%r)" % buf.getvalue())
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cmd_records(["list", "--rule", "R020_ShellWithSocketStdio"], lines)
    check(rc == 0 and buf.getvalue() == "R020_ShellWithSocketStdio Critical KillProcessTree 77 "
          "stdio_tcp_127.0.0.1:44401_outbound\n", "records list (%r)" % buf.getvalue())
    buf, err = io.StringIO(), io.StringIO()
    with redirect_stdout(buf), redirect_stderr(err):
        rc = cmd_records(["count", "--pid"], lines)
    check(rc == 2 and "missing value" in err.getvalue(), "records refuses a flag without its value")

    if fails:
        for f in fails:
            print("selftest FAIL: " + f)
        return 1
    print("selftest: OK (nn-ms-net.py)")
    return 0


def main(argv):
    if not argv:
        print("usage: see the header of nn-ms-net.py", file=sys.stderr)
        return 2
    cmd, args = argv[0], argv[1:]
    table = {
        "listen": cmd_listen,
        "hold": cmd_hold,
        "beacon": cmd_beacon,
        "sweep": cmd_sweep,
        "ports": cmd_ports,
        "brute": cmd_brute,
        "pty-shell": cmd_pty_shell,
        "burst": cmd_burst,
        "once": cmd_once,
    }
    if cmd == "records":
        return cmd_records(args, sys.stdin)
    if cmd == "json-get" and len(args) == 1:
        return cmd_json_get(args[0], sys.stdin)
    if cmd == "selftest":
        return selftest()
    fn = table.get(cmd)
    if fn is None:
        print("unknown command %s" % cmd, file=sys.stderr)
        return 2
    try:
        return fn(*args)
    except TypeError as e:
        print("%s: %s" % (cmd, e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
