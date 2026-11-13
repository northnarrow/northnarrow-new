#!/usr/bin/env python3
"""Lot 283a — the benign corpus's report (corpus-lib.sh, corpus_report).

Reads, for one corpus run, the steps file (name, begin and end in wall-clock
and monotonic ns, rc, the posture after the step) and the slices of the
signed chains written after the run's mark — the detections chain (every
verdict, with the posture the agent judged it in), the actions chain (kill
intents and their outcomes) and the audit log (COMBAT stages) — and prints,
by step, every kill, every verdict and every COMBAT entry: the rule, the
process, the posture at the time. With the small-file probe's output, it
adds the in-place rewrites of small files: for each step, the most distinct
existing files under 4 KiB one process opened for writing in any 60 s.

Every record is attributed to the last step begun before it (a record more
than 10 s after that step's end is marked "after"). Lines starting with
"TSV" are the same facts, tab-separated, for the inventory.

Stdlib only; run with `python3 -I`.
"""

import argparse
import calendar
import json
import re
import sys
from collections import Counter, defaultdict

TS = re.compile(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.(\d+))?(Z|[+-]\d\d:?\d\d)?")
SMALL = 4096
WINDOW_NS = 60 * 10**9
THRESHOLD = 50


def ts_ns(s):
    """An RFC 3339 time as epoch ns (UTC when no offset), or None."""
    m = TS.search(s or "")
    if not m:
        return None
    y, mo, d, h, mi, se, frac, off = m.groups()
    t = calendar.timegm((int(y), int(mo), int(d), int(h), int(mi), int(se)))
    ns = t * 10**9 + int(((frac or "") + "000000000")[:9])
    if off and off != "Z":
        sign = 1 if off[0] == "+" else -1
        hh, mm = int(off[1:3]), int(off[-2:])
        ns -= sign * (hh * 3600 + mm * 60) * 10**9
    return ns


def find(obj, pred):
    """The first dict in obj (depth first) that pred accepts."""
    if isinstance(obj, dict):
        if pred(obj):
            return obj
        for v in obj.values():
            r = find(v, pred)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = find(v, pred)
            if r is not None:
                return r
    return None


def rows(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except ValueError:
                    continue
    except OSError:
        return


def load_steps(path):
    steps = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 7:
                continue
            steps.append(
                dict(name=p[0], t0=int(p[1]), t1=int(p[2]), m0=int(p[3]), m1=int(p[4]), rc=p[5], posture=p[6] or "?")
            )
    return steps


def attribute(steps, ns):
    """The step a record of wall-clock time ns belongs to."""
    if ns is None:
        return "?"
    cur = None
    for s in steps:
        if s["t0"] <= ns:
            cur = s
    if cur is None:
        return "(before the first step)"
    if ns > cur["t1"] + 10 * 10**9:
        return cur["name"] + " (after)"
    return cur["name"]


def is_kill(resp):
    return "Kill" in str(resp or "")


# Lot 341: an action the no-enforcement gate suppressed (the alpha profile,
# detect-only) — its outcome row's result, and a record's response text.
WOULD_EXECUTE = "would_execute"
WOULD_HAVE = "would have: "


def short(s, n):
    s = str(s if s is not None else "")
    return s if len(s) <= n else s[: n - 1] + "…"


def detections(path, steps):
    out = []
    for r in rows(path):
        d = find(r, lambda x: "posture_at" in x or ("rule_id" in x and "severity" in x))
        if d is None:
            continue
        pr = d.get("principal") or {}
        out.append(
            dict(
                ns=ts_ns(d.get("ts") or r.get("ts")),
                rule=d.get("rule_id") or d.get("detection_type") or "?",
                sev=d.get("severity"),
                resp=d.get("response"),
                verdict=d.get("verdict"),
                posture=d.get("posture_at"),
                pid=pr.get("pid"),
                comm=pr.get("comm"),
                uid=pr.get("uid"),
                exe=d.get("exe"),
                file=d.get("file"),
            )
        )
    for d in out:
        d["step"] = attribute(steps, d["ns"])
    return out


def actions(path, steps):
    intents, outcomes = {}, {}
    for r in rows(path):
        row = r.get("row")
        if row == "intent":
            i = r.get("intent") or {}
            why = i.get("why") or [""]
            intents[r.get("action")] = dict(
                ns=ts_ns(r.get("ts")),
                source=i.get("source"),
                resp=i.get("response"),
                pid=i.get("pid"),
                rule=why[0] if why else "",
                why=why,
            )
        elif row == "outcome":
            o = r.get("outcome") or {}
            outcomes[r.get("action")] = (str(o.get("outcome")), o.get("result"))
    out = []
    for k, i in intents.items():
        i["id"] = k
        i["outcome"], i["result"] = outcomes.get(k, ("(no outcome row)", None))
        i["step"] = attribute(steps, i["ns"])
        out.append(i)
    out.sort(key=lambda x: x["ns"] or 0)
    return out


def combat(path, steps):
    out = []
    for r in rows(path):
        e = find(r, lambda x: x.get("op") == "combat_stage")
        if e is None:
            continue
        s = json.dumps(e, sort_keys=True)
        out.append(dict(ns=ts_ns(e.get("ts") or r.get("ts") or s), text=s, step=None))
    for c in out:
        c["step"] = attribute(steps, c["ns"])
    return out


def journal(path, steps):
    """The agent's posture transitions and ConfirmedIntrusion raises
    (journalctl -o short-unix): context — the signed chains hold the
    verdicts; the trigger that moved the posture is in the journal."""
    out = []
    try:
        f = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return out
    with f:
        for line in f:
            p = line.split(None, 1)
            try:
                ns = int(float(p[0]) * 1e9)
            except (ValueError, IndexError):
                continue
            if "raising ConfirmedIntrusion" in line:
                kv = dict(re.findall(r'(\w+)=("[^"]*"|\S+)', line))
                g = lambda k: kv.get(k, "?").strip('"')
                text = "%s %s (pid %s) %s, %s/%s in %ss%s: %s" % (
                    g("trigger"), g("focal_comm"), g("focal_pid"), g("shape"), g("count_within_window"),
                    g("threshold"), g("window_secs"), ", its cgroup" if g("cgroup_window") == "true" else "",
                    g("focal_filename"))
                out.append(("raise", ns, text))
            elif "POSTURE TRANSITION" in line:
                m = re.search(r"state=.*", line)
                out.append(("transition", ns, m.group(0).strip() if m else line.strip()))
    return [(k, attribute(steps, ns), t) for k, ns, t in out]


def small_files(path, steps):
    """Per step: (max distinct files of one process in 60 s, tgid, comm,
    the same counting empty files too), the top three processes."""
    ev = defaultdict(list)  # tgid -> [(ns, dev:ino, size, comm)]
    attached = None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                p = line.split()
                if p and p[0] == "SF-READY":
                    attached = int(p[1]) if len(p) > 1 and p[1].isdigit() else 0
                    continue
                if len(p) != 7 or p[0] != "SF":
                    continue
                ev[int(p[2])].append((int(p[1]), p[4] + ":" + p[5], int(p[6]), p[3]))
    except OSError:
        return None
    if attached is None:
        return None
    res = {}
    for s in steps:
        if s["m0"] < attached:
            res[s["name"]] = None  # begun before the probe was attached
            continue
        per = []
        for tgid, es in ev.items():
            sel = sorted(e for e in es if s["m0"] <= e[0] <= s["m1"])
            if not sel:
                continue
            best = []
            for nonempty in (True, False):
                xs = [e for e in sel if e[2] > 0] if nonempty else sel
                win, cnt, j, m = Counter(), 0, 0, 0
                for e in xs:
                    win[e[1]] += 1
                    while xs[j][0] < e[0] - WINDOW_NS:
                        win[xs[j][1]] -= 1
                        if win[xs[j][1]] == 0:
                            del win[xs[j][1]]
                        j += 1
                    m = max(m, len(win))
                best.append(m)
            per.append((best[0], best[1], tgid, sel[-1][3]))
        per.sort(reverse=True)
        res[s["name"]] = per[:3]
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--steps", required=True)
    ap.add_argument("--actions", required=True)
    ap.add_argument("--detections", required=True)
    ap.add_argument("--audit", required=True)
    ap.add_argument("--smallfile", default="")
    ap.add_argument("--journal", default="")
    a = ap.parse_args()
    steps = load_steps(a.steps)
    dets = detections(a.detections, steps)
    acts = actions(a.actions, steps)
    stages = combat(a.audit, steps)
    sf = small_files(a.smallfile, steps) if a.smallfile else None
    C = a.corpus

    def detection_of(i):
        best = None
        for d in dets:
            if d["rule"] == i["rule"] and d["pid"] == i["pid"] and d["ns"] and i["ns"]:
                if best is None or abs(d["ns"] - i["ns"]) < abs(best["ns"] - i["ns"]):
                    best = d
        return best

    print("== report %s: %d steps, %d verdicts, %d action intents, %d COMBAT stages" % (C, len(steps), len(dets), len(acts), len(stages)))
    print("  kills (actions chain: intent → outcome; the process and posture from its verdict):")
    kills = [i for i in acts if is_kill(i["resp"]) and i["result"] != WOULD_EXECUTE]
    for i in kills:
        d = detection_of(i) or {}
        print(
            "    [%s] %s %s pid %s %s (%s) posture=%s → %s"
            % (
                short(i["step"], 40),
                short(i["rule"], 44),
                i["resp"],
                i["pid"],
                d.get("comm", "?"),
                short(d.get("exe", "?"), 70),
                d.get("posture", "?"),
                short(i["outcome"], 40),
            )
        )
        print(
            "TSV\tkill\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s"
            % (C, i["step"], i["rule"], i["resp"], d.get("comm", "?"), d.get("exe", "?"), d.get("posture", "?"), i["source"], i["outcome"])
        )
    if not kills:
        print("    none")
    # lot 341: what the gate suppressed — approved, never executed
    would = [i for i in acts if i["result"] == WOULD_EXECUTE]
    print("  would have (the no-enforcement gate: approved, not executed): %d" % len(would))
    for resp, n in Counter(i["resp"] for i in would).most_common():
        print("    %s ×%d" % (resp, n))
        print("TSV	would	%s	%s	%d" % (C, resp, n))
    other = [i for i in acts if not is_kill(i["resp"]) and i["result"] != WOULD_EXECUTE]
    if other:
        print("  other actions:")
        for i in other:
            print("    [%s] %s %s %s pid %s → %s" % (short(i["step"], 40), i["source"], short(i["rule"], 50), i["resp"], i["pid"], short(i["outcome"], 40)))
            print("TSV\taction\t%s\t%s\t%s\t%s\t%s\t%s" % (C, i["step"], i["rule"], i["resp"], i["source"], i["outcome"]))
    print("  COMBAT stages (audit log):")
    for c in stages:
        t = c["text"]
        k = t.find('"cause"')
        print("    [%s] %s" % (short(c["step"], 40), short(t[k:] if k >= 0 else t, 400)))
        print("TSV\tcombat\t%s\t%s\t%s" % (C, c["step"], short(t[k:] if k >= 0 else t, 400)))
    if not stages:
        print("    none")
    if a.journal:
        print("  posture transitions and ConfirmedIntrusion raises (the agent's journal, context):")
        js = journal(a.journal, steps)
        for kind, st, text in js:
            print("    [%s] %s %s" % (short(st, 40), kind, short(text, 300)))
            print("TSV\t%s\t%s\t%s\t%s" % (kind, C, st, text))
        if not js:
            print("    none")
    print("  verdicts by step (rule, severity, response, posture at the verdict, count, processes):")
    by = defaultdict(list)
    for d in dets:
        by[(d["step"], d["rule"], str(d["sev"]), str(d["resp"]), str(d["posture"]))].append(d)
    order = {s["name"]: n for n, s in enumerate(steps)}
    for key in sorted(by, key=lambda k: (order.get(k[0].replace(" (after)", ""), -1), k[0], k[1])):
        ds = by[key]
        comms = Counter(str(x["comm"]) for x in ds).most_common(3)
        files = [f for f, _ in Counter(str(x["file"]) for x in ds if x["file"]).most_common(2)]
        print(
            "    [%s] %s %s %s posture=%s ×%d (%s)%s"
            % (
                short(key[0], 40),
                short(key[1], 44),
                key[2],
                short(key[3], 20),
                key[4],
                len(ds),
                ", ".join("%s×%d" % c for c in comms),
                (" " + ", ".join(short(f, 80) for f in files)) if files else "",
            )
        )
        print("TSV\tverdict\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s" % (C, key[0], key[1], key[2], key[3], key[4], len(ds), ",".join(c[0] for c in comms), ",".join(files)))
    if not dets:
        print("    none")
    print("  steps (rc, posture after):")
    for s in steps:
        print("    %-46s rc=%-3s posture=%s" % (s["name"], s["rc"], s["posture"]))
        print("TSV\tstep\t%s\t%s\t%s\t%s\t%.1f" % (C, s["name"], s["rc"], s["posture"], (s["t1"] - s["t0"]) / 1e9))
    if a.smallfile:
        if sf is None:
            print("  small-file probe: no output (not attached)")
        else:
            print(
                "  small-file probe: most distinct existing files < 4 KiB one process opened for writing in 60 s"
                " (non-empty; with empty ones), threshold candidate %d:" % THRESHOLD
            )
            for s in steps:
                top = sf.get(s["name"])
                if top is None:
                    print("    %-46s n/a (begun before the probe was attached)" % s["name"])
                    print("TSV\tsmall\t%s\t%s\tn/a\tn/a\t-\t-" % (C, s["name"]))
                    continue
                if not top:
                    print("    %-46s 0" % s["name"])
                    print("TSV\tsmall\t%s\t%s\t0\t0\t-\t-" % (C, s["name"]))
                    continue
                m = top[0]
                flag = "  ≥ %d" % THRESHOLD if m[0] >= THRESHOLD else ""
                rest = "; ".join("%s(%d) %d/%d" % (t[3], t[2], t[0], t[1]) for t in top)
                print("    %-46s %d (%d)%s — %s" % (s["name"], m[0], m[1], flag, rest))
                print("TSV\tsmall\t%s\t%s\t%d\t%d\t%s\t%d" % (C, s["name"], m[0], m[1], m[3], m[2]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
