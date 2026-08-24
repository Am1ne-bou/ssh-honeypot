"""
Groups sessions by their exact command sequence.

Same idea as replay.py but the output is one block per *distinct* sequence
instead of one block per session -- 100k sessions collapse to a few hundred
sequences. Echo-inject runs are folded during ingest, so the 43k-chunk ELF
sessions never blow up in memory.

Usage:
  python3 analysis/seqgroup.py <log_dir> [options]

Options:
  --out DIR         output dir (default: seqgroup-YYYY-MM-DD next to cwd)
  --min-cmds N      skip sessions with fewer than N commands (default 1)
  --top N           only write the N biggest clusters to clusters.txt (default all)
  --max-seq-lines N truncate a printed sequence after N lines (default 60)
  --max-sids N      list at most N session ids per cluster (default 5)
  --max-ips N       list at most N source ips per cluster (default 10)
  --normalize       fold hex blobs / ips / long digit runs before hashing
  --dedup-all       dedup every session, not just the known-contaminated dates

Dedup: a merged log can hold the same record twice when a rotation block gets
spliced in more than once. A doubled command list hashes differently from the
clean one, so the session splits off into a bogus cluster and looks like a novel
pattern -- exactly the thing that would get mistaken for a new family. Records
carry nanosecond timestamps, so two records in one session sharing a timestamp
are the same record, never two events.

Order is not restored here: only whole sessions get misplaced by a bad splice
(the events inside one session stay in the order the honeypot wrote them), so
dropping the repeat copy is enough.
"""

import hashlib
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

ECHO_RE = re.compile(r'^echo(\s+-[a-zA-Z]+)+\s+["\']')
HEXBYTE_RE = re.compile(r'\\x[0-9a-fA-F]{2}')
TARGET_RE = re.compile(r'>>\s*(\S+)')

IP_RE = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
HEXBLOB_RE = re.compile(r'\b[0-9a-fA-F]{16,}\b')
DIGITS_RE = re.compile(r'\b\d{5,}\b')

# date prefixes duplicated by the 2026-08-23 merge: the legacy auth.log.1.gz /
# session.log.1.gz block (05-26..05-30) got prepended when it was already present,
# and 07-29 was re-appended from session.log-2026-07-30.gz (dateext names a file
# for the day the rotation ran, not the day it covers). Holding a timestamp set
# for every session would cost ~14M entries; gating on these keeps it near 2M.
# --dedup-all ignores this and pays the full price.
DIRTY_DATES = ("2026-05-26", "2026-05-27", "2026-05-28", "2026-05-29",
               "2026-05-30", "2026-07-29")


def load_jsonlines(path):
    try:
        f = open(path, errors="replace")
    except FileNotFoundError:
        print("no session.log in that dir", file=sys.stderr)
        sys.exit(1)
    with f:
        for line in f:
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def is_echo_inject(cmd):
    return bool(ECHO_RE.match(cmd))


def echo_target(cmd):
    m = TARGET_RE.search(cmd)
    return m.group(1) if m else "?"


def normalize(cmd):
    cmd = IP_RE.sub("<IP>", cmd)
    cmd = HEXBLOB_RE.sub("<HEX>", cmd)
    cmd = DIGITS_RE.sub("<N>", cmd)
    return cmd


def rabat(ts):
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return "?"
    return (dt + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M")


# one entry per session while streaming -- keeps only what the fingerprint needs
class Session:
    __slots__ = ("seq", "ip", "client", "user", "first", "last",
                 "echo_target", "echo_count", "echo_bytes", "seen_ts")

    def __init__(self):
        self.seq = []
        self.seen_ts = None
        self.ip = "?"
        self.client = "?"
        self.user = "?"
        self.first = ""
        self.last = ""
        self.echo_target = None
        self.echo_count = 0
        self.echo_bytes = 0

    # an echo run only becomes a seq line once the run ends
    def flush_echo(self):
        if self.echo_target is None:
            return
        self.seq.append("[%d echo chunks -> %s (~%.1f KB)]" % (
            self.echo_count, self.echo_target, self.echo_bytes / 1024))
        self.echo_target = None
        self.echo_count = 0
        self.echo_bytes = 0

    def push(self, line):
        self.flush_echo()
        self.seq.append(line)

    def push_echo(self, target, nbytes):
        if target != self.echo_target:
            self.flush_echo()
            self.echo_target = target
        self.echo_count += 1
        self.echo_bytes += nbytes


def ingest(path, do_normalize, dedup_all):
    sessions = defaultdict(Session)
    dups = 0
    for rec in load_jsonlines(path):
        sid = rec.get("sid", "")[:12]
        if not sid:
            continue
        msg = rec.get("msg", "")
        ts = rec.get("time", "")
        s = sessions[sid]

        if dedup_all or ts[:10] in DIRTY_DATES:
            if s.seen_ts is None:
                s.seen_ts = set()
            if (ts, msg) in s.seen_ts:
                dups += 1
                continue
            s.seen_ts.add((ts, msg))

        if not s.first:
            s.first = ts
        s.last = ts

        if msg == "handshake ok":
            s.ip = rec.get("remote", "?").split(":")[0]
            s.client = rec.get("client", "?")
            s.user = rec.get("user", "?")
        elif msg in ("shell", "exec"):
            cmd = rec.get("command", "").strip()
            if is_echo_inject(cmd) and echo_target(cmd) != "?":
                s.push_echo(echo_target(cmd), len(HEXBYTE_RE.findall(cmd)))
            else:
                if do_normalize:
                    cmd = normalize(cmd)
                s.push(("exec: " if msg == "exec" else "") + cmd)
        elif msg == "wget fetch":
            s.push("  [wget -> %s]" % rec.get("url", "?"))
        elif msg == "curl fetch":
            s.push("  [curl -> %s]" % rec.get("url", "?"))
        elif msg == "scp receive":
            s.push("  [scp upload started]")
        elif msg == "scp file":
            s.push("  [scp file: %s  %s bytes]" % (rec.get("name", "?"), rec.get("size", "?")))
        elif msg == "scp payload saved":
            s.push("  [quarantined sha256=%s]" % rec.get("sha256", "?")[:16])

    for s in sessions.values():
        s.flush_echo()
        s.seen_ts = None
    return sessions, dups


def cluster(sessions, min_cmds):
    groups = {}
    skipped = 0
    for sid, s in sessions.items():
        # log-only lines (wget/scp markers) don't count as commands
        ncmds = sum(1 for l in s.seq if not l.startswith("  ["))
        if ncmds < min_cmds:
            skipped += 1
            continue
        blob = "\n".join(s.seq)
        h = hashlib.sha1(blob.encode("utf-8", "replace")).hexdigest()[:10]
        g = groups.get(h)
        if g is None:
            g = groups[h] = {
                "hash": h, "seq": s.seq, "ncmds": ncmds, "count": 0,
                "sids": [], "ips": defaultdict(int), "clients": defaultdict(int),
                "users": defaultdict(int), "first": s.first, "last": s.last,
            }
        g["count"] += 1
        g["sids"].append(sid)
        g["ips"][s.ip] += 1
        g["clients"][s.client] += 1
        g["users"][s.user] += 1
        if s.first and s.first < g["first"]:
            g["first"] = s.first
        if s.last > g["last"]:
            g["last"] = s.last
    return groups, skipped


def write_output(groups, skipped, total, outdir, args):
    os.makedirs(outdir, exist_ok=True)
    ordered = sorted(groups.values(), key=lambda g: (-g["count"], -g["ncmds"]))

    index = open(os.path.join(outdir, "summary.txt"), "w")
    index.write("sessions ingested: %d   with >=%d cmds: %d   distinct sequences: %d\n"
                % (total, args["min_cmds"], total - skipped, len(ordered)))
    index.write("%-4s %-11s %8s %6s %6s  %-16s %-16s\n"
                % ("#", "hash", "sessions", "cmds", "ips", "first", "last"))
    for n, g in enumerate(ordered, 1):
        index.write("%-4d %-11s %8d %6d %6d  %-16s %-16s\n" % (
            n, g["hash"], g["count"], g["ncmds"], len(g["ips"]),
            rabat(g["first"]), rabat(g["last"])))
    index.close()

    limit = args["top"] or len(ordered)
    body = open(os.path.join(outdir, "clusters.txt"), "w")
    for n, g in enumerate(ordered[:limit], 1):
        body.write("=" * 70 + "\n")
        body.write("#%d  %s   seen %d time(s)   %d command(s)\n" % (
            n, g["hash"], g["count"], g["ncmds"]))
        body.write("first %s   last %s   Rabat\n" % (rabat(g["first"]), rabat(g["last"])))

        ips = sorted(g["ips"].items(), key=lambda kv: -kv[1])
        body.write("ips (%d): %s%s\n" % (
            len(ips),
            ", ".join("%s x%d" % (ip, n2) for ip, n2 in ips[:args["max_ips"]]),
            " ..." if len(ips) > args["max_ips"] else ""))

        clients = sorted(g["clients"].items(), key=lambda kv: -kv[1])[:3]
        users = sorted(g["users"].items(), key=lambda kv: -kv[1])[:3]
        body.write("clients: %s\n" % ", ".join("%s x%d" % t for t in clients))
        body.write("users: %s\n" % ", ".join("%s x%d" % t for t in users))
        body.write("sids: %s%s\n" % (
            ", ".join(g["sids"][:args["max_sids"]]),
            " ..." if len(g["sids"]) > args["max_sids"] else ""))
        body.write("-" * 70 + "\n")

        seq = g["seq"]
        cap = args["max_seq_lines"]
        for line in seq[:cap]:
            body.write("  " + line + "\n")
        if len(seq) > cap:
            body.write("  ... (%d more lines)\n" % (len(seq) - cap))
        body.write("\n")
    body.close()

    with open(os.path.join(outdir, "clusters.json"), "w") as f:
        json.dump([{
            "hash": g["hash"],
            "count": g["count"],
            "ncmds": g["ncmds"],
            "first": g["first"],
            "last": g["last"],
            "ips": dict(sorted(g["ips"].items(), key=lambda kv: -kv[1])),
            "clients": dict(g["clients"]),
            "users": dict(g["users"]),
            "sids": g["sids"][:50],
            "seq": g["seq"],
        } for g in ordered], f, indent=1)

    return ordered, outdir


def main():
    args = sys.argv[1:]
    if not args or args[0].startswith("--"):
        logdir = "./logs"
    else:
        logdir = args.pop(0)

    opts = {"min_cmds": 1, "top": 0, "max_seq_lines": 60,
            "max_sids": 5, "max_ips": 10}
    outdir = None
    do_normalize = False
    dedup_all = False

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--out" and i + 1 < len(args):
            outdir = args[i+1]; i += 2
        elif a == "--min-cmds" and i + 1 < len(args):
            opts["min_cmds"] = int(args[i+1]); i += 2
        elif a == "--top" and i + 1 < len(args):
            opts["top"] = int(args[i+1]); i += 2
        elif a == "--max-seq-lines" and i + 1 < len(args):
            opts["max_seq_lines"] = int(args[i+1]); i += 2
        elif a == "--max-sids" and i + 1 < len(args):
            opts["max_sids"] = int(args[i+1]); i += 2
        elif a == "--max-ips" and i + 1 < len(args):
            opts["max_ips"] = int(args[i+1]); i += 2
        elif a == "--normalize":
            do_normalize = True; i += 1
        elif a == "--dedup-all":
            dedup_all = True; i += 1
        else:
            i += 1

    if outdir is None:
        outdir = "seqgroup-" + datetime.now().strftime("%Y-%m-%d")

    sessions, dups = ingest(os.path.join(logdir, "session.log"), do_normalize, dedup_all)
    total = len(sessions)
    groups, skipped = cluster(sessions, opts["min_cmds"])
    sessions.clear()

    if not groups:
        print("no sessions with >=%d commands" % opts["min_cmds"], file=sys.stderr)
        sys.exit(1)

    ordered, outdir = write_output(groups, skipped, total, outdir, opts)
    if dups:
        print("dropped %d duplicate records" % dups)
    print("%d sessions -> %d distinct sequences" % (total - skipped, len(ordered)))
    print("wrote %s/{summary.txt,clusters.txt,clusters.json}" % outdir)


if __name__ == "__main__":
    main()
