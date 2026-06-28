"""
Terminal replay -- renders each session as it looked from the attacker's side.
Commands shown in order, echo injection folded by default.

Usage:
  python3 analysis/replay.py <log_dir> [options]

Options:
  --session SID   show only this session (partial match ok)
  --ip IP         show only sessions from this IP
  --min-cmds N    skip sessions with fewer than N commands (default 1)
  --no-fold       show every echo chunk unfolded
  --no-color      plain text output
"""

import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone


# -- colour helpers ----------------------------------------------------------

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RED    = "\033[31m"

USE_COLOR = True

def c(code, s):
    return code + s + RESET if USE_COLOR else s

def prompt(cwd="/root"):
    return c(GREEN, "root@ubuntu") + ":" + c(CYAN, cwd) + c(GREEN, "# ")


# -- log loading -------------------------------------------------------------

def load_jsonlines(path):
    try:
        f = open(path)
    except FileNotFoundError:
        return
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


# -- echo fold detection -----------------------------------------------------

ECHO_RE = re.compile(r'^echo(\s+-[a-zA-Z]+)+\s+["\']')

def is_echo_inject(cmd):
    return bool(ECHO_RE.match(cmd.strip()))

def echo_target(cmd):
    m = re.search(r'>>\s*(\S+)', cmd)
    return m.group(1) if m else "?"

def fold_echo_run(cmds):
    """
    Takes a list of consecutive echo-inject commands targeting the same file.
    Returns a one-line summary.
    """
    target = echo_target(cmds[0])
    total_bytes = 0
    for cmd in cmds:
        # count hex bytes: \xNN patterns
        total_bytes += len(re.findall(r'\\x[0-9a-fA-F]{2}', cmd))
    kb = total_bytes / 1024
    return "[... %d echo chunks -> %s (~%.1f KB ELF)]" % (len(cmds), target, kb)


# -- session rendering -------------------------------------------------------

def parse_ts(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None

def fmt_ts(ts):
    dt = parse_ts(ts)
    if not dt:
        return "?"
    # convert to Rabat time (UTC+1)
    from datetime import timedelta
    rabat = dt + timedelta(hours=1)
    return rabat.strftime("%Y-%m-%d %H:%M") + " Rabat"

def fmt_duration(t0, t1):
    dt0 = parse_ts(t0)
    dt1 = parse_ts(t1)
    if not dt0 or not dt1:
        return "?"
    secs = int((dt1 - dt0).total_seconds())
    if secs < 60:
        return "%ds" % secs
    return "%dm%ds" % (secs // 60, secs % 60)


def render_session(sid, evs, fold=True):
    if not evs:
        return

    # -- collect metadata --
    ip = "?"
    client = "?"
    user = "?"
    first_ts = evs[0][0]
    last_ts  = evs[-1][0]

    for ts, msg, rec in evs:
        if msg == "handshake ok":
            ip     = rec.get("remote", ip).split(":")[0]
            client = rec.get("client", client)
            user   = rec.get("user", user)
            break

    # extract commands in order
    # echo inject entries use kind="echo_inject" with the compact rec dict as payload
    cmds = []
    for ts, msg, rec in evs:
        if msg in ("shell", "exec"):
            if rec.get("_echo"):
                cmds.append((ts, "echo_inject", rec))
            else:
                cmds.append((ts, msg, rec.get("command", "").strip()))
        elif msg == "wget fetch":
            cmds.append((ts, "log", "  [wget -> %s]" % rec.get("url", "?")))
        elif msg == "curl fetch":
            cmds.append((ts, "log", "  [curl -> %s]" % rec.get("url", "?")))
        elif msg == "scp receive":
            cmds.append((ts, "log", "  [scp upload started]"))
        elif msg == "scp file":
            cmds.append((ts, "log", "  [scp file: %s  %s bytes]" % (
                rec.get("name","?"), rec.get("size","?"))))
        elif msg == "scp payload saved":
            cmds.append((ts, "log", "  [quarantined: sha256=%s...]" % rec.get("sha256","?")[:16]))

    # -- header --
    sep = "=" * 70
    print(c(BOLD, sep))
    print(c(BOLD, "  SESSION %s" % sid))
    print("  %s  |  %s  |  %s" % (
        c(YELLOW, ip), client, fmt_ts(first_ts)))
    print("  duration: %s  |  %d commands" % (
        fmt_duration(first_ts, last_ts), len([x for x in cmds if x[1] != "log"])))
    print(c(BOLD, sep))
    print()

    if not cmds:
        print(c(DIM, "  (no commands)"))
        print()
        return

    # -- render commands with echo folding --
    i = 0
    cwd = "/root"
    while i < len(cmds):
        ts, kind, cmd = cmds[i]

        if kind == "log":
            print(c(DIM, cmd))
            i += 1
            continue

        marker = c(DIM, "[exec] ") if kind == "exec" else ""

        # echo_inject: cmd is the compact rec dict
        if kind == "echo_inject":
            rec = cmd
            if fold:
                target = rec["_target"]
                run = [rec]
                j = i + 1
                while j < len(cmds):
                    _, k2, r2 = cmds[j]
                    if k2 == "echo_inject" and r2["_target"] == target:
                        run.append(r2)
                        j += 1
                    else:
                        break
                if len(run) >= 5:
                    total_bytes = sum(r.get("_nbytes", 0) for r in run)
                    kb = total_bytes / 1024
                    print(c(YELLOW, "[... %d echo chunks -> %s (~%.1f KB ELF)]" % (len(run), target, kb)))
                    i = j
                    continue
            # short run or --no-fold: compact per-chunk line
            print(prompt(cwd) + "[echo chunk -> %s (~%.1f KB)]" % (
                rec["_target"], rec.get("_nbytes", 0) / 1024))
            i += 1
            continue

        # track cwd -- only pure "cd <path>" with no compound operators
        if re.match(r'^cd\s+\S+$', cmd):
            dest = cmd.split(None, 1)[1].strip()
            if dest.startswith("/"):
                cwd = dest.rstrip("/") or "/"
            elif dest == "~":
                cwd = "/root"
            else:
                cwd = (cwd.rstrip("/") + "/" + dest)

        print(prompt(cwd) + marker + cmd)
        i += 1

    print()


# -- main --------------------------------------------------------------------

def main():
    args = sys.argv[1:]
    if not args or args[0].startswith("--"):
        logdir = "./logs"
    else:
        logdir = args.pop(0)

    filter_sid = None
    filter_ip  = None
    min_cmds   = 1
    fold       = True

    i = 0
    while i < len(args):
        a = args[i]
        if a == "--session" and i + 1 < len(args):
            filter_sid = args[i+1]; i += 2
        elif a == "--ip" and i + 1 < len(args):
            filter_ip = args[i+1]; i += 2
        elif a == "--min-cmds" and i + 1 < len(args):
            min_cmds = int(args[i+1]); i += 2
        elif a == "--no-fold":
            fold = False; i += 1
        elif a == "--no-color":
            global USE_COLOR
            USE_COLOR = False; i += 1
        else:
            i += 1

    session_path = os.path.join(logdir, "session.log")

    # group events by sid, keep chronological order
    # store compact dicts -- echo inject hex strings are ~600 bytes each and
    # there are millions of them, so we pre-classify and drop the payload
    events = defaultdict(list)
    for rec in load_jsonlines(session_path):
        sid = rec.get("sid", "")[:12]
        ts  = rec.get("time", "")
        msg = rec.get("msg", "")
        if msg == "handshake ok":
            data = {"remote": rec.get("remote","?"), "client": rec.get("client","?"), "user": rec.get("user","?")}
        elif msg in ("shell", "exec"):
            cmd = rec.get("command", "").strip()
            if is_echo_inject(cmd) and echo_target(cmd) != "?":
                nbytes = len(re.findall(r'\\x[0-9a-fA-F]{2}', cmd))
                data = {"_echo": True, "_target": echo_target(cmd), "_nbytes": nbytes, "command": ""}
            else:
                data = {"command": cmd}
        elif msg == "wget fetch":
            data = {"url": rec.get("url","?")}
        elif msg == "curl fetch":
            data = {"url": rec.get("url","?")}
        elif msg == "scp receive":
            data = {}
        elif msg == "scp file":
            data = {"name": rec.get("name","?"), "size": rec.get("size","?")}
        elif msg == "scp payload saved":
            data = {"sha256": rec.get("sha256","?")}
        else:
            continue
        events[sid].append((ts, msg, data))

    if not events:
        print("no sessions found in", logdir, file=sys.stderr)
        sys.exit(1)

    # sort each session's events
    for sid in events:
        events[sid].sort(key=lambda x: x[0])

    # sort sessions by start time
    sessions = sorted(events.items(), key=lambda kv: kv[1][0][0] if kv[1] else "")

    count = 0
    for sid, evs in sessions:
        # apply filters
        if filter_sid and filter_sid not in sid:
            continue

        ip = "?"
        for _, msg, rec in evs:
            if msg == "handshake ok":
                ip = rec.get("remote", "?").split(":")[0]
                break

        if filter_ip and filter_ip not in ip:
            continue

        ncmds = sum(1 for _, msg, _ in evs if msg in ("shell", "exec"))
        if ncmds < min_cmds:
            continue

        render_session(sid, evs, fold=fold)
        count += 1

    if count == 0:
        print("no sessions matched filters", file=sys.stderr)


if __name__ == "__main__":
    main()
