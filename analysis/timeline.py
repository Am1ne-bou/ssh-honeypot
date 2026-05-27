"""
First-seen / last-seen tracker for passwords and commands.
Also flags passwords that appear in both login attempts and chpasswd values
so you can watch the credential feedback loop close in real time.

Usage: python3 analysis/timeline.py [log_dir]
  log_dir defaults to ./logs if not given.
"""

import json
import os
import sys
from collections import defaultdict


def load_jsonlines(path):
    try:
        f = open(path)
    except FileNotFoundError:
        print("WARNING: %s not found, skipping" % path, file=sys.stderr)
        return
    except OSError as e:
        print("WARNING: could not open %s: %s" % (path, e), file=sys.stderr)
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


def heading(title):
    print()
    print(title)
    print("-" * len(title))


def main():
    logdir = sys.argv[1] if len(sys.argv) > 1 else "./logs"
    auth_path    = os.path.join(logdir, "auth.log")
    session_path = os.path.join(logdir, "session.log")

    # password -> {first, last, count, in_chpasswd}
    pw_first  = {}
    pw_last   = {}
    pw_count  = defaultdict(int)
    pw_chpasswd = set()  # passwords seen in "echo root:X | chpasswd"

    # command -> {first, last, count}
    cmd_first = {}
    cmd_last  = {}
    cmd_count = defaultdict(int)

    for rec in load_jsonlines(auth_path):
        if rec.get("msg") != "auth attempt":
            continue
        pw = rec.get("password", "")
        ts = rec.get("time", "")
        if not pw or not ts:
            continue
        pw_count[pw] += 1
        if pw not in pw_first or ts < pw_first[pw]:
            pw_first[pw] = ts
        if pw not in pw_last or ts > pw_last[pw]:
            pw_last[pw] = ts

    for rec in load_jsonlines(session_path):
        msg = rec.get("msg", "")
        ts  = rec.get("time", "")
        if msg not in ("shell", "exec"):
            continue
        cmd = rec.get("command", "").strip()
        if not cmd or not ts:
            continue

        # extract chpasswd passwords -- "echo 'root:PASSWORD' | chpasswd"
        if "chpasswd" in cmd:
            # find the value after "root:" inside quotes or not
            import re
            m = re.search(r"root:([^\s'\"\\]+)", cmd)
            if m:
                pw_chpasswd.add(m.group(1))

        cmd_count[cmd] += 1
        if cmd not in cmd_first or ts < cmd_first[cmd]:
            cmd_first[cmd] = ts
        if cmd not in cmd_last or ts > cmd_last[cmd]:
            cmd_last[cmd] = ts

    # --- report ---
    print("=" * 60)
    print("FIRST/LAST SEEN TIMELINE")
    print("Log dir: %s" % os.path.abspath(logdir))
    print("=" * 60)

    heading("CREDENTIAL FEEDBACK LOOP")
    overlap = set(pw_first.keys()) & pw_chpasswd
    if not overlap:
        print("  No overlap yet -- chpasswd passwords not seen in login attempts.")
    else:
        print("  Passwords seen in BOTH login attempts AND chpasswd values:")
        for pw in sorted(overlap):
            print("    %-32s  first login: %s  count: %d" % (
                pw, pw_first[pw][11:19], pw_count[pw]))

    # passwords only in chpasswd (not yet looped back)
    only_chpasswd = pw_chpasswd - set(pw_first.keys())
    if only_chpasswd:
        print()
        print("  Passwords in chpasswd but NOT yet seen in login attempts (watch for loop-back):")
        for pw in sorted(only_chpasswd):
            print("    %s" % pw)

    heading("NEW PASSWORDS OVER TIME  (first 20 by first-seen)")
    items = sorted(pw_first.items(), key=lambda x: x[1])[:20]
    if not items:
        print("  (none)")
    else:
        print("  %-32s  %-8s  %-8s  %s" % ("password", "first", "last", "count"))
        for pw, first in items:
            last  = pw_last.get(pw, "?")
            count = pw_count[pw]
            flag  = " <-- chpasswd" if pw in pw_chpasswd else ""
            print("  %-32s  %-8s  %-8s  %d%s" % (
                pw[:32], first[11:19], last[11:19], count, flag))

    heading("NEW COMMANDS OVER TIME  (first 20 by first-seen)")
    items = sorted(cmd_first.items(), key=lambda x: x[1])[:20]
    if not items:
        print("  (none)")
    else:
        print("  %-60s  %-8s  %-8s  %s" % ("command", "first", "last", "count"))
        for cmd, first in items:
            last  = cmd_last.get(cmd, "?")
            count = cmd_count[cmd]
            display = cmd if len(cmd) <= 60 else cmd[:57] + "..."
            print("  %-60s  %-8s  %-8s  %d" % (display, first[11:19], last[11:19], count))

    print()


if __name__ == "__main__":
    main()
