#!/usr/bin/env python3
"""
quick header-only report -- same numbers as report.py render_header,
but streams the big session.log instead of loading it all into memory.

usage: python3 analysis/quick-report.py <log-dir>
"""
import sys
import os
import json
from datetime import datetime


def main():
    if len(sys.argv) < 2:
        print("usage: python3 analysis/quick-report.py <log-dir>", file=sys.stderr)
        sys.exit(1)
    log_dir = sys.argv[1]

    # auth.log is small -- parse it fully for attempts / ips / accepted / span
    attempts = accepted = 0
    ips = set()
    tmin = tmax = None
    auth_path = os.path.join(log_dir, "auth.log")
    if os.path.exists(auth_path):
        with open(auth_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("msg") != "auth attempt":
                    continue
                attempts += 1
                if e.get("outcome") == "accepted":
                    accepted += 1
                r = e.get("remote")
                if r:
                    ips.add(r.split(":")[0])
                t = e.get("time")
                if t:
                    try:
                        dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
                        if tmin is None or dt < tmin:
                            tmin = dt
                        if tmax is None or dt > tmax:
                            tmax = dt
                    except ValueError:
                        pass

    # session.log is huge -- count commands by byte-scanning, no json parse.
    # a counted command line has msg shell/exec AND a command field, matching
    # report.py render_header exactly.
    commands = 0
    sess_path = os.path.join(log_dir, "session.log")
    if os.path.exists(sess_path):
        with open(sess_path, "rb") as f:
            for line in f:
                if b'"command":' not in line:
                    continue
                if b'"msg":"shell"' in line or b'"msg":"exec"' in line:
                    commands += 1

    if tmin and tmax:
        t0 = tmin.strftime("%Y-%m-%d %H:%M UTC")
        t1 = tmax.strftime("%Y-%m-%d %H:%M UTC")
        hours = (tmax - tmin).total_seconds() / 3600
        span = f"{t0}  ->  {t1}  ({hours:.1f}h)"
    else:
        span = "no timestamps"

    W = 62
    print()
    print("=" * W)
    print("  SSH HONEYPOT -- ATTACK REPORT")
    print("=" * W)
    print(f"  {span}")
    print()
    for val, label in [
        (attempts, "auth attempts"),
        (len(ips), "source IPs"),
        (accepted, "sessions accepted"),
        (commands, "commands captured"),
    ]:
        print(f"  {val:>10}  {label}")
    print()
    print("=" * W)
    print()


if __name__ == "__main__":
    main()
