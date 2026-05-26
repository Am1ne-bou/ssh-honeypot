"""
SSH honeypot log analyzer. Reads auth.log, session.log, server.log from a
directory of JSON-lines files and prints a summary report.

Usage: python3 analysis/stats.py [log_dir]
  log_dir defaults to ./logs if not given.
"""

import argparse
import json
import os
import sys
from collections import Counter


def load_jsonlines(path):
    """Yield parsed dicts from a JSON-lines file. Skip bad lines, warn on missing file."""
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
                # malformed line -- log rotation artifacts, truncated writes, etc.
                continue


def heading(title):
    print()
    print(title)
    print("-" * len(title))


def print_top(counter, n):
    items = counter.most_common(n)
    if not items:
        print("  (none)")
        return
    # right-align counts so columns line up regardless of key length
    count_width = len(str(items[0][1]))
    key_width = max(len(str(k)) for k, _ in items)
    for k, v in items:
        print("  %-*s  %*d" % (key_width, k, count_width, v))


def strip_port(remote):
    """Extract IP from 'IP:port'. Handles IPv6 '[::1]:port' by keeping brackets."""
    # rsplit on last colon -- safe for both IPv4 and IPv6 bracket notation
    return remote.rsplit(":", 1)[0]


def main():
    parser = argparse.ArgumentParser(
        description="Analyze SSH honeypot JSON log files."
    )
    parser.add_argument(
        "logdir",
        nargs="?",
        default="./logs",
        help="directory containing auth.log, session.log, server.log (default: ./logs)",
    )
    args = parser.parse_args()

    auth_path    = os.path.join(args.logdir, "auth.log")
    session_path = os.path.join(args.logdir, "session.log")
    server_path  = os.path.join(args.logdir, "server.log")

    passwords   = Counter()
    usernames   = Counter()
    source_ips  = Counter()
    banners     = Counter()
    commands    = Counter()
    accepted    = 0
    rejected    = 0
    timestamps  = []

    # --- auth.log ---
    for rec in load_jsonlines(auth_path):
        if rec.get("msg") != "auth attempt":
            continue

        outcome = rec.get("outcome", "")
        if outcome == "accepted":
            accepted += 1
        elif outcome == "rejected":
            rejected += 1

        pw = rec.get("password", "")
        if pw:
            passwords[pw] += 1

        user = rec.get("user", "")
        if user:
            usernames[user] += 1

        remote = rec.get("remote", "")
        if remote:
            source_ips[strip_port(remote)] += 1

        banner = rec.get("client", "")
        if banner:
            banners[banner] += 1

        ts = rec.get("time")
        if ts:
            timestamps.append(ts)

    # --- session.log ---
    # msg=="shell": attacker typed a line in the fake shell, "command" has the input
    # msg=="exec":  attacker sent an exec request directly (scp, rsync, one-shot cmds)
    for rec in load_jsonlines(session_path):
        ts = rec.get("time")
        if ts:
            timestamps.append(ts)

        msg = rec.get("msg", "")
        if msg in ("shell", "exec"):
            cmd = rec.get("command", "").strip()
            if cmd:
                commands[cmd] += 1

    # --- server.log (timestamps only, for time range) ---
    for rec in load_jsonlines(server_path):
        ts = rec.get("time")
        if ts:
            timestamps.append(ts)

    total = accepted + rejected

    # --- report ---
    print("=" * 52)
    print("SSH HONEYPOT REPORT")
    print("Log dir: %s" % os.path.abspath(args.logdir))
    print("=" * 52)

    heading("SUMMARY")
    print("  Total auth attempts    : %d" % total)
    print("  Unique source IPs      : %d" % len(source_ips))
    print("  Unique passwords tried : %d" % len(passwords))
    print("  Accepted               : %d" % accepted)
    print("  Rejected               : %d" % rejected)
    print("  Commands captured      : %d" % sum(commands.values()))

    heading("TOP 15 PASSWORDS")
    print_top(passwords, 15)

    heading("TOP 15 USERNAMES")
    print_top(usernames, 15)

    heading("TOP 15 SOURCE IPs")
    print_top(source_ips, 15)

    heading("TOP 10 CLIENT BANNERS")
    print_top(banners, 10)

    heading("TOP 20 COMMANDS")
    print_top(commands, 20)

    heading("TIME RANGE")
    if timestamps:
        # ISO 8601 strings sort lexicographically -- no datetime parsing needed
        timestamps.sort()
        print("  Earliest : %s" % timestamps[0])
        print("  Latest   : %s" % timestamps[-1])
    else:
        print("  (no timestamps found)")

    print()


if __name__ == "__main__":
    main()
