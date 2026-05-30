"""
SSH honeypot log analyzer. Reads auth.log, session.log, server.log from a
directory of JSON-lines files and prints a summary report.

Usage: python3 analysis/stats.py [log_dir]
  log_dir defaults to ./logs if not given.
"""

import argparse
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime


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


SPRAY_MIN_IPS    = 3
SPRAY_WINDOW_MINS = 60

# fingerprints keyed by family name; tested against raw command strings
FAMILIES = [
    ("ELF echo injector", lambda c: bool(re.search(r"echo -e -n.*>> /tmp/", c))),
    ("Diicot GPU miner",  lambda c: "lspci | egrep VGA" in c),
    ("C2 dropper",        lambda c: "14.46.136.77" in c),
    ("astats dropper",    lambda c: "cat > astats" in c),
    ("VPS scout",         lambda c: "awk '{printf $1}'" in c),
    ("SSHCHK",            lambda c: "echo" in c and r"\x6F\x6B" in c),
    ("minimal scanner",   lambda c: c.strip() in ("uname -s -m", "uname -m", "uname -s")),
    ("password changer",  lambda c: "chpasswd" in c or c.strip() == "passwd"),
]


def parse_ts(s):
    """Parse an ISO 8601 timestamp, tolerating nanosecond precision."""
    s = s.rstrip("Z")
    if "." in s:
        base, frac = s.split(".", 1)
        s = base + "." + frac[:6]
    return datetime.fromisoformat(s + "+00:00")


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
    parser.add_argument(
        "--full",
        action="store_true",
        help="show all entries instead of top N",
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
    spray_buckets = {}  # (pw, user) -> list of (ts_str, ip)
    echo_targets  = Counter()  # /tmp/X -> chunk count
    family_sids   = {name: set() for name, _ in FAMILIES}

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

        if pw and user and remote and ts:
            key = (pw, user)
            if key not in spray_buckets:
                spray_buckets[key] = []
            spray_buckets[key].append((ts, strip_port(remote)))

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
                m = re.search(r">> (/tmp/\S+)", cmd)
                if m:
                    echo_targets[m.group(1)] += 1
                sid = rec.get("sid", "")
                for name, test in FAMILIES:
                    if test(cmd):
                        family_sids[name].add(sid)

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

    N = 10**9 if args.full else None

    heading("TOP 15 PASSWORDS" if not args.full else "ALL PASSWORDS")
    print_top(passwords, N or 15)

    heading("TOP 15 USERNAMES" if not args.full else "ALL USERNAMES")
    print_top(usernames, N or 15)

    heading("TOP 15 SOURCE IPs" if not args.full else "ALL SOURCE IPs")
    print_top(source_ips, N or 15)

    heading("TOP 10 CLIENT BANNERS" if not args.full else "ALL CLIENT BANNERS")
    print_top(banners, N or 10)

    heading("ALL COMMANDS" if args.full else "TOP 20 COMMANDS")
    print_top(commands, N or 20)

    heading("TIME RANGE")
    if timestamps:
        # ISO 8601 strings sort lexicographically -- no datetime parsing needed
        timestamps.sort()
        print("  Earliest : %s" % timestamps[0])
        print("  Latest   : %s" % timestamps[-1])
    else:
        print("  (no timestamps found)")

    heading("ECHO INJECTION TARGETS")
    if echo_targets:
        print_top(echo_targets, None)
        print("  --")
        print("  total chunks : %d" % sum(echo_targets.values()))
    else:
        print("  (none)")

    heading("CREDENTIAL SPRAYS  (>=%d IPs in <=%d min window)" % (SPRAY_MIN_IPS, SPRAY_WINDOW_MINS))
    # sliding window: find tightest burst per credential, not just total span
    window_secs = SPRAY_WINDOW_MINS * 60
    sprays = []
    for (pw, user), events in spray_buckets.items():
        if len(events) < SPRAY_MIN_IPS:
            continue
        parsed = sorted((parse_ts(ts).timestamp(), ip) for ts, ip in events)
        ip_counts = {}
        best_n = 0
        best_span = 0.0
        left = 0
        for right, (epoch, ip) in enumerate(parsed):
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            while epoch - parsed[left][0] > window_secs:
                old_ip = parsed[left][1]
                ip_counts[old_ip] -= 1
                if ip_counts[old_ip] == 0:
                    del ip_counts[old_ip]
                left += 1
            n = len(ip_counts)
            if n > best_n:
                best_n = n
                best_span = (epoch - parsed[left][0]) / 60.0
        if best_n >= SPRAY_MIN_IPS:
            sprays.append((best_n, best_span, user, pw))
    sprays.sort(reverse=True)
    if sprays:
        for n_ips, mins, user, pw in sprays:
            print("  %3d IPs  %5.0f min  %s / %s" % (n_ips, mins, user, pw))
    else:
        print("  (none)")

    heading("ATTACK FAMILIES (unique sessions)")
    active = [(name, len(sids)) for name, sids in family_sids.items() if sids]
    active.sort(key=lambda x: x[1], reverse=True)
    if active:
        name_w = max(len(n) for n, _ in active)
        for name, n in active:
            print("  %-*s  %d sessions" % (name_w, name, n))
    else:
        print("  (none identified)")

    print()


if __name__ == "__main__":
    main()
