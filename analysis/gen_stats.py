"""
Generate STATS.md, the single source of truth for honeypot numbers.

Streams the JSON-lines logs (auth.log, session.log, server.log) from a log
directory and writes a Markdown file with generation time, coverage window,
totals, top-15 tables, classified family count, and payload counts.

Usage: python3 analysis/gen_stats.py <log_dir> [--out STATS.md] [--mapping family_mapping.json]
  log_dir defaults to ./logs
  --out defaults to STATS.md next to this script's repo root
  --mapping defaults to family_mapping.json at the repo root

STATS.md is generated. Never hand-edit it. Never put VPS host, port, or server
paths in here -- this file is committed and may be pushed.

Duplicate records are dropped before counting. A merged log can contain the same
record twice when a rotation block gets concatenated in more than once (logrotate
dateext names a file for the day the rotation RAN, so *-07-30.gz holds 07-29 data
-- easy to splice in twice). Timestamps are nanosecond precision, so two records
sharing a timestamp AND an identity key are the same record, never two events.
"""

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone


# date prefixes the 2026-08-23 merge duplicated (legacy .1.gz block re-prepended,
# and 07-29 re-appended from the file dateext named -07-30). Command records are
# far too many to dedup wholesale, so the bookkeeping is gated to these days.
DIRTY_DATES = ("2026-05-26", "2026-05-27", "2026-05-28", "2026-05-29",
               "2026-05-30", "2026-07-29")


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
                continue


def strip_port(remote):
    """Extract IP from 'IP:port'. Handles IPv6 '[::1]:port' by keeping brackets."""
    return remote.rsplit(":", 1)[0]


def parse_ts(s):
    """Parse an ISO 8601 timestamp, tolerating nanosecond precision. Returns aware UTC datetime."""
    s = s.rstrip("Z")
    if "." in s:
        base, frac = s.split(".", 1)
        s = base + "." + frac[:6]
    return datetime.fromisoformat(s + "+00:00")


def count_families(mapping_path):
    """Count distinct family_id values in family_mapping.json (incl. sub_splits and multi-tag).
    Returns (count, None) on success, (None, reason) if the mapping is missing/unreadable."""
    try:
        data = json.load(open(mapping_path))
    except (FileNotFoundError, OSError):
        return None, "family_mapping.json not found at %s" % mapping_path
    except json.JSONDecodeError as e:
        return None, "family_mapping.json parse error: %s" % e

    fams = set()
    for entry in data:
        fid = entry.get("family_id")
        if isinstance(fid, list):
            fams.update(fid)
        elif fid:
            fams.add(fid)
        for split in (entry.get("sub_splits") or []):
            sf = split.get("family_id")
            if sf:
                fams.add(sf)
    return len(fams), None


def ascii_safe(s):
    """Escape non-ASCII bytes in attacker-controlled strings so the committed file
    stays pure ASCII. A password like a BOM-prefixed insult shows as \\ufeff..., which
    is also more honest than silently reproducing invisible bytes."""
    return s.encode("ascii", "backslashreplace").decode("ascii")


def fmt_top(counter, n):
    """Markdown table rows for the top n entries. Escapes pipes so tables don't break."""
    lines = ["| value | count |", "| --- | --- |"]
    for k, v in counter.most_common(n):
        key = ascii_safe(str(k)).replace("|", "\\|")
        lines.append("| `%s` | %d |" % (key, v))
    if len(lines) == 2:
        lines.append("| (none) | 0 |")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate STATS.md from honeypot logs.")
    parser.add_argument("logdir", nargs="?", default="./logs",
                        help="directory with auth.log, session.log, server.log (default: ./logs)")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    parser.add_argument("--out", default=os.path.join(repo_root, "STATS.md"),
                        help="output Markdown file (default: STATS.md at repo root)")
    parser.add_argument("--mapping", default=os.path.join(repo_root, "family_mapping.json"),
                        help="classification mapping file (default: family_mapping.json at repo root)")
    args = parser.parse_args()

    auth_path    = os.path.join(args.logdir, "auth.log")
    session_path = os.path.join(args.logdir, "session.log")
    server_path  = os.path.join(args.logdir, "server.log")

    passwords  = Counter()
    usernames  = Counter()
    source_ips = Counter()
    pairs      = set()   # distinct (user, password)
    attempts   = 0
    accepted   = 0
    ts_min = ts_max = None   # ISO 8601 sorts lexicographically -- compare raw strings

    def see_ts(ts):
        nonlocal ts_min, ts_max
        if ts_min is None or ts < ts_min:
            ts_min = ts
        if ts_max is None or ts > ts_max:
            ts_max = ts

    # --- auth.log ---
    seen_auth = set()
    dup_auth = 0
    for rec in load_jsonlines(auth_path):
        if rec.get("msg") != "auth attempt":
            continue
        key = (rec.get("time"), rec.get("remote"), rec.get("user"), rec.get("password"))
        if key in seen_auth:
            dup_auth += 1
            continue
        seen_auth.add(key)
        attempts += 1
        pw = rec.get("password", "")
        user = rec.get("user", "")
        remote = rec.get("remote", "")
        ts = rec.get("time")
        if pw:
            passwords[pw] += 1
        if user:
            usernames[user] += 1
        if remote:
            source_ips[strip_port(remote)] += 1
        if pw or user:
            pairs.add((user, pw))
        if ts:
            see_ts(ts)

    # --- session.log ---
    # sid is minted per incoming TCP connection (before the SSH handshake), so distinct
    # sids count connections, including failed handshakes and bare port scans. An
    # established session is a "handshake ok" line. echo-inject spam is ignored here;
    # we key only on sid and a few msg types, so the 14 GB file streams in one pass.
    sids = set()
    handshake_ok      = 0    # msg="handshake ok"      -- SSH session actually established
    scp_files_offered = 0    # msg="scp file"          -- a file the attacker tried to push
    scp_quarantined   = 0    # msg="scp payload saved" -- bytes actually written to disk
    # only the counted msg types need dedup bookkeeping -- sids is a set already and
    # min/max timestamps don't care about repeats, so this stays a few hundred k keys
    # instead of one per event.
    seen_sess = set()
    seen_cmd = set()   # commands are millions -- only tracked on DIRTY_DATES
    commands = 0
    dup_sess = 0
    for rec in load_jsonlines(session_path):
        ts = rec.get("time")
        if ts:
            see_ts(ts)
        sid = rec.get("sid")
        if sid:
            sids.add(sid)
        msg = rec.get("msg", "")

        if msg in ("shell", "exec") and rec.get("command") is not None:
            if ts and ts[:10] in DIRTY_DATES:
                ckey = (sid, ts)
                if ckey in seen_cmd:
                    dup_sess += 1
                    continue
                seen_cmd.add(ckey)
            commands += 1
            continue

        if msg not in ("handshake ok", "scp file", "scp payload saved"):
            continue
        key = (sid, ts, msg)
        if key in seen_sess:
            dup_sess += 1
            continue
        seen_sess.add(key)
        if msg == "handshake ok":
            handshake_ok += 1
        elif msg == "scp file":
            scp_files_offered += 1
        elif msg == "scp payload saved":
            scp_quarantined += 1

    # --- server.log (timestamps only, extends the window over restarts) ---
    for rec in load_jsonlines(server_path):
        ts = rec.get("time")
        if ts:
            see_ts(ts)

    family_count, family_err = count_families(args.mapping)

    duration_hours = None
    if ts_min and ts_max:
        duration_hours = (parse_ts(ts_max) - parse_ts(ts_min)).total_seconds() / 3600.0

    now = datetime.now(timezone.utc)

    out = []
    out.append("# Honeypot statistics")
    out.append("")
    out.append("Generated: %s UTC" % now.strftime("%Y-%m-%d %H:%M:%S"))
    out.append("")
    out.append("This file is generated by `analysis/gen_stats.py` (`make stats`). "
               "Do not edit by hand. It is the single source of truth for the numbers "
               "quoted in README.md and FINDINGS.md.")
    out.append("")

    out.append("## Coverage")
    out.append("")
    if ts_min and ts_max:
        out.append("- First event: %s UTC" % ts_min)
        out.append("- Last event: %s UTC" % ts_max)
        out.append("- Duration: %.0f hours (%.1f days)" % (duration_hours, duration_hours / 24.0))
    else:
        out.append("- (no timestamps found in logs)")
    if dup_auth or dup_sess:
        out.append("- Duplicate records dropped before counting: %d auth, %d session"
                   % (dup_auth, dup_sess))
    out.append("")

    out.append("## Totals")
    out.append("")
    out.append("| metric | value |")
    out.append("| --- | --- |")
    out.append("| Auth attempts | %d |" % attempts)
    out.append("| Unique source IPs | %d |" % len(source_ips))
    out.append("| Connections (TCP, incl. failed handshakes) | %d |" % len(sids))
    out.append("| Sessions (SSH handshake completed) | %d |" % handshake_ok)
    out.append("| Commands captured | %d |" % commands)
    out.append("| Distinct user/password pairs | %d |" % len(pairs))
    out.append("| Unique passwords tried | %d |" % len(passwords))
    out.append("| Unique usernames tried | %d |" % len(usernames))
    if family_count is not None:
        out.append("| Classified attack families | %d |" % family_count)
    else:
        out.append("| Classified attack families | TODO: %s |" % family_err)
    out.append("| Payloads captured (SCP) | %d |" % scp_files_offered)
    out.append("| Payloads quarantined | %d |" % scp_quarantined)
    out.append("")

    out.append("## Top 15 passwords")
    out.append("")
    out.append(fmt_top(passwords, 15))
    out.append("")
    out.append("## Top 15 usernames")
    out.append("")
    out.append(fmt_top(usernames, 15))
    out.append("")
    out.append("## Top 15 source IPs")
    out.append("")
    out.append(fmt_top(source_ips, 15))
    out.append("")

    with open(args.out, "w") as f:
        f.write("\n".join(out) + "\n")

    print("wrote %s" % args.out)
    if dup_auth or dup_sess:
        print("  dropped %d duplicate auth / %d duplicate session records" % (dup_auth, dup_sess))
    print("  attempts=%d ips=%d conns=%d sessions=%d cmds=%d pairs=%d families=%s payloads=%d quarantined=%d"
          % (attempts, len(source_ips), len(sids), handshake_ok, commands, len(pairs),
             family_count if family_count is not None else "TODO",
             scp_files_offered, scp_quarantined))


if __name__ == "__main__":
    main()
