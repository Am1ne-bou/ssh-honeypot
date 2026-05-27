"""
Per-session timeline reconstruction. Groups all log events by session ID (sid)
and renders a Markdown report with one section per session.

Usage: python3 analysis/sessions.py [log_dir]
  log_dir defaults to ./logs if not given.

Output is Markdown -- pipe to a file or a renderer.
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


def short_ts(ts):
    """Trim ISO timestamp to HH:MM:SS for compact display."""
    if not ts:
        return "?"
    # "2026-05-27T19:03:12.345Z" -> "19:03:12"
    try:
        return ts[11:19]
    except Exception:
        return ts


def main():
    logdir = sys.argv[1] if len(sys.argv) > 1 else "./logs"
    auth_path    = os.path.join(logdir, "auth.log")
    session_path = os.path.join(logdir, "session.log")

    # sid -> list of (timestamp, type, data-dict)
    events = defaultdict(list)

    # auth.log: accepted attempts carry the sid in the "user" field context
    # session.log: all events carry sid
    for rec in load_jsonlines(auth_path):
        sid = rec.get("sid", "")
        ts  = rec.get("time", "")
        if rec.get("msg") == "auth attempt":
            events[sid].append((ts, "auth", rec))

    for rec in load_jsonlines(session_path):
        sid = rec.get("sid", "")
        ts  = rec.get("time", "")
        msg = rec.get("msg", "")
        if msg in ("handshake ok", "handshake failed", "channel request",
                   "shell", "exec", "scp receive", "scp file", "scp payload saved",
                   "scp data drained"):
            events[sid].append((ts, msg, rec))

    if not events:
        print("No sessions found in %s" % logdir, file=sys.stderr)
        sys.exit(1)

    # sort each session's events by timestamp
    for sid in events:
        events[sid].sort(key=lambda x: x[0])

    # sort sessions by their first event timestamp
    sessions = sorted(events.items(), key=lambda kv: kv[1][0][0] if kv[1] else "")

    print("# Session timelines")
    print()
    print("Log dir: `%s`  |  Sessions: %d" % (os.path.abspath(logdir), len(sessions)))
    print()

    for sid, evs in sessions:
        if not evs:
            continue

        # pull metadata from first handshake-ok or auth event
        remote = "?"
        user   = "?"
        banner = "?"
        outcome_accepted = False
        for _, typ, rec in evs:
            if typ == "auth" and rec.get("outcome") == "accepted":
                outcome_accepted = True
                remote = rec.get("remote", remote)
                user   = rec.get("user", user)
                banner = rec.get("client", banner)
                break
            if typ == "auth":
                remote = rec.get("remote", remote)
                user   = rec.get("user", user)
                banner = rec.get("client", banner)
            if typ == "handshake ok":
                remote = rec.get("remote", remote)
                user   = rec.get("user", user)
                banner = rec.get("client", banner)

        start = evs[0][0]
        end   = evs[-1][0]
        mark  = "[ACCEPTED]" if outcome_accepted else "[rejected]"

        print("---")
        print()
        print("## Session `%s`  %s" % (sid, mark))
        print()
        print("- **From:** `%s`" % remote)
        print("- **User:** `%s`  **Banner:** `%s`" % (user, banner))
        print("- **Start:** %s  **End:** %s" % (start, end))
        print()
        print("| Time | Event | Detail |")
        print("|------|-------|--------|")

        # collect passwords tried (for accepted sessions -- shows credential reuse)
        passwords = []
        for _, typ, rec in evs:
            if typ == "auth":
                pw = rec.get("password", "")
                outcome = rec.get("outcome", "")
                if pw:
                    passwords.append((pw, outcome))

        for ts, typ, rec in evs:
            t = short_ts(ts)
            if typ == "auth":
                pw = rec.get("password", "")
                n  = rec.get("attempt", "")
                out = rec.get("outcome", "")
                print("| %s | auth #%s | `%s` -> %s |" % (t, n, pw, out))
            elif typ == "handshake ok":
                print("| %s | connected | `%s` |" % (t, rec.get("client", "")))
            elif typ in ("shell", "exec"):
                cmd = rec.get("command", "").strip()
                # truncate long commands so the table stays readable
                if len(cmd) > 80:
                    cmd = cmd[:77] + "..."
                print("| %s | %s | `%s` |" % (t, typ, cmd.replace("|", "\\|")))
            elif typ == "scp file":
                name = rec.get("name", "")
                size = rec.get("size", "")
                print("| %s | scp upload | `%s` (%s bytes) |" % (t, name, size))
            elif typ == "scp payload saved":
                h = rec.get("sha256", "")
                print("| %s | quarantined | sha256=`%s` |" % (t, h[:16] + "..."))
            else:
                print("| %s | %s | |" % (t, typ))

        print()


if __name__ == "__main__":
    main()
