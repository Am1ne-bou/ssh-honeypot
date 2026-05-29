#!/usr/bin/env python3
"""
periods.py -- compare honeypot metrics across server restarts / config changes

reads server.log "listening" events to detect period boundaries,
then slices auth.log and session.log and compares key stats per period.

usage: python3 analysis/periods.py <log-dir>
       python3 analysis/periods.py <log-dir> --no-color
"""
import sys
import json
import os
from datetime import datetime, timezone
from collections import Counter, defaultdict

NO_COLOR = "--no-color" in sys.argv or not sys.stdout.isatty()

def _c(code, s):
    if NO_COLOR:
        return s
    return f"\033[{code}m{s}\033[0m"

def red(s):    return _c("91", s)
def yellow(s): return _c("93", s)
def green(s):  return _c("92", s)
def cyan(s):   return _c("96", s)
def dim(s):    return _c("2",  s)
def bold(s):   return _c("1",  s)

def parse_ts(s):
    # fromisoformat doesn't handle the nanosecond precision Go emits,
    # truncate to microseconds
    s = s[:26] + s[s.rfind("+"):]  if "+" in s[10:] else s[:26] + "Z"
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None

def load_jsonl(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out

def get_ts(e):
    return parse_ts(e.get("time", "")) if "time" in e else None

# ---- period detection --------------------------------------------------------

def detect_periods(server_events):
    """
    return list of dicts:
      start: datetime
      end:   datetime or None (open, still running)
      threshold: int or None (not logged yet, old server version)
    """
    starts = []
    for e in server_events:
        if e.get("msg") != "listening":
            continue
        ts = get_ts(e)
        if ts is None:
            continue
        starts.append({
            "start": ts,
            "threshold": e.get("auth_threshold"),  # None for old log entries
        })

    starts.sort(key=lambda x: x["start"])

    periods = []
    for i, s in enumerate(starts):
        end = starts[i + 1]["start"] if i + 1 < len(starts) else None
        periods.append({
            "start": s["start"],
            "end": end,
            "threshold": s["threshold"],
        })
    return periods

def slice_events(events, start, end):
    out = []
    for e in events:
        ts = get_ts(e)
        if ts is None:
            continue
        if ts < start:
            continue
        if end is not None and ts >= end:
            continue
        out.append(e)
    return out

# ---- metrics -----------------------------------------------------------------

PHASES = {
    "uname": "RECON", "id": "RECON", "whoami": "RECON", "hostname": "RECON",
    "nproc": "RECON", "lspci": "RECON", "lscpu": "RECON", "free": "RECON",
    "df": "RECON", "ps": "RECON", "cat": "RECON", "ls": "RECON",
    "find": "RECON", "nvidia-smi": "RECON", "ifconfig": "RECON", "ip": "RECON",
    "netstat": "RECON", "env": "RECON",
    "mkdir": "STAGE", "touch": "STAGE", "cd": "STAGE", "cp": "STAGE", "mv": "STAGE",
    "scp": "UPLOAD", "curl": "UPLOAD", "wget": "UPLOAD", "nc": "UPLOAD",
    "chmod": "EXEC", "bash": "EXEC", "sh": "EXEC",
    "crontab": "PERSIST", "systemctl": "PERSIST", "chpasswd": "PERSIST",
    "useradd": "PERSIST", "usermod": "PERSIST",
    "killall": "CLEANUP", "kill": "CLEANUP", "pkill": "CLEANUP", "chattr": "CLEANUP",
}

def classify(cmd):
    cmd = cmd.strip()
    if cmd.startswith("sudo "):
        cmd = cmd[5:].strip()
    first = cmd.split()[0] if cmd else ""
    if first.startswith("./") or (first.startswith("/") and "/" in first[1:]):
        return "EXEC"
    return PHASES.get(first, "OTHER")

def compute_stats(auth, sess):
    attempts  = [e for e in auth if e.get("msg") == "auth attempt"]
    accepted  = [e for e in attempts if e.get("outcome") == "accepted"]
    unique_ips = len({e.get("remote", ":").split(":")[0] for e in attempts})
    passwords  = Counter(e["password"] for e in attempts if "password" in e)
    commands   = [e.get("command", "") for e in sess
                  if e.get("msg") in ("shell", "exec") and "command" in e]
    cmd_counter = Counter(c.split()[0] if c.strip() else "" for c in commands if c.strip())
    phase_counts = Counter(classify(c) for c in commands)

    by_ip = defaultdict(int)
    for e in attempts:
        ip = e.get("remote", ":").split(":")[0]
        by_ip[ip] += 1
    single_shot = sum(1 for n in by_ip.values() if n == 1)

    return {
        "attempts":   len(attempts),
        "accepted":   len(accepted),
        "unique_ips": unique_ips,
        "single_shot": single_shot,
        "commands":   len(commands),
        "passwords":  passwords,
        "top_cmds":   cmd_counter,
        "phases":     phase_counts,
    }

# ---- rendering ---------------------------------------------------------------

def fmt_delta(before, after, label, higher_is="bad"):
    if before == 0 and after == 0:
        return dim(f"  {label}: 0 -> 0")
    delta = after - before
    pct   = (delta / before * 100) if before else float("inf")
    sign  = "+" if delta >= 0 else ""
    num   = f"{sign}{delta} ({sign}{pct:.0f}%)" if before else f"{sign}{delta}"
    if delta == 0:
        color = dim
    elif higher_is == "bad":
        color = red if delta > 0 else green
    else:
        color = green if delta > 0 else red
    return color(f"  {label}: {before} -> {after}  {num}")

def render_period(idx, p, stats):
    start_s = p["start"].strftime("%Y-%m-%d %H:%M UTC")
    end_s   = p["end"].strftime("%Y-%m-%d %H:%M UTC") if p["end"] else "now"
    thresh  = str(p["threshold"]) if p["threshold"] is not None else "?"
    dur     = ""
    if p["end"]:
        h = (p["end"] - p["start"]).total_seconds() / 3600
        dur = f"  ({h:.1f}h)"

    print(bold(cyan(f"\nPERIOD {idx + 1}  threshold={thresh}")))
    print(dim(f"  {start_s}  ->  {end_s}{dur}"))
    print()
    print(f"  auth attempts : {bold(str(stats['attempts']))}")
    print(f"  unique IPs    : {bold(str(stats['unique_ips']))}")
    print(f"  single-shot   : {bold(str(stats['single_shot']))}  {dim('(IPs that tried exactly once)')}")
    print(f"  accepted      : {bold(str(stats['accepted']))}")
    print(f"  commands      : {bold(str(stats['commands']))}")

    if stats["phases"]:
        phase_str = "  ".join(f"{ph}={n}" for ph, n in stats["phases"].most_common())
        print(f"  kill-chain    : {dim(phase_str)}")

    if stats["passwords"]:
        top_pw = stats["passwords"].most_common(5)
        print(f"  top passwords : ", end="")
        print("  ".join(f"{pw!r}({n})" for pw, n in top_pw))

    if stats["top_cmds"]:
        top_c = stats["top_cmds"].most_common(5)
        print(f"  top commands  : ", end="")
        print("  ".join(f"{c}({n})" for c, n in top_c))

def render_comparison(p_before, s_before, p_after, s_after):
    thresh_b = str(p_before["threshold"]) if p_before["threshold"] is not None else "?"
    thresh_a = str(p_after["threshold"])  if p_after["threshold"]  is not None else "?"
    print(bold(f"\nDELTA  (period threshold={thresh_b}  ->  threshold={thresh_a})"))
    print(fmt_delta(s_before["attempts"],   s_after["attempts"],   "attempts",   higher_is="neutral"))
    print(fmt_delta(s_before["unique_ips"], s_after["unique_ips"], "unique IPs", higher_is="neutral"))
    print(fmt_delta(s_before["single_shot"],s_after["single_shot"],"single-shot",higher_is="neutral"))
    print(fmt_delta(s_before["accepted"],   s_after["accepted"],   "accepted",   higher_is="good"))
    print(fmt_delta(s_before["commands"],   s_after["commands"],   "commands",   higher_is="good"))

# ---- main --------------------------------------------------------------------

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("usage: python3 analysis/periods.py <log-dir>", file=sys.stderr)
        sys.exit(1)

    log_dir = args[0]
    srv_events  = load_jsonl(os.path.join(log_dir, "server.log"))
    auth_events = load_jsonl(os.path.join(log_dir, "auth.log"))
    sess_events = load_jsonl(os.path.join(log_dir, "session.log"))

    periods = detect_periods(srv_events)
    if not periods:
        print("no 'listening' events found in server.log -- nothing to split", file=sys.stderr)
        sys.exit(1)

    print(bold(cyan(f"\n{'=' * 60}")))
    print(bold(cyan("  SSH HONEYPOT -- PERIOD COMPARISON")))
    print(bold(cyan(f"{'=' * 60}")))
    print(f"  {len(periods)} period(s) detected from server.log\n")

    all_stats = []
    for i, p in enumerate(periods):
        auth = slice_events(auth_events, p["start"], p["end"])
        sess = slice_events(sess_events, p["start"], p["end"])
        stats = compute_stats(auth, sess)
        all_stats.append(stats)
        render_period(i, p, stats)

    if len(periods) > 1:
        print(bold(cyan(f"\n{'=' * 60}")))
        for i in range(len(periods) - 1):
            render_comparison(periods[i], all_stats[i], periods[i+1], all_stats[i+1])
        print()

if __name__ == "__main__":
    main()
