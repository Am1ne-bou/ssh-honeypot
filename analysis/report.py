#!/usr/bin/env python3
"""
report.py -- rich terminal attack report from honeypot JSON logs

usage: python3 analysis/report.py <log-dir>
       python3 analysis/report.py <log-dir> --no-color
"""
import sys
import json
import os
from datetime import datetime, timezone
from collections import defaultdict, Counter

# ---- color ---------------------------------------------------------------

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

# ---- kill-chain classification -------------------------------------------

# first word of a command -> phase
PHASES = {
    # discovery
    "uname": "RECON",  "id": "RECON",      "whoami": "RECON",
    "hostname": "RECON", "nproc": "RECON", "lspci": "RECON",
    "lscpu": "RECON",  "free": "RECON",    "df": "RECON",
    "ps": "RECON",     "top": "RECON",     "cat": "RECON",
    "ls": "RECON",     "find": "RECON",    "nvidia-smi": "RECON",
    "ifconfig": "RECON", "ip": "RECON",    "netstat": "RECON",
    "env": "RECON",    "printenv": "RECON",
    # staging
    "mkdir": "STAGE",  "touch": "STAGE",   "cd": "STAGE",
    "cp": "STAGE",     "mv": "STAGE",
    # upload / download
    "scp": "UPLOAD",   "curl": "UPLOAD",   "wget": "UPLOAD",
    "tftp": "UPLOAD",  "nc": "UPLOAD",     "python": "UPLOAD",
    # execution
    "chmod": "EXEC",   "bash": "EXEC",     "sh": "EXEC",
    "./": "EXEC",
    # persistence
    "crontab": "PERSIST", "systemctl": "PERSIST", "chpasswd": "PERSIST",
    "useradd": "PERSIST", "usermod": "PERSIST",
    # anti-forensics / cleanup
    "killall": "CLEANUP", "kill": "CLEANUP", "pkill": "CLEANUP",
    "chattr": "CLEANUP",  "history": "CLEANUP",
}

PHASE_COLOR = {
    "RECON":   cyan,
    "STAGE":   yellow,
    "UPLOAD":  red,
    "EXEC":    red,
    "PERSIST": red,
    "CLEANUP": yellow,
    "OTHER":   dim,
}

def classify(cmd):
    cmd = cmd.strip()
    if cmd.startswith("sudo "):
        cmd = cmd[5:].strip()
    first = cmd.split()[0] if cmd else ""
    # bare ./ or /path/to/binary -> execution
    if first.startswith("./") or (first.startswith("/") and "/" in first[1:]):
        return "EXEC"
    return PHASES.get(first, "OTHER")

# ---- bot family fingerprinting -------------------------------------------

def fingerprint_bot(commands, banner):
    """Return a short label for the bot family based on observed behavior."""
    cmds = " ".join(commands)
    has_lspci   = "lspci" in cmds
    has_nproc   = "nproc" in cmds
    has_scp_t   = "scp" in cmds and "-t" in cmds
    has_mining  = any(x in cmds for x in ("xmrig", "minerd", "stratum", "monero"))
    has_curl    = "curl" in cmds or "wget" in cmds
    has_lib_dir = "/lib/" in cmds and "mkdir" in cmds

    if has_lspci and has_nproc and (has_scp_t or has_lib_dir):
        return red("Diicot / crypto-miner dropper")
    if has_scp_t or has_lib_dir:
        return red("dropper (unknown family)")
    if has_curl or has_mining:
        return red("downloader")
    if has_lspci or has_nproc:
        return yellow("miner recon")
    if "SSH-2.0-Go" in banner:
        return dim("Go scanner (credential stuffing only)")
    return dim("generic scanner")

# ---- session narrative ---------------------------------------------------

def narrate(commands):
    """One sentence describing what the bot did in this session."""
    phases = [classify(c) for c in commands]
    phase_set = set(phases)

    parts = []
    if "RECON" in phase_set:
        # what did it look for?
        recon_cmds = [c for c, p in zip(commands, phases) if p == "RECON"]
        targets = []
        if any("lspci" in c or "nvidia" in c for c in recon_cmds):
            targets.append("GPU")
        if any("nproc" in c for c in recon_cmds):
            targets.append("CPU cores")
        if any("uname" in c for c in recon_cmds):
            targets.append("OS/kernel")
        if any("/etc/passwd" in c for c in recon_cmds):
            targets.append("user list")
        parts.append("fingerprinted " + (", ".join(targets) if targets else "system"))

    if "STAGE" in phase_set:
        stage_cmds = [c for c, p in zip(commands, phases) if p == "STAGE"]
        dirs = [c.split()[-1] for c in stage_cmds if c.strip().startswith("mkdir")]
        if dirs:
            parts.append(f"created staging dir(s): {', '.join(dirs[:2])}")
        else:
            parts.append("staged directories")

    if "UPLOAD" in phase_set:
        up_cmds = [c for c, p in zip(commands, phases) if p == "UPLOAD"]
        methods = set(c.split()[0].lstrip("sudo ") for c in up_cmds)
        n = sum(1 for c in commands if "scp" in c and "-t" in c)
        if n:
            parts.append(f"tried SCP upload {n}x")
        else:
            parts.append(f"fetched payload via {', '.join(methods)}")

    if "EXEC" in phase_set:
        parts.append("executed payload")
    if "PERSIST" in phase_set:
        parts.append("attempted persistence")
    if "CLEANUP" in phase_set:
        parts.append("killed competing processes")

    if not parts:
        return dim("no significant commands")
    parts[0] = parts[0][0].upper() + parts[0][1:]
    return ". ".join(parts) + "."

# ---- parsing -------------------------------------------------------------

def load(log_dir):
    auth, sess = [], []
    for fname, target in [("auth.log", auth), ("session.log", sess)]:
        path = os.path.join(log_dir, fname)
        if not os.path.exists(path):
            continue
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    target.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return auth, sess

# ---- renderers -----------------------------------------------------------

SEP = dim("-" * 60)

def render_header(auth, sess):
    attempts = sum(1 for e in auth if e.get("msg") == "auth attempt")
    accepted = sum(1 for e in auth if e.get("outcome") == "accepted")
    ips      = len({e["remote"].split(":")[0] for e in auth
                    if e.get("msg") == "auth attempt" and "remote" in e})
    commands = sum(1 for e in sess if e.get("msg") in ("shell", "exec") and "command" in e)

    times = []
    for e in auth:
        try:
            times.append(datetime.fromisoformat(e["time"].replace("Z", "+00:00")))
        except Exception:
            pass

    if times:
        t0 = min(times).strftime("%Y-%m-%d %H:%M UTC")
        t1 = max(times).strftime("%Y-%m-%d %H:%M UTC")
        hours = (max(times) - min(times)).total_seconds() / 3600
        span = f"{t0}  ->  {t1}  ({hours:.1f}h)"
    else:
        span = "no timestamps"

    W = 62
    print()
    print(bold(cyan("=" * W)))
    print(bold(cyan("  SSH HONEYPOT -- ATTACK REPORT")))
    print(bold(cyan("=" * W)))
    print(f"  {dim(span)}")
    print()
    cols = [
        (str(attempts), "auth attempts"),
        (str(ips),      "source IPs"),
        (str(accepted), "sessions accepted"),
        (str(commands), "commands captured"),
    ]
    for val, label in cols:
        color = green if label == "sessions accepted" and accepted else bold
        print(f"  {color(val):>10}  {label}")
    print()
    print(bold(cyan("=" * W)))
    print()


def render_heatmap(auth):
    by_hour = Counter()
    for e in auth:
        if e.get("msg") != "auth attempt":
            continue
        try:
            t = datetime.fromisoformat(e["time"].replace("Z", "+00:00"))
            by_hour[t.hour] += 1
        except Exception:
            pass
    if not by_hour:
        return

    peak = max(by_hour.values())
    print(bold("HOURLY ACTIVITY") + dim("  (UTC, auth attempts)"))
    print()
    for h in range(24):
        n = by_hour.get(h, 0)
        filled = int(n / peak * 38) if peak else 0
        bar = red("#" * filled) + dim("." * (38 - filled))
        print(f"  {h:02d}  {bar}  {n}")
    print()


def render_ips(auth, sess):
    attempts_by_ip  = Counter()
    accepted_by_ip  = Counter()
    passwords_by_ip = defaultdict(set)
    banners_by_ip   = defaultdict(set)

    for e in auth:
        if e.get("msg") != "auth attempt":
            continue
        ip = e.get("remote", ":").split(":")[0]
        attempts_by_ip[ip] += 1
        if e.get("outcome") == "accepted":
            accepted_by_ip[ip] += 1
        if "password" in e:
            passwords_by_ip[ip].add(e["password"])
        if "client" in e:
            banners_by_ip[ip].add(e["client"])

    scp_count = Counter()
    for e in sess:
        cmd = e.get("command", "")
        if e.get("msg") in ("shell", "exec") and "scp" in cmd and "-t" in cmd:
            scp_count[e.get("sid", "")] += 1
    dropper_sids = {sid for sid, n in scp_count.items() if n > 0}

    print(bold("SOURCE IPs"))
    print()
    for ip in sorted(attempts_by_ip, key=lambda x: -attempts_by_ip[x]):
        n        = attempts_by_ip[ip]
        accepted = accepted_by_ip[ip]
        uniq_pw  = len(passwords_by_ip[ip])
        banner   = next(iter(banners_by_ip[ip]), "unknown")

        tags = []
        if accepted:
            tags.append(green("ACCEPTED"))
        if uniq_pw > 30:
            tags.append(yellow(f"WORDLIST({uniq_pw})"))
        tag_str = ("  " + "  ".join(tags)) if tags else ""

        print(f"  {bold(ip):<20}  {n:>4} attempts  {uniq_pw:>3} pw  {dim(banner[:30])}{tag_str}")
    print()


def render_credentials(auth):
    passwords = Counter()
    for e in auth:
        if e.get("msg") == "auth attempt" and "password" in e:
            passwords[e["password"]] += 1
    if not passwords:
        return

    peak = passwords.most_common(1)[0][1]
    print(bold("TOP PASSWORDS"))
    print()
    for pw, n in passwords.most_common(12):
        filled = int(n / peak * 28) if peak else 0
        bar = yellow("#" * filled) + dim("." * (28 - filled))
        print(f"  {bar}  {n:>4}x  {pw!r}")
    print()

    # sequential numeric patterns (123 -> 1234 -> 12345)
    numeric = sorted((p for p in passwords if p.isdigit()), key=lambda x: (len(x), x))
    seen, chains = set(), []
    for i, p in enumerate(numeric):
        if p in seen:
            continue
        chain = [p]
        cur = p
        for q in numeric[i+1:]:
            if q.startswith(cur) and len(q) == len(cur) + 1:
                chain.append(q)
                cur = q
        if len(chain) >= 3:
            chains.append(chain)
            seen.update(chain)
    if chains:
        print(f"  {yellow('!')} sequential pattern detected:")
        for ch in chains[:3]:
            print(f"    {dim(' -> ').join(ch)}")
        print()


def render_sessions(auth, sess):
    # group shell events by sid
    by_sid = defaultdict(list)
    for e in sess:
        if e.get("msg") in ("shell", "exec") and "command" in e:
            by_sid[e["sid"]].append(e)

    # find accepted auth events (keyed by time; no sid in auth.log)
    # use session.log "channel" events to get remote if available
    remote_by_sid = {}
    for e in sess:
        if "remote" in e and "sid" in e:
            remote_by_sid[e["sid"]] = e["remote"].split(":")[0]

    accepted_ips = defaultdict(list)  # ip -> list of (time, sid)
    for e in auth:
        if e.get("outcome") == "accepted":
            ip = e.get("remote", ":").split(":")[0]
            accepted_ips[ip].append(e.get("time", ""))

    all_sids = sorted(by_sid.keys())
    if not all_sids:
        print(bold("ACCEPTED SESSIONS"))
        print(f"  {dim('no commands recorded yet')}")
        print()
        return

    print(bold(f"ACCEPTED SESSIONS  ({len(all_sids)} with commands)"))
    print()

    for sid in all_sids:
        events  = by_sid[sid]
        cmds    = [e["command"] for e in events]
        when    = events[0].get("time", "?")[:19].replace("T", " ")
        ip      = remote_by_sid.get(sid, "?")

        phases  = [classify(c) for c in cmds]
        has_scp = any("scp" in c and "-t" in c for c in cmds)

        banner_guess = ""
        family = fingerprint_bot(cmds, banner_guess)
        story  = narrate(cmds)

        flag = f"  {red('[DROPPER]')}" if has_scp else ""
        print(f"  {cyan(sid[:12])}  {bold(ip) if ip != '?' else dim('ip unknown')}  {dim(when)}{flag}")
        print(f"  {dim('family:')} {family}")
        print(f"  {dim('story:')}  {story}")
        print()

        prev_phase = None
        for cmd, phase in zip(cmds, phases):
            color = PHASE_COLOR.get(phase, dim)
            if phase != prev_phase:
                print(f"    {color(f'[{phase}]')}")
                prev_phase = phase
            short = cmd if len(cmd) <= 64 else cmd[:61] + "..."
            print(f"    {dim('|')} {color(short)}")
        print()


def render_alerts(auth, sess):
    lines = []

    # SCP upload attempts
    scp_sids = {e["sid"] for e in sess
                if e.get("msg") in ("shell", "exec")
                and "scp" in e.get("command", "")
                and "-t" in e.get("command", "")}
    if scp_sids:
        lines.append(red(f"! payload upload via SCP in {len(scp_sids)} session(s) "
                         f"-- check quarantine dir for captured files"))

    # credential feedback loop: IP keeps trying after first accept
    by_ip = defaultdict(list)
    for e in auth:
        if e.get("msg") == "auth attempt":
            ip = e.get("remote", ":").split(":")[0]
            by_ip[ip].append(e)
    for ip, events in by_ip.items():
        accepted_times = sorted(e["time"] for e in events if e.get("outcome") == "accepted")
        if not accepted_times:
            continue
        after = sum(1 for e in events
                    if e.get("outcome") == "rejected" and e.get("time", "") > accepted_times[0])
        if after >= 5:
            lines.append(yellow(f"! credential feedback loop: {ip} made {after} attempts "
                                f"after first shell accept"))

    # volume spike
    attempt_count = Counter(e.get("remote", ":").split(":")[0] for e in auth
                            if e.get("msg") == "auth attempt")
    for ip, n in attempt_count.items():
        if n > 300:
            lines.append(yellow(f"! high volume: {ip} -> {n} attempts (distributed spray?)"))

    # next kill-chain phase prediction
    all_cmds = [e.get("command", "") for e in sess if e.get("msg") in ("shell", "exec")]
    all_phases = set(classify(c) for c in all_cmds)
    if "UPLOAD" in all_phases and "EXEC" not in all_phases:
        lines.append(cyan("-> watch for: EXEC phase (chmod +x / ./payload)"))
    elif "RECON" in all_phases and "STAGE" not in all_phases:
        lines.append(cyan("-> watch for: STAGE phase (mkdir /lib/randomdir)"))
    if "EXEC" in all_phases and "PERSIST" not in all_phases:
        lines.append(cyan("-> watch for: PERSIST phase (crontab / systemctl)"))

    if not lines:
        lines.append(green("no critical alerts"))

    print(bold("ALERTS"))
    print()
    for line in lines:
        print(f"  {line}")
    print()


# ---- main ----------------------------------------------------------------

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print("usage: python3 analysis/report.py <log-dir>", file=sys.stderr)
        sys.exit(1)

    log_dir = args[0]
    auth, sess = load(log_dir)

    if not auth and not sess:
        print(f"no log events found in {log_dir!r}", file=sys.stderr)
        sys.exit(1)

    render_header(auth, sess)
    render_heatmap(auth)
    render_ips(auth, sess)
    render_credentials(auth)
    render_sessions(auth, sess)
    render_alerts(auth, sess)


if __name__ == "__main__":
    main()
