"""
STEP A1: compute command-shape fingerprints for all sessions.
Groups near-identical sessions, outputs unique_patterns.json.

Usage:
  python3 analysis/fingerprint.py <log_dir> [--out unique_patterns.json]
"""

import hashlib
import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from replay import load_jsonlines, is_echo_inject, echo_target

# is_echo_inject from replay.py only checks echo+flags+quote structure, not
# hex content -- it would misclassify "echo -e 'SSHCHK_...'" as hex injection.
# Require at least one \xNN byte to avoid that.
_HEX_BYTE = re.compile(r'\\x[0-9a-fA-F]{2}')

def _is_hex_inject(cmd):
    # require >>, not just hex content -- stdout echo beacons ("ok", "auth_ok") are not file injection
    return is_echo_inject(cmd) and bool(_HEX_BYTE.search(cmd)) and ">>" in cmd

KEEP_MSGS = {
    "handshake ok", "shell", "exec",
    "wget fetch", "curl fetch",
    "scp receive", "scp file", "scp payload saved",
}

# IP:port in any string
_IP_RE     = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
# 2+ consecutive \xNN hex escapes (catches short beacons like \x6f\x6b "ok")
_HEX_RE    = re.compile(r'(\\x[0-9a-fA-F]{2}){2,}')
# 40+ chars of base64 alphabet (catches long random tokens and hashes)
_B64_RE    = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
# random-looking name inside common temp dirs
_RAND_PATH = re.compile(
    r'((?:/tmp|/lib|/dev/shm|/var/run|/mnt|/root|/etc|/var/lib)/)[a-zA-Z0-9]{8,}'
)
# SSHCHK session token
_SSHCHK_RE = re.compile(r'SSHCHK_[0-9a-f]+_(BEGIN|END)')
# bare 8+ char alphanumeric (used for SCP C-header filenames)
_RAND_NAME = re.compile(r'^[a-zA-Z0-9]{8,}$')


def _norm_url(url):
    url = url.rstrip(')')           # strip trailing ) from (wget ... || curl ...) grouping
    url = _IP_RE.sub('<IP>', url)
    url = re.sub(r'<IP>:\d{1,5}', '<IP>:<PORT>', url)
    url = _B64_RE.sub('<PAYLOAD>', url)
    return url


def _norm_cmd(cmd):
    cmd = _SSHCHK_RE.sub(r'SSHCHK_<TOKEN>_\1', cmd)
    cmd = _HEX_RE.sub('<HEX>', cmd)
    cmd = _IP_RE.sub('<IP>', cmd)
    cmd = re.sub(r'<IP>:\d{1,5}', '<IP>:<PORT>', cmd)
    cmd = _RAND_PATH.sub(r'\1<RAND>', cmd)
    cmd = _B64_RE.sub('<PAYLOAD>', cmd)
    return cmd


def _shape_and_raw(evs):
    """
    Return (normalized shape list, raw command list).
    Echo injection runs are folded into a single shape entry (chunk count
    excluded from the shape so sessions with the same binary but different
    injection lengths still get the same fingerprint).
    Raw list is capped at 60 entries.
    """
    shape = []
    raw   = []

    i = 0
    while i < len(evs):
        _, msg, rec = evs[i]

        if msg in ("shell", "exec"):
            cmd = rec.get("command", "").strip()

            if _is_hex_inject(cmd):
                # collect the whole run targeting the same file
                target = echo_target(cmd)
                run = [cmd]
                j = i + 1
                while j < len(evs):
                    _, msg2, rec2 = evs[j]
                    if msg2 in ("shell", "exec"):
                        c2 = rec2.get("command", "").strip()
                        if _is_hex_inject(c2) and echo_target(c2) == target:
                            run.append(c2)
                            j += 1
                            continue
                    break

                norm_target = _RAND_PATH.sub(r'\1<RAND>', target)
                shape.append("[HEX_INJECT -> %s]" % norm_target)
                if len(raw) < 60:
                    raw.append("[... %d echo chunks -> %s]" % (len(run), target))
                i = j
                continue

            shape.append(_norm_cmd(cmd))
            if len(raw) < 60:
                raw.append(cmd)

        elif msg == "wget fetch":
            url = rec.get("url", "?")
            shape.append("[wget -> %s]" % _norm_url(url))
            if len(raw) < 60:
                raw.append("[wget -> %s]" % url)

        elif msg == "curl fetch":
            url = rec.get("url", "?")
            shape.append("[curl -> %s]" % _norm_url(url))
            if len(raw) < 60:
                raw.append("[curl -> %s]" % url)

        elif msg == "scp receive":
            shape.append("[scp upload started]")
            if len(raw) < 60:
                raw.append("[scp upload started]")

        elif msg == "scp file":
            fname = rec.get("name", "?")
            norm  = "<RAND>" if _RAND_NAME.match(fname) else fname
            shape.append("[scp file: %s]" % norm)
            if len(raw) < 60:
                raw.append("[scp file: %s  %s bytes]" % (fname, rec.get("size", "?")))

        elif msg == "scp payload saved":
            shape.append("[quarantined]")
            if len(raw) < 60:
                raw.append("[quarantined: sha256=%s]" % rec.get("sha256", "?"))

        i += 1

    # collapse consecutive identical shape entries (retry loops: "cat > astats" x3)
    deduped = []
    for entry in shape:
        if not deduped or deduped[-1] != entry:
            deduped.append(entry)

    return deduped, raw


def _session_ip(evs):
    for _, msg, rec in evs:
        if msg == "handshake ok":
            return rec.get("remote", "?").split(":")[0]
    return "?"


def _fid(shape):
    return hashlib.sha256(
        json.dumps(shape, separators=(",", ":")).encode()
    ).hexdigest()[:12]


def _build_sessions(log_dir):
    events = defaultdict(list)
    for rec in load_jsonlines(os.path.join(log_dir, "session.log")):
        msg = rec.get("msg", "")
        if msg not in KEEP_MSGS:
            continue
        sid = rec.get("sid", "")[:12]
        events[sid].append((rec.get("time", ""), msg, rec))
    for sid in events:
        events[sid].sort(key=lambda x: x[0])
    return events


def main():
    args = sys.argv[1:]
    if not args:
        print("usage: fingerprint.py <log_dir> [--out <file>]", file=sys.stderr)
        sys.exit(1)

    log_dir  = args[0]
    out_path = "unique_patterns.json"
    if "--out" in args:
        out_path = args[args.index("--out") + 1]

    print("loading sessions from %s ..." % log_dir, file=sys.stderr)
    sessions = _build_sessions(log_dir)
    total = len(sessions)
    print("  %d sessions" % total, file=sys.stderr)

    groups = defaultdict(lambda: {
        "sids": [], "ips": [], "shape": None, "example_raw": None
    })

    for sid, evs in sessions.items():
        shape, raw = _shape_and_raw(evs)
        fid = _fid(shape)
        ip  = _session_ip(evs)
        g   = groups[fid]
        g["sids"].append(sid)
        g["ips"].append(ip)
        if g["shape"] is None:
            g["shape"]       = shape
            g["example_raw"] = raw

    sorted_groups = sorted(
        groups.items(),
        key=lambda kv: len(kv[1]["sids"]),
        reverse=True,
    )

    patterns = [
        {
            "fingerprint_id": fid,
            "session_count":  len(g["sids"]),
            "ip_count":       len(set(g["ips"])),
            "command_shape":  g["shape"],
            "example_raw":    g["example_raw"],
            "example_ips":    list(dict.fromkeys(g["ips"]))[:5],
        }
        for fid, g in sorted_groups
    ]

    with open(out_path, "w") as f:
        json.dump(patterns, f, indent=2)

    n_patterns = len(patterns)
    print("wrote %d patterns -> %s" % (n_patterns, out_path), file=sys.stderr)

    print()
    print("SUMMARY")
    print("  sessions in     : %d" % total)
    print("  unique patterns : %d" % n_patterns)
    print("  collapse ratio  : %.1fx" % (total / max(n_patterns, 1)))
    print()
    print("TOP 20 patterns (by session_count):")
    print("  %-14s  %8s  %5s  %s" % ("fingerprint_id", "sessions", "IPs", "shape[:3]"))
    print("  " + "-" * 76)
    for p in patterns[:20]:
        preview = str(p["command_shape"][:3]).replace("\n", " ")[:62]
        print("  %-14s  %8d  %5d  %s" % (
            p["fingerprint_id"],
            p["session_count"],
            p["ip_count"],
            preview,
        ))


if __name__ == "__main__":
    main()
