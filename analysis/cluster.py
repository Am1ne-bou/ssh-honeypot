"""
STEP A2: cluster unique_patterns.json into behavioral clusters.
Rules are explicit string-match checks, applied in priority order, first match wins.
Outputs clusters_report.md.

Usage:
  python3 analysis/cluster.py [unique_patterns.json] [--out clusters_report.md]
"""

import json
import sys
from collections import defaultdict


def _any_has(shape, *needles):
    """True if any needle is a substring of any entry in shape."""
    return any(n in cmd for cmd in shape for n in needles)


# ---------------------------------------------------------------------------
# rules -- ordered, first match wins
# each entry: (cluster_id, label, signature_description, match_fn)
# ---------------------------------------------------------------------------

RULES = [
    (
        "C00", "empty-session",
        "shape is empty (no exec or shell commands observed)",
        lambda s: len(s) == 0,
    ),
    (
        "C01", "stdout-hex-beacon",
        "exactly ['echo -e \"<HEX>\"'] -- hex bytes sent to stdout, no file redirect",
        lambda s: s == ['echo -e "<HEX>"'],
    ),
    (
        "C02", "sshchk-probe",
        "SSHCHK_<TOKEN>_BEGIN/END framing present in any command",
        lambda s: _any_has(s, "SSHCHK"),
    ),
    (
        "C03", "hex-file-inject",
        "[HEX_INJECT -> path] entry present (echo hex chunks writing to a file)",
        lambda s: _any_has(s, "[HEX_INJECT ->"),
    ),
    (
        "C04", "writable-dir-probe",
        "'for d in /dev/shm /tmp /var/run...' iteration, or w.sh / astats / watcher-netai",
        lambda s: _any_has(s, "for d in /dev/shm", "w.sh", "astats", "watcher-netai"),
    ),
    (
        "C05", "passwd-changer",
        "reads /etc/passwd AND has a standalone passwd call or chpasswd (not just the cat line)",
        lambda s: _any_has(s, "cat /etc/passwd") and (
            _any_has(s, "chpasswd") or
            any(
                cmd.strip() == "passwd" or cmd.strip().startswith("passwd ")
                for cmd in s if "etc/passwd" not in cmd
            )
        ),
    ),
    (
        "C06", "single-cmd-probe",
        "exactly one command: 'uname -s -m', 'uname -a', or 'hostname' (bare fingerprint probe)",
        lambda s: s in (["uname -s -m"], ["uname -a"], ["hostname"]),
    ),
    (
        "C07", "wget-curl-pipe-sh",
        "wget or curl output piped directly to sh ('| sh' present, fileless exec)",
        lambda s: _any_has(s, "| sh") and _any_has(s, "wget", "curl", "[wget ->", "[curl ->"),
    ),
    (
        "C08", "scp-upload",
        "[scp upload started] or 'scp -t' present (SCP wire protocol, file received)",
        lambda s: _any_has(s, "[scp upload started]", "scp -t"),
    ),
    (
        "C09", "gpu-recon",
        "lspci piped to a GPU-specific grep: '| egrep VGA', '| grep 3D', or '| grep VGA'",
        lambda s: _any_has(s, "lspci | egrep VGA", "lspci | grep 3D", "lspci | grep VGA", "lspci | egrep 3D"),
    ),
    (
        "C11", "meow-dropper",
        "'meow' or 'modzmodz' present",
        lambda s: _any_has(s, "meow", "modzmodz"),
    ),
    (
        "C14", "wowo-binary-dropper",
        "'vipies', 'wowo', or 'runningaway' present (curl-O binary download, not piped to sh)",
        lambda s: _any_has(s, "vipies", "wowo", "runningaway"),
    ),
    (
        "C10", "multi-pkg-scout",
        "'which apt' or 'apt-get' AND 'which yum'/'yum'/'pacman'/'zypper' (multi-distro availability check)",
        lambda s: _any_has(s, "which apt", "apt-get") and _any_has(s, "which yum", "yum ", "pacman", "zypper"),
    ),
    (
        "C15", "tmp-chmod-bash-exec",
        "'chmod +x' and 'bash -c ./' both present (execute previously uploaded binary from /tmp)",
        lambda s: _any_has(s, "chmod +x") and _any_has(s, "bash -c ./"),
    ),
    (
        "C16", "sep-framed-probe",
        "'---SEP---' delimiter used to frame structured multi-field output",
        lambda s: _any_has(s, "---SEP---"),
    ),
]

# ---------------------------------------------------------------------------
# tie-break table -- pairs that look similar, with the distinguishing feature
# ---------------------------------------------------------------------------

TIE_BREAKS = [
    (
        "C06 sub-commands",
        "Three exact commands map to C06 (single-cmd-probe).",
        "'uname -s -m' (arch + kernel name), "
        "'uname -a' (full kernel string), "
        "'hostname' (machine name only). "
        "Distinguish by the exact command if sub-family matters.",
    ),
    (
        "C03 vs C08",
        "Both write a file to disk on the honeypot.",
        "C03: written via echo hex chunks ([HEX_INJECT -> path] in shape, "
        "hundreds or thousands of echo commands). "
        "C08: written via SCP wire protocol ([scp upload started] in shape, "
        "single protocol exchange). "
        "Distinguish by [HEX_INJECT] vs [scp upload started].",
    ),
    (
        "C07 vs C14",
        "Both fetch a remote resource with wget or curl.",
        "C07: fetched bytes are piped to sh ('| sh' in a command, no file saved). "
        "C14: fetched bytes are saved to disk (curl -O, no | sh) and executed separately. "
        "Distinguish by '| sh' absent vs present.",
    ),
    (
        "C01 vs C07",
        "Both have hex content in an echo command.",
        "C01: echo sends hex to stdout only -- no download, no file, no sh. "
        "C07: the wget/curl | sh chain is the main command; echo is a separate beacon step. "
        "Distinguish by 'wget'/'curl'/'| sh' present in C07, absent in C01.",
    ),
    (
        "C08 vs C15",
        "Both relate to executing a binary from /tmp.",
        "C08: the upload session (SCP receive side, [scp upload started]). "
        "C15: the execute session (chmod +x <name> + bash -c ./<name>), "
        "typically a separate connection after the binary is already on disk. "
        "Distinguish by [scp upload started] vs 'bash -c ./'.",
    ),
    (
        "C02 vs C16",
        "Both use a delimiter token to frame structured output.",
        "C02: SSHCHK_<TOKEN>_BEGIN ... END with arithmetic proof-of-work ($((expr))). "
        "C16: '---SEP---' as a plain field separator, no token, no math expression. "
        "Distinguish by 'SSHCHK' vs '---SEP---'.",
    ),
    (
        "C04 vs C10",
        "Both are multi-command system probe sessions.",
        "C04: first or second command is the writable-dir iteration "
        "('for d in /dev/shm /tmp /var/run...'). "
        "C10: commands include apt-get AND yum/pacman/zypper "
        "(multi-distro package manager enumeration). "
        "These do not overlap in practice (C04 is checked first).",
    ),
]


# ---------------------------------------------------------------------------
# report helpers
# ---------------------------------------------------------------------------

def _fmt_shape(shape, n=7):
    if not shape:
        return "  (empty)"
    lines = []
    for i, cmd in enumerate(shape[:n]):
        lines.append("  %d. %s" % (i + 1, cmd[:120]))
    if len(shape) > n:
        lines.append("  ... (%d more entries)" % (len(shape) - n))
    return "\n".join(lines)


def _fmt_raw(raw, n=9):
    if not raw:
        return "  (no commands)"
    lines = []
    for cmd in raw[:n]:
        lines.append("  > %s" % str(cmd)[:140])
    if len(raw) > n:
        lines.append("  ... (%d more)" % (len(raw) - n))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    args     = sys.argv[1:]
    pfile    = "unique_patterns.json"
    out_path = "clusters_report.md"

    if args and not args[0].startswith("--"):
        pfile = args.pop(0)
    if "--out" in args:
        out_path = args[args.index("--out") + 1]

    data = json.load(open(pfile))

    # classify
    buckets = defaultdict(list)
    for p in data:
        shape = p["command_shape"]
        cid   = "TAIL"
        for rule_id, _lbl, _desc, fn in RULES:
            try:
                if fn(shape):
                    cid = rule_id
                    break
            except Exception:
                pass
        buckets[cid].append(p)

    rule_meta = {r[0]: (r[1], r[2]) for r in RULES}
    rule_meta["TAIL"] = ("unmatched", "no rule matched")

    total_sessions = sum(p["session_count"] for p in data)
    total_patterns = len(data)

    W = []
    W.append("# Clusters Report")
    W.append("")
    W.append("Source: `%s` | Patterns: %d | Sessions: %d | Rules: %d" % (
        pfile, total_patterns, total_sessions, len(RULES)))
    W.append("")
    W.append("---")
    W.append("")

    order = [r[0] for r in RULES] + ["TAIL"]

    for cid in order:
        if cid not in buckets:
            continue
        ps    = buckets[cid]
        label, sig_desc = rule_meta[cid]

        n_sessions = sum(p["session_count"] for p in ps)
        pct        = 100.0 * n_sessions / total_sessions

        # sample IPs across all patterns in cluster (deduplicated)
        seen_ips = []
        for p in sorted(ps, key=lambda x: x["session_count"], reverse=True):
            for ip in p["example_ips"]:
                if ip not in seen_ips:
                    seen_ips.append(ip)
                if len(seen_ips) >= 8:
                    break
            if len(seen_ips) >= 8:
                break

        rep = max(ps, key=lambda p: p["session_count"])

        W.append("## %s -- %s" % (cid, label))
        W.append("")
        W.append("**Rule:** %s" % sig_desc)
        W.append("")
        W.append("patterns=%d | sessions=%d (%.1f%%) | IPs (sample): %s" % (
            len(ps), n_sessions, pct, ", ".join(seen_ips[:6])))
        W.append("")

        if len(ps) > 1:
            W.append("**Sub-patterns (%d):**" % len(ps))
            W.append("")
            W.append("```")
            for p in sorted(ps, key=lambda x: x["session_count"], reverse=True):
                preview = str(p["command_shape"][:2]).replace("\n", " ")[:70]
                W.append("%-14s  s=%-5d  ip=%-4d  %s" % (
                    p["fingerprint_id"],
                    p["session_count"],
                    p["ip_count"],
                    preview,
                ))
            W.append("```")
            W.append("")

        W.append("**Representative shape** (`%s`, %d sessions):" % (
            rep["fingerprint_id"], rep["session_count"]))
        W.append("")
        W.append("```")
        W.append(_fmt_shape(rep["command_shape"]))
        W.append("```")
        W.append("")
        W.append("**Example IPs:** %s" % ", ".join(rep["example_ips"][:5]))
        W.append("")
        W.append("**Raw example:**")
        W.append("")
        W.append("```")
        W.append(_fmt_raw(rep["example_raw"]))
        W.append("```")
        W.append("")
        W.append("---")
        W.append("")

    # tie-break section
    W.append("## Tie-break guide -- similar clusters")
    W.append("")
    for pair, similarity, distinction in TIE_BREAKS:
        W.append("### %s" % pair)
        W.append("")
        W.append("Similarity: %s" % similarity)
        W.append("")
        W.append("Distinction: %s" % distinction)
        W.append("")
    W.append("---")
    W.append("")

    with open(out_path, "w") as f:
        f.write("\n".join(W) + "\n")

    # stdout summary
    print("wrote %s" % out_path)
    print()
    print("%-8s  %-24s  %8s  %8s  %6s" % (
        "cluster", "label", "patterns", "sessions", "%"))
    print("-" * 62)
    for cid in order:
        if cid not in buckets:
            continue
        ps    = buckets[cid]
        label = rule_meta[cid][0]
        ns    = sum(p["session_count"] for p in ps)
        pct   = 100.0 * ns / total_sessions
        print("%-8s  %-24s  %8d  %8d  %5.1f%%" % (
            cid, label, len(ps), ns, pct))


if __name__ == "__main__":
    main()
