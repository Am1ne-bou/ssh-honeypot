"""
Phase B classification engine: session -> cluster -> family assignment.

Reads family_mapping.json (cluster->family table, finalized) and raw sessions.
Emits families.json with per-IP family assignments and full rule traceability.

Does NOT reimplement any rule logic -- imports RULES from cluster.py and
session loading from fingerprint.py. Does not execute, decode, or run any
captured command or payload; inert string checks only.

Usage:
  python3 analysis/classify.py <log_dir> \
      [--mapping family_mapping.json] \
      [--out families.json]
"""

import datetime
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from cluster import RULES
from fingerprint import _build_sessions, _fid, _session_ip, _shape_and_raw


# ---------------------------------------------------------------------------
# mapping loader
# ---------------------------------------------------------------------------

def _load_mapping(path):
    """
    Returns (by_cluster, c08_fid_family, exclude_sids).
    by_cluster: cluster_id -> full entry dict from family_mapping.json
    c08_fid_family: fingerprint_id -> family_id for C08 sub-splits
    exclude_sids: set of session ids to drop before classification
    """
    with open(path) as f:
        entries = json.load(f)

    by_cluster = {}
    c08_fid_family = {}
    exclude_sids = set()

    for e in entries:
        cid = e["cluster_id"]
        by_cluster[cid] = e
        if e.get("exclude_sids"):
            exclude_sids.update(e["exclude_sids"])
        if cid == "C08" and e.get("sub_splits"):
            for split in e["sub_splits"]:
                c08_fid_family[split["fingerprint_id"]] = split["family_id"]

    return by_cluster, c08_fid_family, exclude_sids


# ---------------------------------------------------------------------------
# classification helpers
# ---------------------------------------------------------------------------

def _apply_rules(shape):
    """Run cluster.py RULES in order, first match wins. Returns (cluster_id, rule_desc)."""
    for cid, _label, desc, match_fn in RULES:
        if match_fn(shape):
            return cid, desc
    return "TAIL", "no rule matched"


def _c09_stage(cmds):
    """
    Tag F2/Diicot session stage from raw command strings (inert substring check).
    Returns one of: recon_only / recon_kill / recon_kill_execute
    """
    has_chattr = any("chattr" in c for c in cmds)
    has_chmod_exec = (
        any("chmod" in c and ("+x" in c or "777" in c) for c in cmds)
        and (any(c.endswith("&") or " &" in c for c in cmds) or has_chattr)
    )
    if has_chattr or has_chmod_exec:
        return "recon_kill_execute"
    has_kill = any(
        any(k in c for k in ("pkill", "killall"))
        and any(t in c for t in ("xmrig", "cnrig", "java"))
        for c in cmds
    )
    return "recon_kill" if has_kill else "recon_only"


def _classify(shape, cmds, fingerprint, by_cluster, c08_fid_family):
    """
    Returns (cluster_id, rule_desc, family_ids, stage).

    family_ids is a list -- usually [fam], but ["F7","F12"] for C14 dual-tag.
    stage is a string for C09/F2 only, else None.
    Unresolvable cases return (cid, rule_desc, [], None).
    """
    cid, rule_desc = _apply_rules(shape)

    # C08: family depends on fingerprint_id, not cluster_id alone
    if cid == "C08":
        fam = c08_fid_family.get(fingerprint)
        if fam is None:
            # should not happen after EXCLUDE_SIDS filtering; log and skip
            print(
                "  WARN: C08 fingerprint %s not in sub_splits -- marking unclassified" % fingerprint,
                file=sys.stderr,
            )
        return cid, rule_desc, [fam] if fam else [], None

    # C14: dual-tagged F7+F12, do not force one label
    if cid == "C14":
        return cid, rule_desc, ["F7", "F12"], None

    # C09: carry stage tag alongside family_id
    if cid == "C09":
        stage = _c09_stage(cmds)
        fam = by_cluster.get(cid, {}).get("family_id")
        return cid, rule_desc, [fam] if fam else [], stage

    fam = by_cluster.get(cid, {}).get("family_id")
    return cid, rule_desc, [fam] if fam else [], None


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]
    if not args:
        print(
            "usage: classify.py <log_dir> [--mapping family_mapping.json] [--out families.json]",
            file=sys.stderr,
        )
        sys.exit(1)

    log_dir = args[0]
    mapping_path = "family_mapping.json"
    out_path = "families.json"
    if "--mapping" in args:
        mapping_path = args[args.index("--mapping") + 1]
    if "--out" in args:
        out_path = args[args.index("--out") + 1]

    # -- load --
    print("loading mapping from %s ..." % mapping_path, file=sys.stderr)
    by_cluster, c08_fid_family, exclude_sids = _load_mapping(mapping_path)

    print("loading sessions from %s ..." % log_dir, file=sys.stderr)
    sessions = _build_sessions(log_dir)
    print("  %d sessions total" % len(sessions), file=sys.stderr)

    # -- classify --
    # ip -> {sessions: [...], families: set()}
    ip_data = defaultdict(lambda: {"sessions": [], "families": set()})

    for sid, evs in sessions.items():
        if sid in exclude_sids:
            continue

        shape, _raw = _shape_and_raw(evs)
        fingerprint = _fid(shape)
        cmds = [r.get("command", "") for _, msg, r in evs if msg in ("shell", "exec")]
        ip = _session_ip(evs)

        cid, rule_desc, family_ids, stage = _classify(
            shape, cmds, fingerprint, by_cluster, c08_fid_family
        )

        ip_data[ip]["sessions"].append({
            "sid": sid,
            "cluster_id": cid,
            "rule": rule_desc,
            "families": family_ids,
            "stage": stage,
        })
        for fam in family_ids:
            ip_data[ip]["families"].add(fam)

    # -- aggregate to family level --
    fam_ip_entries = defaultdict(list)   # family_id -> [{ip, session_count, clusters, rule}]
    fam_sess_count = defaultdict(int)    # family_id -> session count
    f2_stages = {"recon_only": 0, "recon_kill": 0, "recon_kill_execute": 0}

    multi_family_ips = {}
    unclassified_ips = []

    for ip, data in sorted(ip_data.items()):
        families = data["families"]
        sess_list = data["sessions"]

        if len(families) > 1:
            multi_family_ips[ip] = sorted(families)

        if not families:
            unclassified_ips.append(ip)
            continue

        clusters_seen = sorted(set(s["cluster_id"] for s in sess_list))
        # primary rule: first session that resolved to a family
        primary_rule = next(s["rule"] for s in sess_list if s["families"])

        for fam in families:
            ip_entry = {
                "ip": ip,
                "session_count": len(sess_list),
                "clusters": clusters_seen,
                "rule": primary_rule,
            }
            if fam == "F2":
                # per-session stage tags so individual IPs are auditable in Phase C
                ip_entry["stage_sessions"] = [
                    {"sid": s["sid"], "stage": s["stage"]}
                    for s in sess_list
                    if s["stage"] is not None
                ]
            fam_ip_entries[fam].append(ip_entry)

        for sess in sess_list:
            for fam in sess["families"]:
                fam_sess_count[fam] += 1
            if sess["stage"] and sess["stage"] in f2_stages:
                f2_stages[sess["stage"]] += 1

    # -- sanity checks before writing --
    families_built = {
        fam: {
            "ip_count": len(fam_ip_entries[fam]),
            "session_count": fam_sess_count[fam],
        }
        for fam in fam_ip_entries
    }
    errors = []
    f15 = families_built.get("F15", {})
    f1 = families_built.get("F1", {})
    if f15.get("ip_count") != 3:
        errors.append("F15 ip_count=%d, expected 3" % f15.get("ip_count", 0))
    if f15.get("session_count") != 14954:
        errors.append("F15 session_count=%d, expected 14954" % f15.get("session_count", 0))
    f1_ip = f1.get("ip_count", 0)
    if not (1028 <= f1_ip <= 1032):
        errors.append("F1 ip_count=%d, expected ~1030 -- lookup may be broken" % f1_ip)
    if errors:
        print("\nSANITY CHECK FAILED -- not writing output:", file=sys.stderr)
        for e in errors:
            print("  " + e, file=sys.stderr)
        sys.exit(1)

    # -- build output --
    all_fams = sorted(fam_ip_entries.keys(), key=lambda x: int(x[1:]))

    families_out = {}
    for fam in all_fams:
        entry = {
            "ip_count": len(fam_ip_entries[fam]),
            "session_count": fam_sess_count[fam],
            "ips": sorted(fam_ip_entries[fam], key=lambda x: -x["session_count"]),
        }
        if fam == "F2":
            entry["stage_breakdown"] = dict(f2_stages)
        families_out[fam] = entry

    total_ips = len(ip_data)
    total_sessions = sum(len(d["sessions"]) for d in ip_data.values())

    out = {
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "excluded_sids": sorted(exclude_sids),
        "total_ips_classified": total_ips,
        "families": families_out,
        "multi_family_ips": {ip: v for ip, v in sorted(multi_family_ips.items())},
        "unclassified": {
            "ip_count": len(unclassified_ips),
            "ips": sorted(unclassified_ips),
        },
    }

    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    # -- summary to stdout --
    print()
    print("CLASSIFICATION SUMMARY")
    print("=" * 52)
    print("  excluded_sids        : %d  (expected 5)" % len(exclude_sids))
    print("  sessions (post-excl) : %d" % total_sessions)
    print("  IPs total            : %d" % total_ips)
    print("  multi-family IPs     : %d" % len(multi_family_ips))
    print("  unclassified IPs     : %d" % len(unclassified_ips))
    print()
    print("  %-6s  %8s  %14s  %7s" % ("family", "ip_count", "session_count", "% sess"))
    print("  " + "-" * 48)
    for fam in all_fams:
        d = families_out[fam]
        pct = 100.0 * d["session_count"] / total_sessions if total_sessions else 0.0
        print("  %-6s  %8d  %14d  %6.1f%%" % (
            fam, d["ip_count"], d["session_count"], pct,
        ))
        if fam == "F2":
            sb = d["stage_breakdown"]
            print("           recon_only=%(recon_only)d  recon_kill=%(recon_kill)d"
                  "  recon_kill_execute=%(recon_kill_execute)d" % sb)
    print()
    if multi_family_ips:
        print("  multi-family IPs:")
        for ip, fams in sorted(multi_family_ips.items()):
            print("    %s -> %s" % (ip, fams))
        print()
    print("wrote %s" % out_path)


if __name__ == "__main__":
    main()
