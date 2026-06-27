# C01 Decision Brief

Source: 22551-session dataset, ~/honeypot-logs/2026-06-26.merged/session.log
Excludes: 737e03e52dba, 2d1b80adfb0f, e30b8bd4ff98, 84e0a852afa6, 0c4e580eeda1

---

## 1. Byte sequence confirmation

The raw command across ALL 14954 C01 sessions is:

  echo -e "\x6F\x6B"

Hex payload: \x6F\x6B = ASCII "ok" (0x6F = 'o', 0x6B = 'k').
Distinct payloads observed: 1 (no variation).
The sequence is identical across all sessions and all 3 source IPs.

---

## 2. Top 15 source IPs by session count

C01 has only 3 source IPs total. All 3 listed below.

  rank  IP                sessions   pct of C01
  ----  ----------------  --------   ----------
     1  103.105.67.170      14793       98.9%
     2  71.227.179.172        154        1.0%
     3  103.64.129.98           7        0.0%

Total: 14954 sessions from 3 IPs.

---

## 3. Cross-cluster overlap for those 3 IPs

For each of the 3 C01 IPs: does the same IP appear in any other named cluster?

  103.105.67.170 -- C01 only. Not seen in C02 through C16 or TAIL.
  71.227.179.172 -- C01 only. Not seen in C02 through C16 or TAIL.
  103.64.129.98  -- C01 only. Not seen in C02 through C16 or TAIL.

None of the 3 C01 IPs appear in any other cluster.

---

## 4. C01-only IPs vs overlap IPs

  C01-only IPs (never in any other cluster):  3  (100%)
  IPs that also appear in another cluster:    0  (0%)
  Total C01 IPs:                              3

---

## 5. C01 vs C02 structural distinction

C02 (SSHCHK, F8) -- 2 sessions, 1 IP (45.154.244.133):
  Command: echo SSHCHK_<TOKEN>_BEGIN; uname -srm; echo $((7*191+3)); hostname;
           df -P / 2>/dev/null | awk ...; echo SSHCHK_<TOKEN>_END
  Structure: BEGIN/END framing, arithmetic proof-of-work, system recon chain, 1 compound command.

C01 (ok-beacon) -- 14954 sessions, 3 IPs:
  Command: echo -e "\x6F\x6B"
  Structure: single standalone echo, no framing, no token, no math, no recon.

IP overlap between C01 and C02: none (45.154.244.133 never appears in C01).
C01 is not a truncated version of C02. The two commands share no structural features.
C01 could be an authentication-confirmation beacon (the server echoes "ok" after accepting
the connection) or a client-side probe verifying that exec channels work on the honeypot.
The 3-IP concentration (one IP holds 98.9% of sessions) suggests a single scanner campaign,
not a distributed tool.

---

## Raw numbers for reference

  C01 session count:     14954  (66.3% of full dataset)
  C01 distinct IPs:          3
  Byte sequence variants:    1  (\x6F\x6B only)
  Cross-cluster IP overlap:  0
  C02 session count:         2  (structurally unrelated)
