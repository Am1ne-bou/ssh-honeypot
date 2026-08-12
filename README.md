# ssh-honeypot

![CI](https://github.com/Am1ne-bou/ssh-honeypot/actions/workflows/ci.yml/badge.svg)

Medium-interaction SSH honeypot in Go. Listens on port 22, logs every auth attempt,
accepts attackers into a fake Linux shell, and records everything they do.

Built to sit on a real public VPS and collect attack data -- what credentials bots
try, what recon they run, what payloads they attempt to drop.

Started as low-interaction (just auth logging). Then the first logs came in and I
wanted to capture more -- see what attackers actually do when they think they're on a
real system. Added lspci, nvidia-smi, and started getting GPU miners to run their full
kill chain. Saw the SCP dropper, so I added the quarantine. Eventually got the first real
payload captured: a Raspberry Pi SSH worm, plus binaries from the ELF echo injector.
Looking back, the "low interaction" label no longer fits. The SCP wire protocol, the
stateful virtual FS, working pipes, and arithmetic expansion are all solidly medium.

## findings (1546+ hours, Helsinki VPS)

Full analysis in [FINDINGS.md](FINDINGS.md).

105980 auth attempts from 2397 source IPs. 103192 sessions accepted. 15 attack families identified.
Almost all clients identify as `SSH-2.0-Go` -- mass scanners built on the Go SSH library.

Latest pull (Jul 27): +2915 attempts and sessions in ~180h, this time spread at baseline --
no single-IP mega-spike (unlike Jul 14 and Jul 18). The all-time top sprayers
(`165.227.238.235`, `161.97.166.185`) are carry-over, not new activity; +138 unique IPs.
Commands crossed 9.77M, still 99.5% ELF echo injector (F10). See FINDINGS.md.

Two things worth separating: 87% of attempts target `user=root` and 89% carry the
`SSH-2.0-Go` banner -- this is almost entirely automated Go scanners aimed at root.
And command volume lies -- F10 is 99.5% of *commands* but only 201 sessions, while
**SSHCHK is 57975 sessions (63% of all accepts)** and is the real dominant behavior.
Also live: a coordinated Postgres spray, 57 and 51 distinct IPs hitting the same
`postgres` credential inside an hour -- botnet coordination, not lone scanners.

Top passwords: `admin`, `123456`, `1234`, `\ufeff------fuck------`, `support`, `password`, `e3@HJgr=$4in-a-`, `postgres`, `alpine`.

**1. Credential stuffing** -- wordlist spray, RockYou-based. One IP tried 1545 unique
passwords then kept going 1382 more times after getting in. Also saw a Chinese breach
dataset: dates like `19870825` mixed with romanized names.

**2. Diicot / GPU miner** -- ~180 sessions. Checks GPU via `lspci` and `nvidia-smi`,
locks `authorized_keys` with `chattr -i` (immutable even to root), kills competing
miners. The fake Tesla T4 in the lspci output triggered the full deployment. Payload
fetched from `http://103.160.59.94:28816/CZRmrtxnrNONBXhwfFeqjNfBrliNaShG`, saved
as `~/.sysmonitor`.

**3. SCP dropper** -- tried 11 directories looking for a writable path via `scp -t`.
The honeypot speaks the SCP wire protocol so the bot thought it succeeded.

**4. Password changer** -- changes root password to `chpasswd` to lock out other
attackers. Classic competitive exclusion.

**5. C2 dropper (fileless)** -- `auth_ok` hex beacon + `wget|sh` pipeline from `https://14.46.136.77/sh`. Nothing
written to disk. Runs via SSH exec channel, invisible to shell-based logging.

**6. w.sh / astats persistence bot** -- cron AND systemd user service simultaneously.
Process names (`astats`, `netai`, `kstats`) disguised as monitoring tools.
Dropper fetched from `http://91.239.211.89/init.sh` (tries /tmp, /var/tmp, /dev/shm).

**7. VPS infrastructure scout** -- 35 commands, no payload. Includes a `dd` disk
benchmark to assess mining suitability before deciding to deploy.

**8. SSHCHK liveness checker** -- structured C2 probe with BEGIN/END token framing
and an arithmetic proof-of-work (`echo $((7*191+3))` must return 1340). Confirms
a real shell before sending a payload. 15,106 sessions as of June 21 (~940/day
June 10-15, then plateaued -- only +35 in the six days after).

**9. Minimal OS scanner** -- just `uname -s -m`, disconnects. Pure cataloguing.

**10. ELF echo injector** -- 78 minutes, one SSH connection, 43,058 `echo -e -n`
commands writing four binaries byte by byte when downloads failed. 84 sessions total,
3,299,268 echo chunks, accelerating (~4-6 sessions/day in the June 15-21 window).
session.log is 3.3GB+ largely because of this.

```
amd64  -- 5MB, 64-bit Go, stripped
kal64  -- 3MB, 64-bit Go, stripped
kswpad -- 1.2MB, ELF 32-bit x86
linux  -- 1.3MB, ELF 32-bit x86, UPX packed
```
I still need to properly analyse them - planning to use Ghidra learn it first but when i will have more time.

**11. Meow dropper** -- downloads `meow` (x86-64) and `meowarm64` (ARM64) from C2,
creates two backdoor sudo users (`admin1`, `user1`) with password `modzmodz`, writes
a root credential to `/tmp/mew`. Entire kill chain in one exec command. 113 sessions,
three C2 IPs now (34.11.111.237, 35.237.91.38, 34.181.210.37). Also injects an SSH key
via `http://197.255.229.88:1987/kon` and fetches a secondary payload from
`http://197.255.229.88:1987/fav.ico` using a curl/wget/python/perl/tcp fallback chain.
Binary analysis pending.

**12. Wowo dropper** -- downloads and executes `runningaway.x86` from
`http://wowo.biz.id/wowiloveyou/runningaway.x86`, passes a campaign tag (`vipies`) as
argument, self-deletes, wipes history. Preceded by a full 35-command infrastructure recon.
Haven't analysed the binary yet.

**13. Raspberry Pi SSH worm (gJw27HGL)** -- first payload actually captured by the
quarantine. A 4.7KB bash script, not a binary. Kills competing malware, injects an SSH
backdoor key, changes the `pi` user password, then spawns an IRC bot that connects to
Undernet and waits for RSA-signed commands. Spreads itself by scanning 100k IPs with
zmap and trying `pi:raspberry` and `pi:raspberry993311`. Still active: 5 captures total
(Jun 2, 6, 8, 9, 14), same hash every time. I read the source but I still need to
understand the IRC C2 side properly -- that's next.

**14. Architecture capability prober** -- SCP-drops two test ELF binaries (x86-64 and x86
32-bit, both "Hello, world!" assembly, 512B and 348B), executes each, deletes them. Uses
`top -bn1` first to snapshot running processes. The test binaries are handcrafted minimal
ELFs -- just enough to confirm execution works before the real payload arrives. Client was
SSH-2.0-OpenSSH_9.9 (only real OpenSSH in the dataset). One session June 12, source IP
185.129.62.63. Real payload never came. Quarantine hashes: e374a7ad (512B), f74a8b06 (348B).

**15. SSH liveness/capability probe** -- `echo -e "\x6F\x6B"` (decodes to "ok"), standalone
single command, no recon, no follow-up observed. 14954 sessions (66.3% of all sessions),
3 source IPs, 98.9% from one IP (103.105.67.170). Zero cross-cluster overlap -- never
combined with any other named family. Likely confirming exec-channel works before making
a decision externally. Plan: improve bait response and add follow-up detection to see if
that IP ever returns after the beacon.

---

## architecture

```
attacker --> TCP :22 --> iptables REDIRECT --> :2222 --> honeypot process
                                                         |
                                             /var/lib/honeypot/logs/
                                               auth.log     (every auth attempt)
                                               session.log  (commands, exec, SCP)
                                               server.log   (startup, config)

operator --> TCP :VPS_PORT --> real OpenSSH
```

Three JSON log files, one event per line:

- `auth.log` -- every login attempt: IP, user, password, client banner, attempt number, outcome
- `session.log` -- handshakes, channel requests, commands (both interactive shell and SSH exec)
- `server.log` -- startup with config snapshot (auth_threshold, addr), errors

## auth behavior

Configurable via `-auth-threshold N` (default 1 -- accept immediately).

With `N=1` every bot gets a shell on the first attempt. With `N=10` the server
harvests up to 9 passwords per IP before accepting. The attempt counter accumulates
across connections keyed by source IP (not IP:port) since bots open a fresh TCP
connection per guess.

The threshold and a timestamp are logged at startup in `server.log`, which the
period analysis tool uses to compare behavior across deployments.

## build

```bash
make build
```

Produces a static Linux binary. Needs Go 1.22+. Cross-compiles from any OS.

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ssh-honeypot .
```

## deploy

Move real sshd to a non-standard port first. In `/etc/ssh/sshd_config`:

```
Port VPS_PORT
```

Restart sshd, **verify you can still connect on VPS_PORT before doing anything else.**

Redirect port 22 to the honeypot:

```bash
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
iptables-save > /etc/iptables/rules.v4
```

Service user and directories:

```bash
useradd -r -s /sbin/nologin -d /var/lib/honeypot honeypot
mkdir -p /var/lib/honeypot/logs /var/lib/honeypot/quarantine
chown -R honeypot:honeypot /var/lib/honeypot
```

Copy binary and systemd unit:

```bash
scp -P <port> -i ~/.ssh/your_key ssh-honeypot user@VPS:/tmp/ssh-honeypot
ssh -p <port> -i ~/.ssh/your_key user@VPS \
  "sudo install -m 755 /tmp/ssh-honeypot /usr/local/bin/ssh-honeypot && \
   sudo systemctl restart ssh-honeypot"
```

Verify the new binary is running (look for `auth_threshold` in the listening line):

```bash
ssh -p <port> -i ~/.ssh/your_key user@VPS \
  "cat /var/lib/honeypot/logs/server.log | tail -3"
```

## flags

```
-addr            listen address                    (default :2222)
-host-key        ed25519 host key file             (default ./host.key)
-log-dir         log file directory                (default ./logs)
-quarantine-dir  payload capture directory         (default "" = disabled)
-max-conn        concurrent connection cap         (default 100)
-auth-threshold  accept after N attempts per IP    (default 1)
```

The host key is generated on first run and reused across restarts. A key that changes
on every restart is a fingerprinting tell -- scanners notice.

## logs

`auth.log` entry:

```json
{"time":"2026-05-27T05:03:14Z","level":"INFO","msg":"auth attempt","method":"password","user":"root","password":"123456","remote":"35.200.201.144:54321","client":"SSH-2.0-Go","attempt":1,"outcome":"accepted"}
```

`session.log` has two types of command entries:

```json
{"time":"2026-05-27T05:03:14Z","level":"INFO","msg":"shell","sid":"dc727dd9b3","command":"uname -s -v -n -r -m"}
{"time":"2026-05-29T10:24:55Z","level":"INFO","msg":"exec","sid":"5d9fcafd","command":"uname -a; echo -e \"\\x61\\x75\\x74\\x68\\x5F\\x6F\\x6B\\x0A\"; (wget ... | sh -s ssh)"}
```

`msg=shell` is an interactive shell command. `msg=exec` is a one-shot SSH exec (no PTY).
Most automated bots use exec -- analysis scripts must count both.

`server.log` startup entry:

```json
{"time":"2026-05-29T06:15:23Z","level":"INFO","msg":"listening","addr":":2222","auth_threshold":1}
```

## analysis

Pull logs from VPS:

```bash
mkdir -p ~/honeypot-logs/$(date +%Y-%m-%d)
scp -P <port> -i ~/.ssh/your_key \
  "user@VPS:/var/lib/honeypot/logs/*.log" \
  ~/honeypot-logs/$(date +%Y-%m-%d)/
```

Run all scripts at once:

```bash
./analyze.sh ~/honeypot-logs/2026-05-29
```

Produces five files: `result-HHMM--DD-MM-{report,full-stats,session,timeline,periods}.txt`.

Individual scripts:

```bash
python3 analysis/report.py   ./logs  # heatmap, top passwords, session narratives, alerts
python3 analysis/stats.py    ./logs  # raw counts + full password list
python3 analysis/sessions.py ./logs  # per-session event timeline
python3 analysis/timeline.py ./logs  # first/last-seen per command and password
python3 analysis/periods.py  ./logs  # compare periods across server restarts / threshold changes
```

`periods.py` reads `server.log` for restart timestamps and `auth_threshold` values,
slices auth and session logs by period, and prints a side-by-side comparison. Useful
for measuring the effect of config changes (e.g. threshold=10 vs threshold=1).

## fake shell

Handles ~80 registered commands: `whoami`, `id`, `uname`, `ls`, `cat`, `ps`,
`ifconfig`, `nvidia-smi`, `curl`, `wget`, `sudo`, and more. Returns plausible output
for Ubuntu 24.04 with a Tesla T4 GPU and 8 CPU cores.

Supported shell features:

- Pipes: `nvidia-smi -q | grep "Product Name" | wc -l` returns `1`
- `&&` chaining: stops on first non-zero exit
- `> /dev/null` redirect stripping
- `$VAR` / `${VAR}` expansion
- Per-session virtual filesystem: `mkdir /tmp/x` then `ls /tmp` shows it
- SCP receive: speaks wire protocol, acks uploads, writes to session FS

With `--quarantine-dir` set, SCP payloads are saved as `<sha256>-<name>.bin`
(read-only, 50 MB cap per file).

Known limitations:

- no `$(cmd)` substitution
- network commands return canned output, no real traffic sent
- `> file` writes (other than `/dev/null`) not implemented
