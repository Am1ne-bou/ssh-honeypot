# ssh-honeypot

![CI](https://github.com/Am1ne-bou/ssh-honeypot/actions/workflows/ci.yml/badge.svg)

Low-interaction SSH honeypot in Go. Listens on a port, rejects the first 9 password
attempts per IP (logging each one), then accepts the 10th and drops the attacker into
a fake Linux shell. Every command they type is logged as JSON.

Built to sit on a real public VPS and collect attack data -- what credentials bots try,
what recon commands they run once they think they're in.

## findings (55 hours, Helsinki VPS)

2949 auth attempts from 131 source IPs. Almost all clients identify as `SSH-2.0-Go` --
mass scanners written in Go. Top passwords: `123456`, `admin`, `password`, `1234`.

Two distinct bot families observed once they got a shell:

**Diicot / crypto miner recon** -- runs this exact sequence every session:

```
uname -s -v -n -r -m
nproc
lspci | egrep VGA && lspci | grep 3D
uname -m
```

Fingerprinting OS, CPU count, and GPU. The `lspci | grep 3D` line checks for a GPU
worth mining on. The fake shell returns a Tesla T4 and 8 cores -- good bait.

**Dropper bot** -- after getting a shell, tries to stage a payload directory then upload:

```
mkdir /lib/<random10chars>
scp -t -r /lib/<random10chars>/
```

Repeats with different paths (`/dev/`, `/dev/shm/`, `/var/volatile/`). Looking for a
writable directory. `scp -t` in this context is the attacker's machine trying to push
a file to us -- we speak the SCP wire protocol server-side so the bot thinks it worked.

**Credential feedback loop** confirmed: 71.227.179.172 made 1382 attempts after first
shell accept. Bots that get in add the working password to their spray list and keep
hammering. The `chpasswd` command shows up in session logs when they try to lock down
the account.

---

## architecture

```
attacker --> TCP :22 --> iptables REDIRECT --> :2222 --> honeypot process
                                                         |
                                             /var/lib/honeypot/logs/
                                               auth.log
                                               session.log
                                               server.log

operator --> TCP :VPS_PORT --> real OpenSSH
```

Three JSON log files, one event per line:

- `auth.log` -- every login attempt: IP, user, password, client banner, attempt number, outcome
- `session.log` -- handshakes, channel requests, commands typed in the fake shell
- `server.log` -- startup, errors, rejected connections

## auth behavior

Rejects the first 9 password attempts from each IP, accepts the 10th. This harvests
more credentials per attacker before letting them through and makes the server look
slightly harder to crack.

Most bots open a fresh TCP connection per guess, so the attempt counter accumulates
across connections keyed by source IP (not IP:port).

## build

```bash
make build
```

Produces a static Linux binary. Needs Go 1.22+. Cross-compiles from any OS.

Or manually:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o ssh-honeypot .
```

## deploy

Move real sshd to a non-standard port first. In `/etc/ssh/sshd_config`:

```
Port VPS_PORT
```

Restart sshd, **open a new session and verify you can still connect on VPS_PORT
before doing anything else.**

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

Copy binary and systemd unit, then:

```bash
systemctl enable --now ssh-honeypot
```

## flags

```
-addr           listen address              (default :2222)
-host-key       ed25519 host key file       (default ./host.key)
-log-dir        log file directory          (default ./logs)
-quarantine-dir payload capture directory   (default "" = disabled)
-max-conn       concurrent connection cap   (default 100)
```

The host key is generated on first run and reused across restarts. Keeping it stable
matters -- scanners fingerprint servers by host key, a key that changes every restart
is an obvious tell.

## logs

Example `auth.log` entry:

```json
{"time":"2026-05-26T12:24:53Z","level":"INFO","msg":"auth attempt","method":"password","user":"root","password":"123456","remote":"185.220.101.47:54321","client":"SSH-2.0-Go","attempt":7,"outcome":"rejected"}
```

Example `session.log` entry:

```json
{"time":"2026-05-26T11:38:03Z","level":"INFO","msg":"shell","sid":"25a1bd545ce9","command":"cat /etc/passwd"}
```

## analysis

Copy logs off the VPS first:

```bash
scp -r user@vps:/var/lib/honeypot/logs ./honeypot-logs/$(date +%Y-%m-%d)
```

Run all analysis scripts at once:

```bash
./analyze.sh ./honeypot-logs/2026-05-28
```

Produces four files: `result-HHMM--DD-MM-report.txt`, `-full-stats.txt`, `-session.txt`,
`-timeline.txt`.

Or run individual scripts:

```bash
python3 analysis/report.py ./logs          # rich terminal report with heatmap + bot families
python3 analysis/stats.py --full ./logs    # raw counts + full password list
python3 analysis/sessions.py ./logs        # per-session event timeline
python3 analysis/timeline.py ./logs        # first/last-seen, credential feedback loop
```

All scripts are stdlib only.

## fake shell

Handles the most common attacker commands: `whoami`, `id`, `uname`, `ls`, `cat`,
`ps`, `ifconfig`, `curl`, `wget`, `sudo`, and ~50 others. Returns plausible output
for a generic Ubuntu 24.04 server with a Tesla T4 GPU.

Supported shell features:

- Pipes: `nvidia-smi -q | grep "Product Name" | wc -l` returns `1`
- `&&` chaining: `lspci | egrep VGA && lspci | grep 3D` works correctly
- `> /dev/null` redirect stripping
- `$VAR` and `${VAR}` expansion
- Per-session virtual filesystem: `mkdir /tmp/x` then `ls /tmp` shows it

SCP uploads land in the session FS. If a bot does `chmod +x /tmp/payload` after
uploading, that appears in `session.log`. With `--quarantine-dir` set, the raw
payload bytes are saved as `<sha256>-<name>.bin` (read-only, 50 MB cap).

Known limitations:

- no `$(cmd)` substitution
- network commands return canned output, no real traffic sent
- `> file` writes (other than `/dev/null`) not implemented
