# ssh-honeypot

![CI](https://github.com/Am1ne-bou/ssh-honeypot/actions/workflows/ci.yml/badge.svg)

Low-interaction SSH honeypot in Go. Listens on port 22, rejects the first 9
password attempts per IP (logging each one), then accepts the 10th and drops
the attacker into a fake shell. Every command they type is logged as JSON.

Built to sit on a real public VPS and collect attack data -- what credentials
bots try, what recon commands they run once they think they're in.

## findings (first 6 hours, Helsinki VPS)

541 auth attempts from 10 source IPs. Top passwords: `123456`, `123`, `1`, `1234`.
Almost all clients identify as `SSH-2.0-Go` -- mass scanners written in Go running
credential lists in parallel.

Once a bot got a shell, the most common command sequence was:

```
uname -s -v -n -r -m
nproc
lspci | egrep VGA && lspci | grep 3D
uname -m
```

That last line -- `lspci | grep 3D` -- is checking for a GPU. This is a crypto miner
looking for hardware worth deploying on. The bot fingerprints the machine (OS, kernel,
CPU count, GPU presence) and either drops a miner or moves on. It ran this exact
script 11 times in the session.

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

The honeypot deliberately rejects the first 9 password attempts from each IP,
then accepts the 10th. This harvests more credentials per attacker before
letting them through, and makes the server look slightly harder to get into.

Most bots open a fresh TCP connection per guess, so the attempt counter
accumulates across connections keyed by source IP (not IP:port).

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
mkdir -p /var/lib/honeypot/logs
chown -R honeypot:honeypot /var/lib/honeypot
```

Copy binary and systemd unit, then:

```bash
systemctl enable --now ssh-honeypot
```

## flags

```
-addr           listen address          (default :2222)
-host-key       ed25519 host key file   (default ./host.key)
-log-dir        log file directory      (default ./logs)
-quarantine-dir payload capture dir     (default "" = disabled)
-max-conn       concurrent connection cap (default 100)
```

The host key is generated on first run and reused across restarts. Keeping it
stable matters -- scanners fingerprint servers by host key, a key that changes
every restart is an obvious tell.

## logs

Example auth.log entry:

```json
{"time":"2026-05-26T12:24:53Z","level":"INFO","msg":"auth attempt","method":"password","user":"root","password":"123456","remote":"185.220.101.47:54321","client":"SSH-2.0-Go","attempt":7,"outcome":"rejected"}
```

Example session.log entry (command captured):

```json
{"time":"2026-05-26T11:38:03Z","level":"INFO","msg":"shell","sid":"25a1bd545ce9","command":"cat /etc/passwd"}
```

## analysis

```bash
# per-session timeline: what each attacker did, in order
python3 analysis/sessions.py /var/lib/honeypot/logs | less

# first/last-seen per password and command; flags credential feedback loops
python3 analysis/timeline.py /var/lib/honeypot/logs
```

Both scripts are stdlib only. They read the JSON log files and correlate events
by `sid` (session ID). Run them locally by copying the logs off the VPS first,
or directly on the VPS if you've uploaded the scripts there.

## fake shell

The fake shell handles the most common recon commands: `whoami`, `id`, `uname`,
`ls`, `cat`, `ps`, `ifconfig`, `curl`, `wget`, `sudo`, and ~40 others.
It returns plausible canned output for a generic Ubuntu server.

Pipes work left-to-right (`nvidia-smi -q | grep "Product Name" | wc -l` returns `1`).
Filesystem state is per-session: `mkdir /tmp/x` then `ls /tmp` shows it. SCP uploads
land in the session FS too -- if the bot does `chmod +x /tmp/payload` after uploading,
that shows up in session.log.

If `--quarantine-dir` is set, uploaded payloads are written to disk as
`<sha256>-<name>.bin` (read-only, 50 MB cap).

Known limitations:

- no `$(cmd)` substitution, only `$VAR` expansion
- network commands return canned output, no real traffic sent

Bots run scripts without checking if commands actually worked, so this is
fine for capturing the playbook.
