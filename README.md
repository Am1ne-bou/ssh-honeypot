# ssh-honeypot

Low-interaction SSH honeypot in Go. Accepts any password, drops attackers into
a fake shell, logs everything as JSON. Built to sit on a public VPS port 22
and collect attack data.

## build

`make build` -- produces a static linux binary. Needs Go 1.21+. The Makefile
sets `CGO_ENABLED=0 GOOS=linux` so you can cross-compile from anywhere.

## deploy

Move real sshd to a different port first (`Port VPS_PORT` in
`/etc/ssh/sshd_config`), restart, **open a new terminal and verify you can
still ssh on the new port** before doing anything else.

Then redirect 22 -> 2222 in iptables:

```
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
iptables-save > /etc/iptables/rules.v4
```

Service user + dirs:

```
useradd -r -s /sbin/nologin -d /var/lib/honeypot honeypot
mkdir -p /var/lib/honeypot/logs
chown -R honeypot:honeypot /var/lib/honeypot
```

Copy binary + systemd unit, `systemctl enable --now ssh-honeypot`.

## flags

```
-addr      listen address (default :2222)
-host-key  ed25519 host key file (default ./host.key)
-log-dir   log file directory (default ./logs)
-max-conn  concurrent connection cap (default 100)
```

Host key is generated on first run and reused after. Keeping it stable matters
because scanners fingerprint by host key -- a key that changes every restart
is a tell.

## logs

Three JSON files in `-log-dir`:

- `auth.log` -- every login attempt (user, password, remote IP, client banner)
- `session.log` -- handshakes, channel requests, commands typed in the fake shell
- `server.log` -- startup, accept errors, rejected connections

example:

```
{"time":"...","level":"INFO","msg":"auth attempt","method":"password","user":"root","password":"123456","remote":"185.220.101.47:54321","client":"SSH-2.0-libssh_0.9.6","outcome":"accepted"}
```

## limitations

Fake shell. Don't expect it to fool a person.

- pipes not interpreted (`ls | grep x` -- the LHS runs, pipe is in the log)
- no `$(cmd)`, only `$VAR`
- no fs state -- `touch foo` "succeeds" but `ls` won't show it
- network commands (curl, wget, ssh, ping) all return canned output
- fixed hostname/uname

That's fine -- bots run scripts without checking if commands actually worked.

## TODO

- real fs state (so `touch` / `mkdir` / `ls` agree)
- ratelimit auth attempts per IP, not just total connections
- pcap mode? could be useful for replay
