# ssh-honeypot

Low-interaction SSH honeypot written in Go. Accepts all password auth,
serves a fake shell, logs everything to JSON. Meant to run on a public VPS
and collect real attack data.

---

## Build

Requires Go 1.21+.

```bash
make build
# produces a static linux binary: ./ssh-honeypot
```

Cross-compile from any OS -- the Makefile sets `CGO_ENABLED=0 GOOS=linux`
so the binary runs on the VPS without any C dependencies.

---

## Deploy

```bash
# on VPS as root -- create a dedicated user with no login shell
useradd -r -s /sbin/nologin -d /var/lib/honeypot honeypot
mkdir -p /var/lib/honeypot/logs
chown -R honeypot:honeypot /var/lib/honeypot
chmod 700 /var/lib/honeypot

# move real sshd off port 22 first
# edit /etc/ssh/sshd_config -> Port VPS_PORT
# systemctl restart sshd
# open a new terminal and verify you can still ssh on VPS_PORT before continuing

# redirect port 22 to honeypot on 2222
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
# persist across reboots
iptables-save > /etc/iptables/rules.v4

# copy files
scp ssh-honeypot root@vps:/usr/local/bin/
scp systemd/ssh-honeypot.service root@vps:/etc/systemd/system/

# on the VPS
make install   # or do the scp manually then:
systemctl daemon-reload
systemctl enable --now ssh-honeypot
systemctl status ssh-honeypot
```

---

## Flags

```
-addr      listen address (default :2222)
-host-key  path to ed25519 host key file (default ./host.key)
-log-dir   directory for log files (default ./logs)
-max-conn  max concurrent SSH connections (default 100)
```

The host key is generated on first run and persisted. Keeping it stable
means scanners that fingerprint by host key will recognise the honeypot
across restarts.

---

## Log format

Three JSON log files in the log directory:

`auth.log` -- every login attempt:
```json
{"time":"2024-01-15T03:42:11Z","level":"INFO","msg":"auth attempt","method":"password","user":"root","password":"123456","remote":"185.220.101.47:54321","client":"SSH-2.0-libssh_0.9.6","outcome":"accepted"}
```

`session.log` -- handshakes, channel requests, commands typed:
```json
{"time":"2024-01-15T03:42:12Z","level":"INFO","msg":"shell","sid":"a3f9b2","command":"cat /etc/passwd"}
```

`server.log` -- startup, errors, connection rejections.
