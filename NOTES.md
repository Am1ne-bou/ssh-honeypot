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
