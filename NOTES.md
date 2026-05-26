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
