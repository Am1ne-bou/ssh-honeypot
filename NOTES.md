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
