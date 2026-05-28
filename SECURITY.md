# Security policy

## What this tool does

This is a passive research honeypot. It listens for inbound SSH connections, logs
credentials and commands that attackers try, and returns fake responses. It does not
attack anything, does not exfiltrate data to third parties, and does not execute any
attacker-supplied code.

## Data logged

The honeypot logs the following data from incoming connections:

- Source IP address and port
- SSH client banner (version string)
- Usernames and **passwords in plaintext**
- Commands typed in the fake shell
- SCP filenames and sizes (not contents, unless `--quarantine-dir` is set)

Treat the log files as sensitive. Passwords collected here are often reused from real
accounts. Do not publish raw password lists, and restrict log file access to the
operator only.

## Quarantine directory

If `--quarantine-dir` is set, the honeypot writes uploaded payloads to disk as
`<sha256>-<name>.bin` with mode `0o400` (read-only, owner only). The directory should
not be world-readable. Treat quarantined files as potentially malicious -- do not
execute them on the host system.

The honeypot defends against path traversal in attacker-supplied filenames by calling
`filepath.Base` before writing. Files larger than 50 MB are discarded without saving.

## Intended use

This tool is for:

- Personal security research
- Learning about attack patterns
- Academic or professional threat intelligence

It is not intended to be used as part of an attack, to harvest credentials for
unauthorized access, or to deceive legitimate users.

## Deployment hardening

- Run as a dedicated non-root service user with no login shell
- The systemd unit applies `NoNewPrivileges`, `ProtectSystem=strict`,
  `CapabilityBoundingSet=`, and other restrictions
- Real SSH should be on a non-standard port with key-only authentication
- Log files and quarantine directory should be owned by the service user only
- The honeypot process itself has no credentials and no access to the host filesystem
  beyond its own working directories

## Scope of the fake shell

The fake shell does not execute attacker commands on the host. All command output is
hardcoded or computed from internal state. There is no `eval`, no `exec`, no subprocess
spawning. An attacker interacting with the shell is talking to Go code, not to a real
Linux environment.

The session virtual filesystem is in-memory and per-connection. Files "uploaded" via
SCP exist only in that map and are discarded when the connection closes (unless
`--quarantine-dir` captures the raw bytes).

## Reporting a vulnerability

If you find a security issue in the honeypot code itself -- a way to escape the fake
shell and reach the host, crash the process, or cause unintended behavior:

Open a GitHub issue or contact the maintainer directly. No formal bounty, but I will
fix it and credit you.

If the vulnerability could be actively exploited against running instances before a fix
is available, send a private message first rather than opening a public issue.
