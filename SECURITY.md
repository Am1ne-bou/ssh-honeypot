# Security policy

## What this tool does

This is a passive research honeypot. It listens for inbound SSH connections,
logs credentials and commands that attackers try, and returns fake responses.
It does not attack anything, does not exfiltrate data to third parties, and
does not execute any attacker-supplied code.

## Data logged

The honeypot logs the following data from incoming connections:

- Source IP address and port
- SSH client banner (version string)
- Usernames and **passwords in plaintext**
- Commands typed in the fake shell

If you are running this on a public IP, treat the log files as sensitive.
Passwords people try here are often reused from real accounts -- handle them
accordingly and do not publish raw password lists.

## Intended use

This tool is for:

- Personal security research
- Learning about attack patterns
- Academic or professional threat intelligence

It is not intended to be used as part of an attack, to harvest credentials for
unauthorized access, or to deceive legitimate users.

## Deployment note

If you deploy this, make sure your real SSH service is on a non-standard port
and protected by key-only auth. The honeypot itself has no auth -- it accepts
(and logs) any connection. Do not run it as root.

## Reporting a vulnerability in this tool

If you find a security issue in the honeypot code itself (e.g. a way to escape
the fake shell and reach the host, or a way to crash the process):

Open a GitHub issue or email the maintainer directly. No formal bounty, but
I will fix it and credit you.

Do not open a public issue if the vulnerability could be actively exploited
against running instances before a fix is available -- send a private message
first.
