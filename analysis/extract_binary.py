#!/usr/bin/env python3
# extract binaries injected via echo -e -n hex chunks from a session
# usage: python3 extract_binary.py <sid> [session.log or log-dir]

import json, re, sys, os
from collections import defaultdict

def parse_hex(cmd):
    m = re.search(r'echo -e -n "([^"]*)"', cmd)
    if not m:
        return None
    raw = m.group(1)
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i:i+2] == '\\x' and i + 4 <= len(raw):
            out.append(int(raw[i+2:i+4], 16))
            i += 4
        elif raw[i] == '\\' and i + 1 < len(raw):
            i += 2  # skip other escapes
        else:
            out.append(ord(raw[i]))
            i += 1
    return bytes(out)

def target_name(cmd):
    m = re.search(r'>>\s*(\S+)', cmd)
    return os.path.basename(m.group(1)) if m else 'unknown'

sid_prefix = sys.argv[1]
arg2 = sys.argv[2] if len(sys.argv) > 2 else '.'
logfile = os.path.join(arg2, 'session.log') if os.path.isdir(arg2) else arg2

chunks = defaultdict(list)
seen = set()

with open(logfile) as f:
    for line in f:
        try:
            e = json.loads(line)
            if e.get('msg') not in ('shell', 'exec'):
                continue
            if not e['sid'].startswith(sid_prefix):
                continue
            cmd = e.get('command', '')
            if 'echo -e -n' not in cmd:
                continue
            key = (e['time'], cmd[:40])
            if key in seen:
                continue
            seen.add(key)
            data = parse_hex(cmd)
            if data:
                chunks[target_name(cmd)].append(data)
        except:
            pass

if not chunks:
    print('no echo chunks found for sid', sid_prefix)
    sys.exit(1)

outdir = f'extracted_{sid_prefix[:8]}'
os.makedirs(outdir, exist_ok=True)

for name, parts in chunks.items():
    binary = b''.join(parts)
    path = os.path.join(outdir, name + '.txt')
    with open(path, 'w') as f:
        f.write(binary.hex())
    print(f'{name:10s}  {len(binary):>8} bytes  -> {path}')
