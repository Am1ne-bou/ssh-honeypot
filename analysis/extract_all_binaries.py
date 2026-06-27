#!/usr/bin/env python3
# extract all echo-injected binaries from session.log
# for each target file, picks the session with the most bytes and saves it
# usage: python3 extract_all_binaries.py <log-dir> [output-dir]

import json, re, sys, os, hashlib
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
            i += 2
        else:
            out.append(ord(raw[i]))
            i += 1
    return bytes(out)

def target_name(cmd):
    m = re.search(r'>>\s*(\S+)', cmd)
    return m.group(1) if m else None

log_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
out_dir = sys.argv[2] if len(sys.argv) > 2 else 'extracted_binaries'
logfile = os.path.join(log_dir, 'session.log') if os.path.isdir(log_dir) else log_dir

# target -> sid -> list of bytes chunks
data = defaultdict(lambda: defaultdict(list))
seen = set()

print(f'scanning {logfile} ...')
with open(logfile) as f:
    for line in f:
        if 'echo -e -n' not in line:
            continue
        try:
            e = json.loads(line)
            if e.get('msg') not in ('shell', 'exec'):
                continue
            cmd = e.get('command', '')
            if 'echo -e -n' not in cmd:
                continue
            key = (e['time'], cmd[:60])
            if key in seen:
                continue
            seen.add(key)
            target = target_name(cmd)
            if not target:
                continue
            chunk = parse_hex(cmd)
            if chunk:
                data[target][e['sid']].append(chunk)
        except:
            pass

os.makedirs(out_dir, exist_ok=True)

ELF_MAGIC = b'\x7f\x45\x4c\x46'

print(f'\n{"target":<20} {"sessions":>8} {"best sid":>12} {"bytes":>10} {"sha256"}')
print('-' * 90)

for target in sorted(data):
    sessions = data[target]
    # prefer sessions that start with ELF magic; fall back to largest if none do
    elf_sessions = {s: chunks for s, chunks in sessions.items()
                    if chunks and b''.join(chunks[:1]).startswith(ELF_MAGIC)}
    pool = elf_sessions if elf_sessions else sessions
    best_sid = max(pool, key=lambda s: sum(len(c) for c in pool[s]))
    binary = b''.join(pool[best_sid])
    sha = hashlib.sha256(binary).hexdigest()
    name = os.path.basename(target)
    # deduplicate: if two targets resolve to same name and same hash, skip
    outpath = os.path.join(out_dir, name)
    if os.path.exists(outpath) and hashlib.sha256(open(outpath,'rb').read()).hexdigest() == sha:
        print(f'{target:<20} {len(sessions):>8} {best_sid[:10]:>12} {len(binary):>10,}  {sha[:32]}... (dup, skipped)')
        continue
    with open(outpath, 'wb') as f:
        f.write(binary)
    elf_ok = 'ELF' if binary[:4] == ELF_MAGIC else 'NON-ELF'
    print(f'{target:<20} {len(sessions):>8} {best_sid[:10]:>12} {len(binary):>10,}  {sha[:32]}... [{elf_ok}]')

print(f'\nbinaries saved to {out_dir}/')
print('run: file extracted_binaries/* && sha256sum extracted_binaries/*')
