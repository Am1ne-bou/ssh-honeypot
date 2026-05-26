"""
Deep password analysis from auth.log.
Shows length distribution, character class breakdown, common patterns,
and the full sorted list.

Usage: python3 analysis/passwords.py [log_dir]
  log_dir defaults to ./logs if not given.
"""

import argparse
import json
import os
import sys
from collections import Counter


def load_passwords(auth_path):
    """Return list of every password attempt (with duplicates)."""
    out = []
    try:
        f = open(auth_path)
    except FileNotFoundError:
        print("WARNING: %s not found" % auth_path, file=sys.stderr)
        return out
    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("msg") != "auth attempt":
                continue
            pw = rec.get("password", "")
            if pw:
                out.append(pw)
    return out


def charset(pw):
    """Classify password by character set."""
    has_digit   = any(c.isdigit() for c in pw)
    has_lower   = any(c.islower() for c in pw)
    has_upper   = any(c.isupper() for c in pw)
    has_special = any(not c.isalnum() for c in pw)

    if has_special:
        return "special"
    if has_upper and (has_lower or has_digit):
        return "mixed-case"
    if has_digit and not has_lower and not has_upper:
        return "digits-only"
    if (has_lower or has_upper) and not has_digit:
        return "alpha-only"
    return "alphanumeric"


def heading(title):
    print()
    print(title)
    print("-" * len(title))


def print_counter(counter, limit=None):
    items = counter.most_common(limit)
    if not items:
        print("  (none)")
        return
    count_width = len(str(items[0][1]))
    key_width   = max(len(str(k)) for k, _ in items)
    for k, v in items:
        print("  %-*s  %*d" % (key_width, k, count_width, v))


def main():
    parser = argparse.ArgumentParser(
        description="Deep password analysis from SSH honeypot auth.log."
    )
    parser.add_argument(
        "logdir",
        nargs="?",
        default="./logs",
        help="directory containing auth.log (default: ./logs)",
    )
    args = parser.parse_args()

    auth_path = os.path.join(args.logdir, "auth.log")
    attempts  = load_passwords(auth_path)

    if not attempts:
        print("no password attempts found")
        sys.exit(0)

    unique = Counter(attempts)
    total  = len(attempts)
    nuniq  = len(unique)

    print("=" * 52)
    print("PASSWORD ANALYSIS")
    print("Log dir: %s" % os.path.abspath(args.logdir))
    print("=" * 52)

    heading("SUMMARY")
    print("  Total attempts  : %d" % total)
    print("  Unique passwords: %d" % nuniq)
    print("  Repeat rate     : %.1f%%" % (100.0 * (total - nuniq) / total if total else 0))

    # --- length distribution ---
    heading("LENGTH DISTRIBUTION")
    buckets = Counter()
    for pw in attempts:
        n = len(pw)
        if n <= 4:
            buckets["1-4"] += 1
        elif n <= 8:
            buckets["5-8"] += 1
        elif n <= 12:
            buckets["9-12"] += 1
        else:
            buckets["13+"] += 1
    for label in ["1-4", "5-8", "9-12", "13+"]:
        count = buckets[label]
        bar   = "#" * (count * 30 // total) if total else ""
        print("  %-5s  %5d  %s" % (label, count, bar))

    # --- charset breakdown ---
    heading("CHARACTER CLASS")
    classes = Counter(charset(pw) for pw in attempts)
    print_counter(classes)

    # --- common numeric suffixes ---
    # bots often append numbers to base words: admin123, root2024, etc.
    heading("COMMON NUMERIC SUFFIXES (last 1-4 chars if digits)")
    suffixes = Counter()
    for pw in attempts:
        i = len(pw)
        while i > 0 and pw[i-1].isdigit():
            i -= 1
        tail = pw[i:]
        if tail:
            suffixes[tail] += 1
    print_counter(suffixes, 15)

    # --- common base words (strip trailing digits) ---
    heading("COMMON BASE WORDS (trailing digits stripped)")
    bases = Counter()
    for pw in attempts:
        i = len(pw)
        while i > 0 and pw[i-1].isdigit():
            i -= 1
        base = pw[:i]
        if base:
            bases[base] += 1
    print_counter(bases, 15)

    # --- full list ---
    heading("ALL PASSWORDS (sorted by frequency)")
    print_counter(unique)

    print()


if __name__ == "__main__":
    main()
