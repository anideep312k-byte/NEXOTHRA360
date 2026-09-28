#!/usr/bin/env python3
"""Splice the new DASHBOARD_HTML into KAVACH360.py in place."""
import os, re, sys

TARGET = os.path.expanduser("~/kavach360/KAVACH360.py")
PART1  = os.path.expanduser("~/kavach360/_ui/dashboard_part1.txt")
PART2  = os.path.expanduser("~/kavach360/_ui/dashboard_part2.txt")
BACKUP = TARGET + ".before-ui-splice.bak"

def main():
    for p in (TARGET, PART1, PART2):
        if not os.path.exists(p):
            print("missing:", p); return 2

    with open(PART1, "r", encoding="utf-8") as f: p1 = f.read()
    with open(PART2, "r", encoding="utf-8") as f: p2 = f.read()
    if p1.endswith("\n"): p1 = p1[:-1]
    if not p2.endswith("\n"): p2 = p2 + "\n"
    body = p1 + "\n" + p2

    # Safety: the new UI must not contain a triple-quote sequence.
    if '"""' in body:
        print("ERROR: new UI contains a triple-quote; aborting."); return 3

    with open(TARGET, "r", encoding="utf-8") as f:
        src = f.read()

    # Locate the current DASHBOARD_HTML definition.
    # It is written as:   DASHBOARD_HTML = r"""<...>"""
    pat = re.compile(r'^DASHBOARD_HTML\s*=\s*r?"""', re.MULTILINE)
    m = pat.search(src)
    if not m:
        print("ERROR: could not find DASHBOARD_HTML definition"); return 4
    start = m.start()

    # Find the closing triple-quote AFTER start.
    close_idx = src.find('"""', m.end())
    if close_idx == -1:
        print("ERROR: could not find end of DASHBOARD_HTML"); return 5
    end = close_idx + 3

    old_len = end - start
    new_block = 'DASHBOARD_HTML = r"""' + body + '"""'
    new_src = src[:start] + new_block + src[end:]

    with open(BACKUP, "w", encoding="utf-8") as f:
        f.write(src)
    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(new_src)

    print("backup saved to:", BACKUP)
    print("old block bytes:", old_len)
    print("new block bytes:", len(new_block))
    print("file lines now :", new_src.count("\n") + 1)
    return 0

if __name__ == "__main__":
    sys.exit(main())
