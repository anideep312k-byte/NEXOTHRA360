#!/usr/bin/env python3
"""Replace the <form>...</form> block in login_3d_final.html with the
   freshly-verified form_block.html. Refuses to write on any mismatch."""
import os, re, sys, time, shutil

BASE = os.path.expanduser("~/kavach360")
HTML = os.path.join(BASE, "_ui", "login_3d_final.html")
FORM = os.path.join(BASE, "_ui", "form_block.html")

def main():
    for p in (HTML, FORM):
        if not os.path.exists(p):
            print("missing:", p); return 2
    with open(HTML, "r", encoding="utf-8") as f:
        src = f.read()
    with open(FORM, "r", encoding="utf-8") as f:
        new_form = f.read().rstrip("\n")

    m = re.search(r'<form\b[^>]*>.*?</form>', src, flags=re.DOTALL)
    if not m:
        print("ERROR: <form>...</form> not found in login_3d_final.html"); return 3
    if len(re.findall(r'<form\b[^>]*>', src)) != 1:
        print("ERROR: multiple <form> tags; refusing"); return 4

    out = src[:m.start()] + new_form + src[m.end():]
    bak = HTML + ".before-formfix-" + time.strftime("%Y%m%d-%H%M%S") + ".bak"
    shutil.copy2(HTML, bak)
    with open(HTML, "w", encoding="utf-8") as f:
        f.write(out)
    print("backup:", bak)
    print("replaced <form> block")
    print("old form bytes:", len(m.group(0)), "| new form bytes:", len(new_form))
    print("file lines now:", out.count("\n") + 1)
    return 0

if __name__ == "__main__":
    sys.exit(main())
