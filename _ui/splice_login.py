"""
Safely splice the new 3D login into DASHBOARD_HTML.

Rules:
  * Locate  <div id="loginView"  and  <div id="app"
    inside the DASHBOARD_HTML string only.
  * Replace the byte range between them with the new login block.
  * Inject <style> (login.css) and <script> (login.js) right after the
    login block, still inside DASHBOARD_HTML.
  * Refuse to write unless both anchors are found exactly once.
  * Refuse to write if the new content contains a Python triple quote.
  * Keep a .bak of the file next to it.
"""

import os, re, sys, shutil

BASE = os.path.expanduser("~/kavach360")
TARGET = os.path.join(BASE, "KAVACH360.py")
LOGIN_HTML = os.path.join(BASE, "_ui", "login_new.html")
LOGIN_CSS  = os.path.join(BASE, "_ui", "login.css")
LOGIN_JS   = os.path.join(BASE, "_ui", "login.js")
BACKUP = TARGET + ".before-3d-login.bak"

def read(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()

def main():
    for p in (TARGET, LOGIN_HTML, LOGIN_CSS, LOGIN_JS):
        if not os.path.exists(p):
            print("missing:", p); return 2

    src = read(TARGET)
    new_html = read(LOGIN_HTML).rstrip("\n")
    css = read(LOGIN_CSS).rstrip("\n")
    js  = read(LOGIN_JS).rstrip("\n")

    # Guard: the injected code must not contain a Python triple quote.
    for blob, name in ((new_html, "login_new.html"), (css, "login.css"), (js, "login.js")):
        if '"""' in blob:
            print("ERROR: %s contains a triple quote; aborting." % name); return 3

    # Anchor 1: opening <div id="loginView" ...> — the byte offset of the '<'.
    m1 = re.search(r'<div\s+id="loginView"', src)
    if not m1:
        print("ERROR: could not find loginView in source"); return 4

    # Anchor 2: <div id="app" — must be after loginView.
    m2 = re.search(r'<div\s+id="app"', src[m1.start():])
    if not m2:
        print("ERROR: could not find #app after loginView"); return 5
    app_at = m1.start() + m2.start()

    # Refuse if there are multiple loginView anchors, to be safe.
    if len(re.findall(r'<div\s+id="loginView"', src)) != 1:
        print("ERROR: multiple loginView anchors; refusing"); return 6
    if len(re.findall(r'<div\s+id="app"', src)) < 1:
        print("ERROR: no #app anchor; refusing"); return 7

    # Compose the replacement: HTML + style + script.
    css_block  = '<style>\n'  + css + '\n</style>\n'
    js_block   = '<script>\n' + js  + '\n</script>\n'
    replacement = new_html + "\n" + css_block + js_block + "\n"

    out = src[:m1.start()] + replacement + src[app_at:]

    # Backup once (do not clobber an existing backup from a prior step).
    if not os.path.exists(BACKUP):
        shutil.copy2(TARGET, BACKUP)
        print("backup written:", BACKUP)
    else:
        print("backup already exists:", BACKUP)

    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(out)

    print("replaced login block.")
    print("old bytes from loginView to #app:", app_at - m1.start())
    print("new bytes                    :", len(replacement))
    print("file lines now               :", out.count("\n") + 1)
    return 0

if __name__ == "__main__":
