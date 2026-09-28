#!/usr/bin/env python3
import os, re, sys, time, shutil

BASE = os.path.expanduser("~/kavach360")
TARGET = os.path.join(BASE, "KAVACH360.py")
HTML_F = os.path.join(BASE, "_ui", "login_3d_final.html")
CSS_F  = os.path.join(BASE, "_ui", "login_3d_final.css")
JS_F   = os.path.join(BASE, "_ui", "login_3d_final.js")

def read(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()

def main():
    for p in (TARGET, HTML_F, CSS_F, JS_F):
        if not os.path.exists(p):
            print("missing:", p); return 2

    src = read(TARGET)
    html = read(HTML_F).rstrip("\n")
    css  = read(CSS_F).rstrip("\n")
    js   = read(JS_F).rstrip("\n")

    for blob, name in ((html, "html"), (css, "css"), (js, "js")):
        if '"""' in blob:
            print("ERROR: %s contains triple-quote; aborting" % name); return 3

    # anchor: <div id="loginView" ...>
    m1 = re.search(r'<div\s+id="loginView"', src)
    if not m1:
        print("ERROR: loginView anchor not found"); return 4
    # anchor: <div id="app" ...>  (must be after loginView)
    m2 = re.search(r'<div\s+id="app"', src[m1.start():])
    if not m2:
        print("ERROR: #app anchor not found after loginView"); return 5
    app_at = m1.start() + m2.start()

    if len(re.findall(r'<div\s+id="loginView"', src)) != 1:
        print("ERROR: multiple loginView anchors; refusing"); return 6

    block = (html + "\n\n<style>\n" + css + "\n</style>\n\n"
             + "<script>\n" + js + "\n</script>\n\n")

    out = src[:m1.start()] + block + src[app_at:]

    bak = TARGET + ".before-3d-splice-" + time.strftime("%Y%m%d-%H%M%S") + ".bak"
    shutil.copy2(TARGET, bak)
    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(out)

    print("backup:", bak)
    print("replaced loginView block")
    print("old bytes:", app_at - m1.start(), "| new bytes:", len(block))
    print("file lines now:", out.count("\n") + 1)
    return 0

if __name__ == "__main__":
    sys.exit(main())
