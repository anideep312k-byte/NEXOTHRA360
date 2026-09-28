#!/usr/bin/env python3
"""Insert exactly one SHOW/HIDE handler for #pwToggle inside DASHBOARD_HTML.

Refuses to write if:
  * the #pwToggle element is not present exactly once
  * the fix has already been applied (marker present)
Keeps a timestamped backup next to KAVACH360.py.
Does not touch anything outside DASHBOARD_HTML.
"""
import os, re, sys, time, shutil

BASE = os.path.expanduser("~/kavach360")
TARGET = os.path.join(BASE, "KAVACH360.py")

MARKER = "/* KAVACH360-pwtoggle-fix-v1 */"

# The fix is a self-contained <script> that:
#  * replaces the #pwToggle node with a clean clone (removes any prior listeners)
#  * attaches exactly one listener
#  * flips type between password/text
#  * updates the button label to SHOW / HIDE
#  * never clears the value, never submits the form
FIX = '''
<script>
/* KAVACH360-pwtoggle-fix-v1 */
(function () {
  "use strict";
  function install() {
    var old = document.getElementById("pwToggle");
    var pw  = document.getElementById("liPass");
    if (!old || !pw) return;

    /* Replace the button with a clean clone so no old handler survives. */
    var btn = old.cloneNode(true);
    old.parentNode.replaceChild(btn, old);

    /* Ensure the button cannot submit a form under any circumstance. */
    btn.setAttribute("type", "button");

    /* Set initial label based on current state. */
    btn.textContent = (pw.type === "password") ? "SHOW" : "HIDE";

    btn.addEventListener("click", function (ev) {
      ev.preventDefault();
      ev.stopPropagation();

      var showing = pw.type === "text";

      /* Preserve the current value and caret across the type change. */
      var start = pw.selectionStart;
      var end   = pw.selectionEnd;

      pw.type = showing ? "password" : "text";
      btn.textContent = showing ? "SHOW" : "HIDE";
      btn.setAttribute("aria-pressed", String(!showing));
      btn.setAttribute("aria-label", showing ? "Show passphrase" : "Hide passphrase");

      /* Restore caret, if the input is currently focused. */
      if (pw === document.activeElement && typeof start === "number") {
        try { pw.setSelectionRange(start, end); } catch (e) { /* ignore */ }
      }
    }, false);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", install, { once: true });
  } else {
    install();
  }
})();
</script>
'''

ANCHOR_RE = re.compile(
    r'(<button\b[^>]*\bid="pwToggle"\b[^>]*>.*?</button>\s*</div>)',
    re.DOTALL,
)

def main():
    if not os.path.exists(TARGET):
        print("missing:", TARGET); return 2
    with open(TARGET, "r", encoding="utf-8") as f:
        src = f.read()

    if MARKER in src:
        print("already applied:", MARKER); return 0

    if src.count('id="pwToggle"') != 1:
        print("ERROR: #pwToggle not found exactly once (count=%d)"
              % src.count('id="pwToggle"')); return 3
    if src.count('id="liPass"') != 1:
        print("ERROR: #liPass not found exactly once (count=%d)"
              % src.count('id="liPass"')); return 4

    m = ANCHOR_RE.search(src)
    if not m:
        print("ERROR: could not locate </div> closing the .pw-wrap block"); return 5

    insert_at = m.end()
    out = src[:insert_at] + FIX + src[insert_at:]

    if '"""' in FIX:
        print("ERROR: fix block contains triple-quote; aborting"); return 6

    bak = TARGET + ".before-pwtoggle-fix-" + time.strftime("%Y%m%d-%H%M%S") + ".bak"
    shutil.copy2(TARGET, bak)
    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(out)
    print("backup:", bak)
    print("inserted SHOW/HIDE fix at byte offset:", insert_at)
    print("file lines now:", out.count("\n") + 1)
    return 0

if __name__ == "__main__":
    sys.exit(main())
