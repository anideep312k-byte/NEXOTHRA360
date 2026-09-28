#!/usr/bin/env python3
"""Insert Profile route, renderer, and /v1/me consumer into DASHBOARD_HTML.
Refuses to write unless all anchors are found exactly once.
Keeps a timestamped backup next to KAVACH360.py.
"""
import os, sys, time, shutil

BASE = os.path.expanduser("~/kavach360")
TARGET = os.path.join(BASE, "KAVACH360.py")

ROUTE_ANCHOR = '  { id: "settings",    label: "System Health",    group: "Governance", render: renderSettings }'
ROUTE_NEW    = '  { id: "profile",     label: "My Profile",       group: "Governance", render: renderProfile },\n'

RENDER_ANCHOR = 'async function renderSettings(main) {'
RENDER_NEW = '''async function renderProfile(main) {
  const me = await api("/v1/me");

  const row = (label, value) => [
    el("div", { class: "k", text: label }),
    el("div", { text: value == null || value === "" ? "\\u2014" : String(value) })
  ];

  const wrap = el("div", { class: "stack" }, [
    el("div", { class: "row between" }, [
      el("h1", { text: "My Profile" }),
      el("button", { text: "Refresh", onclick: () => renderProfile(main) })
    ]),
    el("div", { class: "panel" }, [
      el("h2", { text: "Identity" }),
      el("div", { class: "detail-kv" }, [
        ...row("Username", me.username),
        ...row("User ID", me.user_id),
        ...row("Tenant", me.tenant_id),
        ...row("Role", me.role)
      ])
    ]),
    el("div", { class: "panel" }, [
      el("h2", { text: "Role permissions" }),
      el("p", { class: "muted",
        text: "Permissions are enforced by the backend. The list below is a " +
              "read-only summary derived from your role." }),
      el("pre", { class: "json",
        text: JSON.stringify(rolePermissions(me.role), null, 2) })
    ]),
    el("div", { class: "panel" }, [
      el("h2", { text: "Session" }),
      el("div", { class: "detail-kv" }, [
        ...row("Must change password", me.must_change_password ? "yes" : "no"),
        ...row("Tenant", me.tenant_id),
        ...row("Current role", me.role)
      ]),
      el("p", { class: "muted",
        text: "Sensitive material \\u2014 password hash, JWT secret, MFA secret \\u2014 " +
              "is never sent to the browser." })
    ])
  ]);
  clear(main);
  main.appendChild(wrap);
}

function rolePermissions(role) {
  const map = {
    super_admin:   ["* (all permissions)"],
    security_admin:["config:read","config:write","user:read","user:write",
                    "detection:read","detection:write","incident:read",
                    "incident:write","response:approve","response:execute",
                    "response:propose","soar:killswitch","audit:read",
                    "case:read","case:write","ai:invoke","hunt:run",
                    "event:write","ioc:write"],
    soc_manager:   ["incident:read","incident:write","case:read","case:write",
                    "response:approve","response:execute","response:propose",
                    "soar:killswitch","audit:read","ai:invoke","hunt:run",
                    "detection:read","event:write","ioc:write","user:read"],
    l5_analyst:    ["incident:read","incident:write","case:read","case:write",
                    "response:approve","response:execute","response:propose",
                    "ai:invoke","hunt:run","detection:read","detection:write",
                    "event:write","ioc:write","user:read"],
    l4_analyst:    ["incident:read","incident:write","case:read","case:write",
                    "response:propose","ai:invoke","hunt:run","detection:read",
                    "detection:write","event:write","ioc:write"],
    l3_analyst:    ["incident:read","incident:write","case:read","case:write",
                    "ai:invoke","hunt:run","event:write","ioc:write"],
    l2_analyst:    ["incident:read","incident:write","case:read","case:write",
                    "ai:invoke","event:write"],
    l1_analyst:    ["incident:read","case:read","ai:invoke"],
    threat_hunter: ["hunt:run","ai:invoke","incident:read","case:read","event:write"],
    auditor:       ["audit:read","config:read","incident:read","case:read","detection:read"],
    read_only:     ["incident:read","case:read","config:read"]
  };
  return map[role] || ["(unknown role)"];
}

'''

ME_OLD = '''  if (session.load()) {
    api("/v1/me").then(() => showApp()).catch(() => {
      session.clear();
      showLogin();
    });
  } else {
    showLogin();
  }'''

ME_NEW = '''  if (session.load()) {
    api("/v1/me").then((me) => {
      if (me) {
        session.username = me.username || session.username;
        session.role     = me.role     || session.role;
        session.userId   = me.user_id  || session.userId;
        session.tenant   = me.tenant_id|| session.tenant;
        session.save();
      }
      showApp();
    }).catch(() => {
      session.clear();
      showLogin();
    });
  } else {
    showLogin();
  }'''

def count(src, anchor):
    return src.count(anchor)

def main():
    if not os.path.exists(TARGET):
        print("missing:", TARGET); return 2
    with open(TARGET, "r", encoding="utf-8") as f:
        src = f.read()

    if count(src, ROUTE_ANCHOR) != 1:
        print("ERROR: settings route anchor not found exactly once"); return 3
    src = src.replace(ROUTE_ANCHOR, ROUTE_NEW + ROUTE_ANCHOR, 1)

    if count(src, RENDER_ANCHOR) != 1:
        print("ERROR: renderSettings anchor not found exactly once"); return 4
    src = src.replace(RENDER_ANCHOR, RENDER_NEW + RENDER_ANCHOR, 1)

    if count(src, ME_OLD) != 1:
        print("ERROR: /v1/me consumer anchor not found exactly once"); return 5
    src = src.replace(ME_OLD, ME_NEW, 1)

    bak = TARGET + ".before-profile-" + time.strftime("%Y%m%d-%H%M%S") + ".bak"
    shutil.copy2(TARGET, bak)
    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(src)
    print("backup:", bak)
    print("edits applied: route + renderProfile + init() consumer")
    print("file lines now:", src.count("\n") + 1)
    return 0

if __name__ == "__main__":
    sys.exit(main())
