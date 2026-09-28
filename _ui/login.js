   KAVACH360 — 3D cyber-network login background (original).
   Pure Canvas 2D + requestAnimationFrame. No dependencies.
   ============================================================ */
(function () {
  "use strict";

  var canvas = document.getElementById("socCanvas");
  if (!canvas || !canvas.getContext) return;

  var prefersReduce = window.matchMedia
    && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (prefersReduce) return;

  var ctx = canvas.getContext("2d");
  var dpr = Math.min(window.devicePixelRatio || 1, 2);
  var W = 0, H = 0;

  function resize() {
    var r = canvas.parentNode.getBoundingClientRect();
    W = Math.max(1, Math.floor(r.width));
    H = Math.max(1, Math.floor(r.height));
    canvas.width  = Math.floor(W * dpr);
    canvas.height = Math.floor(H * dpr);
    canvas.style.width  = W + "px";
    canvas.style.height = H + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  window.addEventListener("resize", resize, { passive: true });
  resize();

  /* ---------- bounded entity pools ---------- */
  var NODE_MAX  = 90;
  var LINK_MAX  = 140;
  var PART_MAX  = 220;
  var PACK_MAX  = 40;

  var nodes = [];
  var links = [];
  var particles = [];
  var packets = [];
  var ripples = [];
  var radarAngle = 0;

  function rnd(a, b) { return a + Math.random() * (b - a); }
  function dist2(a, b) {
    var dx = a.x - b.x, dy = a.y - b.y;
    return dx * dx + dy * dy;
  }

  function spawnNodes() {
    nodes.length = 0;
    var count = Math.max(24, Math.min(NODE_MAX, Math.floor((W * H) / 22000)));
    for (var i = 0; i < count; i++) {
      nodes.push({
        x: rnd(0, W),
        y: rnd(0, H),
        vx: rnd(-0.12, 0.12),
        vy: rnd(-0.12, 0.12),
        r: rnd(1.1, 2.4),
        kind: Math.random() < 0.14 ? "hot" : "cold"
      });
    }
  }

  function rebuildLinks() {
    links.length = 0;
    var maxd2 = Math.pow(Math.max(W, H) * 0.22, 2);
    outer:
    for (var i = 0; i < nodes.length; i++) {
      for (var j = i + 1; j < nodes.length; j++) {
        if (links.length >= LINK_MAX) break outer;
        if (dist2(nodes[i], nodes[j]) < maxd2) links.push([i, j]);
      }
    }
  }

  function spawnParticles() {
    particles.length = 0;
    for (var i = 0; i < PART_MAX; i++) {
      particles.push({
        x: rnd(0, W),
        y: rnd(0, H),
        vx: rnd(-0.08, 0.08),
        vy: rnd(-0.08, 0.08),
        a: rnd(0.05, 0.35)
      });
    }
  }

  function spawnPackets() {
    packets.length = 0;
    for (var i = 0; i < PACK_MAX; i++) packets.push(newPacket());
  }

  function newPacket() {
    return { link: -1, t: 0, speed: rnd(0.004, 0.012) };
  }

  function pickLink(p) {
    if (!links.length) { p.link = -1; return; }
    p.link = Math.floor(Math.random() * links.length);
    p.t = 0;
  }

  spawnNodes();
  rebuildLinks();
  spawnParticles();
  spawnPackets();

  /* ---------- animation loop ---------- */
  var running = true;
  var last = performance.now();

  document.addEventListener("visibilitychange", function () {
    running = !document.hidden;
    if (running) {
      last = performance.now();
      requestAnimationFrame(frame);
    }
  });

  function step(dt) {
    for (var i = 0; i < nodes.length; i++) {
      var n = nodes[i];
      n.x += n.vx * dt;
      n.y += n.vy * dt;
      if (n.x < -20) n.x = W + 20;
      if (n.x > W + 20) n.x = -20;
      if (n.y < -20) n.y = H + 20;
      if (n.y > H + 20) n.y = -20;
    }
    for (var k = 0; k < particles.length; k++) {
      var p = particles[k];
      p.x += p.vx * dt;
      p.y += p.vy * dt;
      if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
    }
    for (var q = 0; q < packets.length; q++) {
      var pk = packets[q];
      if (pk.link < 0 || pk.link >= links.length) pickLink(pk);
      pk.t += pk.speed * dt;
      if (pk.t >= 1) pickLink(pk);
    }
    radarAngle = (radarAngle + 0.006 * dt) % (Math.PI * 2);
    for (var r = ripples.length - 1; r >= 0; r--) {
      ripples[r].age += dt;
      if (ripples[r].age > 100) ripples.splice(r, 1);
    }
    if (Math.random() < 0.006 && ripples.length < 6) {
      ripples.push({ x: rnd(0, W), y: rnd(0, H), age: 0 });
    }
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);

    var cx = W * 0.5, cy = H * 0.5;
    var coreR = Math.min(W, H) * 0.16;

    /* radar sweep */
    ctx.save();
    var grad = ctx.createRadialGradient(cx, cy, coreR * 0.2, cx, cy, coreR * 2.4);
    grad.addColorStop(0, "rgba(90,209,255,0.10)");
    grad.addColorStop(1, "rgba(90,209,255,0)");
    ctx.fillStyle = grad;
    ctx.beginPath(); ctx.arc(cx, cy, coreR * 2.4, 0, Math.PI * 2); ctx.fill();

    ctx.strokeStyle = "rgba(90,209,255,0.22)";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, coreR * 2.4, radarAngle, radarAngle + 0.35);
    ctx.closePath();
    ctx.stroke();
    ctx.restore();

    /* links */
    ctx.lineWidth = 0.6;
    for (var i = 0; i < links.length; i++) {
      var a = nodes[links[i][0]], b = nodes[links[i][1]];
      ctx.strokeStyle = "rgba(90,209,255,0.08)";
      ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
    }

    /* moving packets */
    for (var q = 0; q < packets.length; q++) {
      var pk = packets[q];
      if (pk.link < 0) continue;
      var L = links[pk.link];
      if (!L) continue;
      var na = nodes[L[0]], nb = nodes[L[1]];
      var x = na.x + (nb.x - na.x) * pk.t;
      var y = na.y + (nb.y - na.y) * pk.t;
      ctx.fillStyle = "rgba(140,230,255,0.9)";
      ctx.beginPath(); ctx.arc(x, y, 1.4, 0, Math.PI * 2); ctx.fill();
    }

    /* ripples */
    for (var r = 0; r < ripples.length; r++) {
      var rp = ripples[r];
      var rr = rp.age * 1.4;
      ctx.strokeStyle = "rgba(90,209,255," + (0.22 * (1 - rp.age / 100)).toFixed(3) + ")";
      ctx.lineWidth = 1;
      ctx.beginPath(); ctx.arc(rp.x, rp.y, rr, 0, Math.PI * 2); ctx.stroke();
    }

    /* nodes */
    for (var k = 0; k < nodes.length; k++) {
      var n = nodes[k];
      if (n.kind === "hot") {
        ctx.fillStyle = "rgba(90,209,255,0.95)";
        ctx.shadowColor = "rgba(90,209,255,0.9)";
        ctx.shadowBlur = 12;
      } else {
        ctx.fillStyle = "rgba(180,220,255,0.65)";
        ctx.shadowColor = "rgba(90,209,255,0.35)";
        ctx.shadowBlur = 5;
      }
      ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2); ctx.fill();
    }
    ctx.shadowBlur = 0;

    /* particles (dimmer, drawn last for a hazy overlay) */
    for (var i2 = 0; i2 < particles.length; i2++) {
      var p = particles[i2];
      ctx.fillStyle = "rgba(160,210,255," + p.a.toFixed(3) + ")";
      ctx.fillRect(p.x, p.y, 1, 1);
    }

    /* central shield core */
    ctx.save();
    ctx.translate(cx, cy);
    ctx.rotate(radarAngle * 0.6);
    var shieldGrad = ctx.createRadialGradient(0, 0, 4, 0, 0, coreR);
    shieldGrad.addColorStop(0, "rgba(90,209,255,0.35)");
    shieldGrad.addColorStop(0.6, "rgba(43,116,209,0.10)");
    shieldGrad.addColorStop(1, "rgba(43,116,209,0)");
    ctx.fillStyle = shieldGrad;
    ctx.beginPath(); ctx.arc(0, 0, coreR, 0, Math.PI * 2); ctx.fill();

    ctx.strokeStyle = "rgba(90,209,255,0.55)";
    ctx.lineWidth = 1.2;
    for (var ring = 0; ring < 3; ring++) {
      var rr2 = coreR * (0.55 + ring * 0.22);
      ctx.beginPath();
      ctx.arc(0, 0, rr2, 0, Math.PI * 1.35);
      ctx.stroke();
    }
    ctx.restore();
  }

  function frame(now) {
    if (!running) return;
    var dt = Math.min(2.5, (now - last) / 16.67);
    last = now;
    step(dt);
    draw();
    requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);

  /* resize → re-seed so density stays reasonable */
  var resizeTimer = null;
  window.addEventListener("resize", function () {
    if (resizeTimer) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      resize();
      spawnNodes();
      rebuildLinks();
      spawnParticles();
      spawnPackets();
    }, 180);
  }, { passive: true });

  /* ============================================================
     Login form wiring — talks to the EXISTING backend
     POST /v1/auth/login  →  { token, user_id, role, tenant_id, must_change_password }
     The response shape is unchanged. This block only drives
     the visual states; it does not change how login works.
     ============================================================ */

  var form    = document.getElementById("loginForm");
  var btn     = document.getElementById("loginBtn");
  var errEl   = document.getElementById("loginErr");
  var pwTog   = document.getElementById("pwToggle");
  var pwField = document.getElementById("liPass");
  var verEl   = document.getElementById("loginVer");

  /* Version tag — best-effort, does not block. */
  fetch("/v1/version", { headers: { "Accept": "application/json" } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) { if (d && d.version) verEl.textContent = "v" + d.version; })
    .catch(function () { /* ignore */ });

  if (pwTog && pwField) {
    pwTog.addEventListener("click", function () {
      var showing = pwField.type === "text";
      pwField.type = showing ? "password" : "text";
      pwTog.setAttribute("aria-pressed", String(!showing));
      pwTog.setAttribute("aria-label", showing ? "Show passphrase" : "Hide passphrase");
      pwField.focus();
    });
  }

  function showError(msg) {
    if (!errEl) return;
    errEl.textContent = msg || "Authentication failed";
    errEl.classList.remove("show");
    /* force a reflow so the shake restarts if shown again */
    void errEl.offsetWidth;
    errEl.classList.add("show");
  }
  function clearError() {
    if (!errEl) return;
    errEl.textContent = "";
    errEl.classList.remove("show");
  }

  function setLoading(on) {
    if (!btn) return;
    if (on) {
      btn.disabled = true;
      btn.classList.add("loading");
    } else {
      btn.disabled = false;
      btn.classList.remove("loading");
    }
  }

  /* If the parent dashboard already handles login, we must not double-handle it.
     The parent attaches its own submit listener to #loginForm. If it exists,
     this handler observes and does nothing else. If it does NOT exist, we
     perform the login ourselves using the same endpoint and same request body
     that the parent would have sent.
     This keeps compatibility with both the old and new dashboard code. */
  var parentHandles = false;

  /* Give the parent script a tick to attach its own listener (it does so on
     DOMContentLoaded, and this file is injected in the same document). */
  setTimeout(function () {
    parentHandles = (form && form.dataset && form.dataset.k360Bound === "1");
    /* If the parent bound its handler, mark it and let it run. Otherwise
       attach a minimal login handler that mirrors the parent's behavior. */
    if (!parentHandles) attachFallbackLogin();
  }, 0);

  function attachFallbackLogin() {
    if (!form) return;
    form.addEventListener("submit", doLogin, true);

    async function doLogin(ev) {
      if (ev) ev.preventDefault();
      clearError();
      var t = document.getElementById("liTenant").value.trim();
      var u = document.getElementById("liUser").value.trim();
      var p = document.getElementById("liPass").value;
      var m = document.getElementById("liMfa").value.trim();
      if (!t || !u || !p) {
        showError("Tenant, analyst ID and passphrase are required.");
        return;
      }
      setLoading(true);
      try {
        var body = { tenant_id: t, username: u, password: p };
        if (m) body.mfa_code = m;
        var resp = await fetch("/v1/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body)
        });
        var data = null;
        try { data = await resp.json(); } catch (e) { data = null; }
        if (!resp.ok || !data || !data.token) {
          showError((data && data.error) || ("Login failed (HTTP " + resp.status + ")"));
          return;
        }
        /* Hand off to the parent's session storage exactly as before. */
        try {
          localStorage.setItem("k360", JSON.stringify({
            token: data.token,
            tenant: data.tenant_id,
            role: data.role,
            username: u,
            userId: data.user_id,
            ts: Date.now()
          }));
        } catch (e) { /* private mode — parent will handle it */ }
        /* Reload so the parent's init() runs and shows the dashboard. */
        location.reload();
      } catch (err) {
        showError("Network error: " + (err && err.message ? err.message : "unreachable"));
      } finally {
        setLoading(false);
      }
    }
  }
