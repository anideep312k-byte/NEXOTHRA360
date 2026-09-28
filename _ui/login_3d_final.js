(function () {
  "use strict";

  /* ---------- 3D cyber-network background ---------- */
  var canvas = document.getElementById("socCanvas");
  var prefersReduce = window.matchMedia
    && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (canvas && canvas.getContext && !prefersReduce) {
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

    var NODE_MAX = 90, LINK_MAX = 140, PART_MAX = 220, PACK_MAX = 40;
    var nodes = [], links = [], particles = [], packets = [], ripples = [];
    var radarAngle = 0;

    function rnd(a, b) { return a + Math.random() * (b - a); }
    function dist2(a, b) { var dx = a.x - b.x, dy = a.y - b.y; return dx*dx + dy*dy; }

    function spawnNodes() {
      nodes.length = 0;
      var count = Math.max(24, Math.min(NODE_MAX, Math.floor((W * H) / 22000)));
      for (var i = 0; i < count; i++) {
        nodes.push({
          x: rnd(0, W), y: rnd(0, H),
          vx: rnd(-0.12, 0.12), vy: rnd(-0.12, 0.12),
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
          x: rnd(0, W), y: rnd(0, H),
          vx: rnd(-0.08, 0.08), vy: rnd(-0.08, 0.08),
          a: rnd(0.05, 0.35)
        });
      }
    }
    function spawnPackets() {
      packets.length = 0;
      for (var i = 0; i < PACK_MAX; i++) packets.push({ link: -1, t: 0, speed: rnd(0.004, 0.012) });
    }
    function pickLink(p) {
      if (!links.length) { p.link = -1; return; }
      p.link = Math.floor(Math.random() * links.length);
      p.t = 0;
    }

    resize();
    spawnNodes(); rebuildLinks(); spawnParticles(); spawnPackets();

    var running = true, last = performance.now();
    document.addEventListener("visibilitychange", function () {
      running = !document.hidden;
      if (running) { last = performance.now(); requestAnimationFrame(frame); }
    });

    function step(dt) {
      for (var i = 0; i < nodes.length; i++) {
        var n = nodes[i];
        n.x += n.vx * dt; n.y += n.vy * dt;
        if (n.x < -20) n.x = W + 20; if (n.x > W + 20) n.x = -20;
        if (n.y < -20) n.y = H + 20; if (n.y > H + 20) n.y = -20;
      }
      for (var k = 0; k < particles.length; k++) {
        var p = particles[k];
        p.x += p.vx * dt; p.y += p.vy * dt;
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
      ctx.closePath(); ctx.stroke();

      ctx.lineWidth = 0.6;
      for (var i = 0; i < links.length; i++) {
        var a = nodes[links[i][0]], b = nodes[links[i][1]];
        ctx.strokeStyle = "rgba(90,209,255,0.08)";
        ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
      }
      for (var q = 0; q < packets.length; q++) {
        var pk = packets[q];
        if (pk.link < 0) continue;
        var L = links[pk.link]; if (!L) continue;
        var na = nodes[L[0]], nb = nodes[L[1]];
        var x = na.x + (nb.x - na.x) * pk.t;
        var y = na.y + (nb.y - na.y) * pk.t;
        ctx.fillStyle = "rgba(140,230,255,0.9)";
        ctx.beginPath(); ctx.arc(x, y, 1.4, 0, Math.PI * 2); ctx.fill();
      }
      for (var r = 0; r < ripples.length; r++) {
        var rp = ripples[r]; var rr = rp.age * 1.4;
        ctx.strokeStyle = "rgba(90,209,255," + (0.22 * (1 - rp.age / 100)).toFixed(3) + ")";
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.arc(rp.x, rp.y, rr, 0, Math.PI * 2); ctx.stroke();
      }
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

      for (var i2 = 0; i2 < particles.length; i2++) {
        var p2 = particles[i2];
        ctx.fillStyle = "rgba(160,210,255," + p2.a.toFixed(3) + ")";
        ctx.fillRect(p2.x, p2.y, 1, 1);
      }

      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(radarAngle * 0.6);
      var sg = ctx.createRadialGradient(0, 0, 4, 0, 0, coreR);
      sg.addColorStop(0,   "rgba(90,209,255,0.35)");
      sg.addColorStop(0.6, "rgba(43,116,209,0.10)");
      sg.addColorStop(1,   "rgba(43,116,209,0)");
      ctx.fillStyle = sg;
      ctx.beginPath(); ctx.arc(0, 0, coreR, 0, Math.PI * 2); ctx.fill();
      ctx.strokeStyle = "rgba(90,209,255,0.55)";
      ctx.lineWidth = 1.2;
      for (var ring = 0; ring < 3; ring++) {
        var rr2 = coreR * (0.55 + ring * 0.22);
        ctx.beginPath(); ctx.arc(0, 0, rr2, 0, Math.PI * 1.35); ctx.stroke();
      }
      ctx.restore();
    }

    function frame(now) {
      if (!running) return;
      var dt = Math.min(2.5, (now - last) / 16.67);
      last = now;
      step(dt); draw();
      requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);

    var rt = null;
    window.addEventListener("resize", function () {
      if (rt) clearTimeout(rt);
      rt = setTimeout(function () {
        resize(); spawnNodes(); rebuildLinks(); spawnParticles(); spawnPackets();
      }, 180);
    }, { passive: true });
  }

  /* ---------- Show/hide passphrase toggle ----------
     The parent dashboard owns the login submit handler; we only wire the
     toggle. We do NOT attach a second submit handler, to avoid double login.
  ------------------------------------------------- */
  function wireToggle() {
    var tog = document.getElementById("pwToggle");
    var pw  = document.getElementById("liPass");
    if (!tog || !pw || tog.dataset.k360Wired === "1") return;
    tog.dataset.k360Wired = "1";
    tog.addEventListener("click", function (ev) {
      ev.preventDefault();
      var showing = pw.type === "text";
      pw.type = showing ? "password" : "text";
      tog.setAttribute("aria-pressed", String(!showing));
      tog.setAttribute("aria-label", showing ? "Show passphrase" : "Hide passphrase");
      pw.focus();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wireToggle);
  } else {
    wireToggle();
  }
})();
