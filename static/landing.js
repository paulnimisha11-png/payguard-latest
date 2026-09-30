/* PayGuard landing page: boot sequence, smooth scroll (Lenis), scroll-driven scenes, warp-speed light rays,
   decrypting headlines, magnetic buttons, tilt cards, live counters and sign-in state. No build step, no GSAP. */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));
  const smooth = (a, b, v) => { const t = clamp((v - a) / (b - a)); return t * t * (3 - 2 * t); };
  const lerp = (a, b, t) => a + (b - a) * t;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const touch = matchMedia("(hover: none)").matches;
  const store = (k, v) => { try { if (v === undefined) return sessionStorage.getItem(k); sessionStorage.setItem(k, v); } catch (e) { return null; } };

  /* ------------------------------------------------------------------ boot sequence */
  const boot = $("#boot");
  function runBoot() {
    return new Promise(done => {
      if (!boot) return done();
      if (reduced || store("pg-booted")) { boot.remove(); return done(); }
      document.body.classList.add("booting");
      const lines = [
        ["> payguard --watch", "hi"],
        ["  loading scam-script signatures (13 families) .......... ", "ok", "OK"],
        ["  loading UPI / QR lure rules ............................ ", "ok", "OK"],
        ["  arming screenshot forensics ............................ ", "ok", "OK"],
        ["  APK X-Ray: trojan permission patterns .................. ", "ok", "OK"],
        ["  intercept feed: 4 live threats near you", "warn"],
        ["> access granted.", "hi"],
      ];
      const box = $("#boot-lines"), bar = $(".boot-bar i");
      let i = 0, finished = false;
      const finish = () => {
        if (finished) return; finished = true;
        store("pg-booted", "1");
        boot.classList.add("done");
        document.body.classList.remove("booting");
        setTimeout(() => boot.remove(), 700);
        done();
      };
      boot.addEventListener("click", finish);
      addEventListener("keydown", finish, { once: true });
      const step = () => {
        if (finished) return;
        if (i >= lines.length) return setTimeout(finish, 380);
        const [text, cls, tail] = lines[i];
        const d = document.createElement("div");
        d.textContent = text;
        if (tail) { const s = document.createElement("span"); s.className = cls; s.textContent = tail; d.appendChild(s); }
        else d.className = cls;
        box.appendChild(d);
        i++;
        bar.style.width = (100 * i / lines.length) + "%";
        setTimeout(step, i === 1 ? 260 : 170 + Math.random() * 120);
      };
      setTimeout(step, 150);
    });
  }

  /* ------------------------------------------------------------------ decrypting text */
  const GLYPHS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#$%&@<>/\\{}[]=+*";
  const esc = s => s.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  function decrypt(el, dur = 1000) {
    const text = el.dataset.text || el.textContent;
    el.setAttribute("aria-label", text);
    if (reduced) { el.textContent = text; return; }
    if (el._dec) cancelAnimationFrame(el._dec);
    const t0 = performance.now();
    const tick = now => {
      const k = clamp((now - t0) / dur);
      const fixed = Math.floor(text.length * k);
      let out = esc(text.slice(0, fixed)), scr = "";
      for (let j = fixed; j < text.length; j++) scr += text[j] === " " ? " " : GLYPHS[(Math.random() * GLYPHS.length) | 0];
      el.innerHTML = out + (scr ? `<span class="scr">${esc(scr)}</span>` : "");
      if (k < 1) el._dec = requestAnimationFrame(tick);
    };
    el._dec = requestAnimationFrame(tick);
  }

  /* ------------------------------------------------------------------ typed intercepts */
  function typeInto(el) {
    const span = $("[data-type]", el);
    if (!span || el._typed) return;
    el._typed = true;
    const full = span.dataset.full || span.textContent;
    span.dataset.full = full;
    if (reduced) { el.classList.add("typed"); return; }
    span.textContent = "";
    let n = 0;
    const t = setInterval(() => {
      n += 2;
      span.textContent = full.slice(0, n);
      if (n >= full.length) { clearInterval(t); el.classList.add("typed"); }
    }, 18);
  }

  /* ------------------------------------------------------------------ warp: light rays rushing past */
  const warp = (() => {
    const cv = $("#warp");
    if (!cv) return { tick() {} };
    const ctx = cv.getContext("2d");
    let W = 0, H = 0, dpr = 1, rays = [];
    const N = touch ? 110 : 240;
    const spawn = r => {
      r.a = Math.random() * Math.PI * 2;
      r.d = Math.random() * 0.08 + 0.005;     // distance from the centre (0..1)
      r.v = Math.random() * 0.6 + 0.4;
      r.w = Math.random() * 1.4 + 0.3;
      r.hue = Math.random();
      return r;
    };
    const resize = () => {
      dpr = Math.min(devicePixelRatio || 1, touch ? 1.25 : 1.5);
      W = innerWidth; H = innerHeight;
      cv.width = W * dpr; cv.height = H * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    addEventListener("resize", resize);
    for (let i = 0; i < N; i++) { const r = spawn({}); r.d = Math.random(); rays.push(r); }
    let speed = 1, last = performance.now();
    return {
      // mood: 0 = calm blue, 1 = alarm red.  boost: extra speed from scrolling.
      tick(now, mood, boost, focusY, level = 1) {
        const dt = Math.min(50, now - last) / 16.67; last = now;
        speed = lerp(speed, 1 + boost, 0.08);
        const cx = W / 2, cy = H * focusY, R = Math.hypot(W, H) * 0.62;
        ctx.globalCompositeOperation = "source-over";
        ctx.fillStyle = "rgba(5,5,7,0.34)";
        ctx.fillRect(0, 0, W, H);
        // core glow
        const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, R * 0.55);
        const blueA = 0.16 * (1 - mood), redA = 0.16 * mood;
        g.addColorStop(0, `rgba(${Math.round(lerp(60, 255, mood))},${Math.round(lerp(140, 40, mood))},${Math.round(lerp(255, 70, mood))},${(0.1 + 0.08 * (blueA + redA) * 6) * level})`);
        g.addColorStop(1, "rgba(0,0,0,0)");
        ctx.fillStyle = g;
        ctx.fillRect(0, 0, W, H);
        ctx.globalCompositeOperation = "lighter";
        for (const r of rays) {
          const d0 = r.d;
          r.d += 0.0026 * r.v * speed * dt * (0.4 + r.d * 2.2);
          if (r.d > 1.05) { spawn(r); continue; }
          const x0 = cx + Math.cos(r.a) * d0 * d0 * R * 1.6, y0 = cy + Math.sin(r.a) * d0 * d0 * R * 1.6;
          const x1 = cx + Math.cos(r.a) * r.d * r.d * R * 1.6, y1 = cy + Math.sin(r.a) * r.d * r.d * R * 1.6;
          // tail length grows with speed
          const tx = x1 - (x1 - x0) * (3 + speed * 4), ty = y1 - (y1 - y0) * (3 + speed * 4);
          const m = clamp(mood + (r.hue - 0.5) * 0.5);
          const col = r.hue > 0.93 ? "25,230,140" : `${Math.round(lerp(70, 255, m))},${Math.round(lerp(150, 35, m))},${Math.round(lerp(255, 65, m))}`;
          const alpha = clamp(r.d * 1.4) * 0.85 * level;
          ctx.strokeStyle = `rgba(${col},${alpha})`;
          ctx.lineWidth = r.w * (0.5 + r.d * 1.8);
          ctx.beginPath(); ctx.moveTo(tx, ty); ctx.lineTo(x1, y1); ctx.stroke();
        }
      },
    };
  })();

  /* ------------------------------------------------------------------ smooth scrolling */
  let lenis = null;
  if (!reduced && window.Lenis) {
    lenis = new window.Lenis({ lerp: 0.085, smoothWheel: true, wheelMultiplier: 0.95, touchMultiplier: 1.4 });
  }
  $$('a[href^="#"]').forEach(a => a.addEventListener("click", e => {
    const t = $(a.getAttribute("href"));
    if (!t) return;
    e.preventDefault();
    if (lenis) lenis.scrollTo(t, { offset: -10, duration: 1.6 });
    else t.scrollIntoView({ behavior: reduced ? "auto" : "smooth" });
  }));

  /* ------------------------------------------------------------------ scenes */
  const hero = $("#hero"), scan = $("#scan"), nav = $("#lnav"), hood = $("#hood-wrap");
  if (hood && window.PGHood) window.PGHood.mount(hood, { laptop: true });
  const stages = $$(".hero-copy .stage");
  const icpts = $$(".icpt");
  const steps = $$("#scan [data-at]");
  $$(".steps li").forEach((li, i) => { li.dataset.n = "0" + (i + 1); });
  const stamp = $(".verdict-stamp"), meterNum = $(".meter-num"), meterBar = $(".meter-bar");
  let stage = -1;
  const progress = el => {
    const r = el.getBoundingClientRect();
    const span = r.height - innerHeight;
    return span > 0 ? clamp(-r.top / span) : clamp(1 - r.top / innerHeight);
  };
  const mouse = { x: 0.5, y: 0.5, sx: 0.5, sy: 0.5 };
  let lastY = scrollY, vel = 0, lastScrollDir = 0, warpFrames = 0;   // reduced motion: draw the rays once, then hold still

  function setStage(n) {
    if (n === stage) return;
    stage = n;
    stages.forEach(s => s.classList.toggle("on", +s.dataset.stage === n));
    const d = stages[n] && $(".decrypt", stages[n]);
    if (d) decrypt(d, n === 0 ? 1100 : 900);
  }

  function frame(now) {
    // scroll velocity for warp speed
    const y = scrollY;
    const dy = y - lastY; lastY = y;
    vel = lerp(vel, Math.abs(dy), 0.12);
    if (Math.abs(dy) > 2) lastScrollDir = Math.sign(dy);

    // nav
    nav.classList.toggle("scrolled", y > 40);
    nav.classList.toggle("hide", y > innerHeight * 1.2 && lastScrollDir > 0 && vel > 3);

    // hero
    const hp = progress(hero);
    hero.style.setProperty("--p", hp.toFixed(4));
    hero.classList.toggle("past-start", hp > 0.02);
    setStage(hp < 0.28 ? 0 : hp < 0.56 ? 1 : 2);
    mouse.sx = lerp(mouse.sx, mouse.x, 0.06); mouse.sy = lerp(mouse.sy, mouse.y, 0.06);
    if (hood) {
      const eyes = smooth(0.18, 0.42, hp) * (hp > 0.55 ? 0.35 + 0.65 * smooth(0.7, 0.85, hp) : 1);
      const redness = smooth(0.3, 0.62, hp);
      const blue = [47, 139, 255], blue2 = [127, 195, 255], red = [255, 31, 61], red2 = [255, 110, 90];
      const mix = (a, b) => `rgb(${a.map((v, i) => Math.round(lerp(v, b[i], redness))).join(",")})`;
      hood.style.setProperty("--rim-a", mix(blue, red));
      hood.style.setProperty("--rim-b", mix(blue2, red2));
      hood.style.setProperty("--eyes", eyes.toFixed(3));
      hood.style.setProperty("--hs", (0.9 + hp * 0.34).toFixed(4));
      hood.style.setProperty("--hy", (hp * 8).toFixed(2) + "vh");
      hood.style.setProperty("--hx", ((mouse.sx - 0.5) * -26).toFixed(1) + "px");
      hood.style.opacity = (1 - smooth(0.88, 1, hp) * 0.6).toFixed(3);
    }
    for (const el of icpts) {
      const at = +el.dataset.at;
      const on = hp >= at && hp < 0.6;
      el.classList.toggle("on", on);
      el.classList.toggle("gone", hp >= 0.6);
      if (on) typeInto(el);
    }
    document.documentElement.style.setProperty("--floor", (0.22 + smooth(0.3, 0.7, hp) * 0.35).toFixed(3));

    // scan demo
    if (scan) {
      const sp = progress(scan);
      scan.style.setProperty("--p", sp.toFixed(4));
      for (const el of steps) el.classList.toggle("on", sp >= +el.dataset.at);
      const risk = Math.round(smooth(0.3, 0.76, sp) * 94);
      if (meterBar) meterBar.style.setProperty("--risk", risk);
      if (meterNum) meterNum.textContent = risk;
      if (stamp) stamp.classList.toggle("on", sp >= 0.82);
    }

    // warp background: calm blue at the top, red once he's noticed you
    const docP = clamp(y / Math.max(1, document.documentElement.scrollHeight - innerHeight));
    const mood = Math.max(smooth(0.25, 0.6, hp), docP > 0.6 ? 0.55 : 0);
    // after the hero the rays calm down so the content stays readable
    const level = 1 - smooth(0.9, 1.25, hp + (hp >= 1 ? clamp((y - hero.offsetTop - hero.offsetHeight + innerHeight) / innerHeight) * 0.35 : 0)) * 0.72;
    if (!reduced || warpFrames++ < 45) warp.tick(now, mood, clamp(vel / 14, 0, 5) * level + hp * 0.8 * level, 0.42 + (mouse.sy - 0.5) * 0.06, level);

    requestAnimationFrame(frame);
  }

  /* ------------------------------------------------------------------ pointer effects */
  const spot = $(".spot");
  addEventListener("pointermove", e => {
    mouse.x = e.clientX / innerWidth; mouse.y = e.clientY / innerHeight;
    if (spot) { spot.style.setProperty("--mx", e.clientX + "px"); spot.style.setProperty("--my", e.clientY + "px"); }
  }, { passive: true });

  if (!touch && !reduced) {
    $$(".magnetic").forEach(b => {
      b.addEventListener("pointermove", e => {
        const r = b.getBoundingClientRect();
        b.style.setProperty("--bx", ((e.clientX - r.left - r.width / 2) * 0.25).toFixed(1) + "px");
        b.style.setProperty("--by", ((e.clientY - r.top - r.height / 2) * 0.35).toFixed(1) + "px");
      });
      b.addEventListener("pointerleave", () => { b.style.setProperty("--bx", "0px"); b.style.setProperty("--by", "0px"); });
    });
    $$(".card3d").forEach(c => {
      c.addEventListener("pointermove", e => {
        const r = c.getBoundingClientRect();
        const px = (e.clientX - r.left) / r.width, py = (e.clientY - r.top) / r.height;
        c.style.setProperty("--rx", ((px - 0.5) * 14).toFixed(2) + "deg");
        c.style.setProperty("--ry", ((0.5 - py) * 12).toFixed(2) + "deg");
        c.style.setProperty("--cx", (px * 100).toFixed(1) + "%");
        c.style.setProperty("--cy", (py * 100).toFixed(1) + "%");
      });
      c.addEventListener("pointerleave", () => { c.style.setProperty("--rx", "0deg"); c.style.setProperty("--ry", "0deg"); });
    });
  }

  /* ------------------------------------------------------------------ reveal + counters */
  $$(".live-row, .fam-visual, .fam-copy, .final > *, .arsenal > .kicker, .arsenal > .h2").forEach(el => el.classList.add("rv"));
  const io = new IntersectionObserver(entries => {
    for (const en of entries) {
      if (!en.isIntersecting) continue;
      const el = en.target;
      if (el.classList.contains("card3d")) {
        const i = $$(".card3d").indexOf(el);
        setTimeout(() => el.classList.add("in"), (i % 3) * 110);
      } else el.classList.add("in");
      if (el.classList.contains("live-row")) countUp();
      io.unobserve(el);
    }
  }, { threshold: 0.15, rootMargin: "0px 0px -8% 0px" });
  $$(".rv, .card3d").forEach(el => io.observe(el));

  let counts = null, counted = false;
  fetch("/api/trends").then(r => r.ok ? r.json() : null).then(d => {
    if (!d || !d.totals) return;
    counts = { checks: d.totals.checks_7d, threats: d.totals.threats_7d, reports: d.totals.reports_7d };
    if ($(".live-row.in")) countUp();
  }).catch(() => {});
  function countUp() {
    if (!counts || counted) return;
    counted = true;
    $$("[data-count]").forEach(el => {
      const target = counts[el.dataset.count] || 0;
      if (reduced) { el.textContent = target.toLocaleString("en-IN"); return; }
      const t0 = performance.now(), dur = 1600;
      const tick = now => {
        const k = clamp((now - t0) / dur), e = 1 - Math.pow(1 - k, 4);
        el.textContent = Math.round(target * e).toLocaleString("en-IN");
        if (k < 1) requestAnimationFrame(tick);
      };
      requestAnimationFrame(tick);
    });
  }

  /* ------------------------------------------------------------------ signed-in state */
  if (window.PG && PG.hinted()) PG.me().then(d => {     // Clerk is only loaded here for browsers that signed in before
    const u = d && d.user;
    if (!u) return;
    const a = $("#nav-signin");
    const first = (u.name || u.email).trim().split(/\s+/)[0];
    a.href = "/account";
    a.textContent = "";
    const av = document.createElement("span"); av.className = "avatar"; av.textContent = first[0].toUpperCase();
    a.append(av, document.createTextNode(" " + first.slice(0, 14)));
    $$('a[href="/login?mode=register"]').forEach(x => { x.href = "/account"; x.textContent = "My account"; });
  }).catch(() => {});

  /* ------------------------------------------------------------------ go */
  if (lenis) {
    const raf = t => { lenis.raf(t); requestAnimationFrame(raf); };
    requestAnimationFrame(raf);
  }
  runBoot().then(() => {
    if (location.hash && $(location.hash)) setTimeout(() => (lenis ? lenis.scrollTo($(location.hash), { immediate: true }) : $(location.hash).scrollIntoView()), 50);
  });
  requestAnimationFrame(frame);
})();
