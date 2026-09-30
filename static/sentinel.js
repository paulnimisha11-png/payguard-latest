/* The Sentinel: the hooded figure on the scanner's progress and result screens.
   Blue + scanning beam while a check runs, then red (scam), yellow (suspicious / be careful) or green (looks safe),
   with light rays bursting from behind his head. Used by app.js (show() and render()). */
(() => {
  "use strict";
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const STATES = {
    scan:   { a: "#2f8bff", b: "#7fc3ff", rgb: [47, 139, 255], eyes: 0.45, speed: 1.4 },
    danger: { a: "#ff1f3d", b: "#ff6b5a", rgb: [255, 31, 61], eyes: 1, speed: 2.2 },
    warn:   { a: "#ffb020", b: "#ffe07a", rgb: [255, 186, 32], eyes: 0.85, speed: 1.3 },
    safe:   { a: "#19e68c", b: "#7dffc4", rgb: [25, 230, 140], eyes: 0.3, speed: 0.6 },
  };
  const LEVEL = { danger: "danger", suspicious: "warn", caution: "warn", low: "safe" };
  const TEXT = {
    en: { scan: "ANALYSING…", danger: "SCAM DETECTED", warn: "SUSPICIOUS", caution: "BE CAREFUL", safe: "LOOKS SAFE",
          kick: "PAYGUARD VERDICT", kickScan: "SCANNING", risk: "risk" },
    hi: { scan: "जाँच हो रही है…", danger: "धोखा पकड़ा गया", warn: "संदिग्ध", caution: "सावधान रहें", safe: "सुरक्षित लगता है",
          kick: "PAYGUARD का फ़ैसला", kickScan: "स्कैन", risk: "जोखिम" },
    kn: { scan: "ಪರಿಶೀಲಿಸಲಾಗುತ್ತಿದೆ…", danger: "ಮೋಸ ಪತ್ತೆಯಾಗಿದೆ", warn: "ಅನುಮಾನಾಸ್ಪದ", caution: "ಎಚ್ಚರಿಕೆ", safe: "ಸುರಕ್ಷಿತವಾಗಿದೆ",
          kick: "PAYGUARD ತೀರ್ಪು", kickScan: "ಸ್ಕ್ಯಾನ್", risk: "ಅಪಾಯ" },
  };
  const KIND = { msg: "Message", qr: "QR / UPI", shot: "Payment screenshot", apk: "App file" };
  const lang = () => { const l = window.APKX && window.APKX.lang ? window.APKX.lang() : document.documentElement.lang; return TEXT[l] ? l : "en"; };
  const tx = k => TEXT[lang()][k] || TEXT.en[k];
  const GLY = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#$%&@";

  function decrypt(el, text, dur = 800) {
    el.setAttribute("aria-label", text);
    if (reduced || /[^\x00-\x7F]/.test(text)) { el.textContent = text; return; }   // Indian scripts: no scramble
    cancelAnimationFrame(el._r);
    const t0 = performance.now();
    const tick = now => {
      const k = Math.min(1, (now - t0) / dur), f = Math.floor(text.length * k);
      let s = "";
      for (let i = f; i < text.length; i++) s += text[i] === " " ? " " : GLY[(Math.random() * GLY.length) | 0];
      el.textContent = text.slice(0, f);
      if (s) { const sp = document.createElement("span"); sp.className = "scr"; sp.textContent = s; el.appendChild(sp); }
      if (k < 1) el._r = requestAnimationFrame(tick);
    };
    el._r = requestAnimationFrame(tick);
  }

  class Sentinel {
    constructor(el) {
      this.el = el;
      el.classList.add("sentinel");
      el.innerHTML = `
        <canvas class="sn-rays" aria-hidden="true"></canvas>
        <div class="sn-grid" aria-hidden="true"></div>
        <div class="sn-fig" aria-hidden="true"></div>
        <div class="sn-beam" aria-hidden="true"></div>
        <div class="sn-copy">
          <p class="sn-kick"><span class="sn-dot"></span><span class="sn-kick-t"></span></p>
          <h2 class="sn-title"></h2>
          <p class="sn-sub"></p>
        </div>
        <div class="sn-ring" aria-hidden="true"></div>`;
      this.fig = el.querySelector(".sn-fig");
      window.PGHood.mount(this.fig, {});
      this.cv = el.querySelector(".sn-rays");
      this.ctx = this.cv.getContext("2d");
      this.rays = [];
      this.col = STATES.scan.rgb.slice();
      this.target = STATES.scan;
      this.speed = 1;
      this.running = false;
      this.resize = this.resize.bind(this);
      addEventListener("resize", this.resize);
      new IntersectionObserver(es => es.forEach(e => (e.isIntersecting ? this.start() : this.stop()))).observe(el);
      document.addEventListener("visibilitychange", () => (document.hidden ? this.stop() : this.el.offsetParent && this.start()));
    }

    set(state, title, sub, kick) {
      const s = STATES[state] || STATES.scan;
      const prev = this.state;
      this.state = state; this.target = s;
      const el = this.el;
      el.dataset.state = state;
      el.style.setProperty("--rim-a", s.a);
      el.style.setProperty("--rim-b", s.b);
      el.style.setProperty("--eyes", s.eyes);
      el.style.setProperty("--sn", s.a);
      el.style.setProperty("--sn-rgb", s.rgb.join(","));
      el.querySelector(".sn-kick-t").textContent = kick;
      decrypt(el.querySelector(".sn-title"), title, state === "scan" ? 500 : 900);
      el.querySelector(".sn-sub").textContent = sub || "";
      if (prev !== state && state !== "scan") {
        el.classList.remove("hit"); void el.offsetWidth; el.classList.add("hit");   // one-shot entrance (flash / shake / ring)
        if (state === "danger" && navigator.vibrate) { try { navigator.vibrate([60, 40, 60]); } catch (e) { /* not allowed */ } }
      }
      if (reduced) { this.col = s.rgb.slice(); this.draw(performance.now(), true); }
      this.start();
    }

    resize() {
      const r = this.el.getBoundingClientRect();
      if (!r.width) return;
      const dpr = Math.min(devicePixelRatio || 1, 1.5);
      this.W = r.width; this.H = r.height;
      this.cv.width = r.width * dpr; this.cv.height = r.height * dpr;
      this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      // rays burst from just behind his head
      const f = this.fig.getBoundingClientRect();
      this.cx = f.left - r.left + f.width / 2;
      this.cy = f.top - r.top + f.height * 0.36;
      if (!this.rays.length) for (let i = 0; i < (r.width < 600 ? 90 : 150); i++) this.rays.push(this.spawn({}, true));
    }
    spawn(o, anywhere) {
      o.a = Math.random() * Math.PI * 2; o.d = anywhere ? Math.random() : Math.random() * 0.1;
      o.v = 0.4 + Math.random() * 0.8; o.w = 0.4 + Math.random() * 1.6; return o;
    }
    start() {
      if (this.running || !this.el.offsetParent) return;
      this.running = true; this.resize(); this.last = performance.now();
      const loop = t => { if (!this.running) return; this.draw(t); if (!reduced) requestAnimationFrame(loop); else this.running = false; };
      requestAnimationFrame(loop);
    }
    stop() { this.running = false; }
    draw(now, once) {
      if (!this.W) this.resize();
      const { ctx, W, H, cx, cy } = this;
      if (!W) return;
      const dt = once ? 1 : Math.min(50, now - this.last) / 16.67; this.last = now;
      const t = this.target;
      this.col = this.col.map((c, i) => c + (t.rgb[i] - c) * 0.06);
      this.speed += (t.speed - this.speed) * 0.05;
      const [r, g, b] = this.col.map(Math.round);
      ctx.globalCompositeOperation = "source-over";
      ctx.fillStyle = once ? "#040406" : "rgba(4,4,6,0.28)";
      ctx.fillRect(0, 0, W, H);
      const R = Math.hypot(W, H) * 0.75;
      const glow = ctx.createRadialGradient(cx, cy, 0, cx, cy, R * 0.45);
      const pulse = this.state === "danger" ? 0.22 + 0.08 * Math.sin(now / 180) : 0.2;
      glow.addColorStop(0, `rgba(${r},${g},${b},${pulse})`);
      glow.addColorStop(1, "rgba(0,0,0,0)");
      ctx.fillStyle = glow; ctx.fillRect(0, 0, W, H);
      ctx.globalCompositeOperation = "lighter";
      for (const o of this.rays) {
        const d0 = o.d;
        if (!once) o.d += 0.0032 * o.v * this.speed * dt * (0.35 + o.d * 2);
        if (o.d > 1.05) { this.spawn(o); continue; }
        const k = 1.5 * R;
        const x1 = cx + Math.cos(o.a) * o.d * o.d * k, y1 = cy + Math.sin(o.a) * o.d * o.d * k;
        const x0 = cx + Math.cos(o.a) * d0 * d0 * k, y0 = cy + Math.sin(o.a) * d0 * d0 * k;
        const tail = once ? 30 : 3 + this.speed * 4;
        const tx = once ? cx + Math.cos(o.a) * o.d * o.d * k * 0.6 : x1 - (x1 - x0) * tail;
        const ty = once ? cy + Math.sin(o.a) * o.d * o.d * k * 0.6 : y1 - (y1 - y0) * tail;
        ctx.strokeStyle = `rgba(${r},${g},${b},${Math.min(1, o.d * 1.5) * 0.8})`;
        ctx.lineWidth = o.w * (0.5 + o.d * 1.6);
        ctx.beginPath(); ctx.moveTo(tx, ty); ctx.lineTo(x1, y1); ctx.stroke();
      }
    }
  }

  let scanS = null, resultS = null;
  const api = {
    // called by app.js whenever the view changes
    view(v) {
      if (v === "progress") {
        const el = document.getElementById("sentinel-scan");
        if (!el) return;
        scanS = scanS || new Sentinel(el);
        scanS.set("scan", tx("scan"), "", tx("kickScan"));
      }
    },
    // called by app.js render() with the finished report
    verdict(r) {
      const el = document.getElementById("sentinel");
      if (!el || !r || !r.verdict) return;
      resultS = resultS || new Sentinel(el);
      const lvl = r.verdict.level;
      const state = LEVEL[lvl] || "warn";
      const title = lvl === "caution" ? tx("caution") : tx(state);
      const sub = `${KIND[r.kind] || "App file"} · ${tx("risk")} ${r.verdict.score}/100`;
      resultS.set(state, title, sub, tx("kick"));
    },
  };
  window.Sentinel = api;
})();
