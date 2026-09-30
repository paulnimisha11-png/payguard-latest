/* PayGuard access terminal: matrix rain, login/register/forgot/reset flows. */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const q = new URLSearchParams(location.search);
  const next = PG.safeNext(q.get("next")) || "/app";

  /* ------------------------------------------------------------------ red matrix rain */
  (() => {
    const cv = $("#rain"), ctx = cv.getContext("2d");
    const chars = "アイウエオカキクケコサシスセソタチツテトナニヌネノ0123456789₹UPI@#$%&*<>/\\{}".split("");
    const FS = 16;
    let W, H, cols, drops, speeds;
    const resize = () => {
      const dpr = Math.min(devicePixelRatio || 1, 1.5);
      W = innerWidth; H = innerHeight;
      cv.width = W * dpr; cv.height = H * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cols = Math.ceil(W / FS);
      drops = Array.from({ length: cols }, () => Math.random() * -H / FS);
      speeds = Array.from({ length: cols }, () => 0.35 + Math.random() * 0.75);
      ctx.fillStyle = "#050507"; ctx.fillRect(0, 0, W, H);
    };
    resize(); addEventListener("resize", resize);
    let last = 0, hot = 0;
    window.rainBurst = () => { hot = 1; };
    const draw = t => {
      requestAnimationFrame(draw);
      if (t - last < 42) return;          // ~24 fps is plenty and saves battery
      last = t;
      ctx.fillStyle = "rgba(5,5,7,0.12)";
      ctx.fillRect(0, 0, W, H);
      ctx.font = `600 ${FS - 2}px "JetBrains Mono", monospace`;
      hot *= 0.96;
      for (let i = 0; i < cols; i++) {
        const y = drops[i] * FS;
        const c = chars[(Math.random() * chars.length) | 0];
        ctx.fillStyle = Math.random() < 0.04 ? "#ffd6dc" : `rgba(255,${Math.round(31 + hot * 160)},${Math.round(61 + hot * 60)},${0.55 + Math.random() * 0.35})`;
        ctx.fillText(c, i * FS, y);
        drops[i] += speeds[i] * (1 + hot * 2);
        if (y > H && Math.random() > 0.975) drops[i] = Math.random() * -20;
      }
    };
    if (reduced) { ctx.fillStyle = "#050507"; ctx.fillRect(0, 0, W, H); }
    else requestAnimationFrame(draw);
  })();

  /* ------------------------------------------------------------------ title decrypt + status log */
  const GLY = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#$%&@";
  function decrypt(el, dur = 900) {
    const text = el.dataset.text;
    if (reduced) { el.textContent = text; return; }
    const t0 = performance.now();
    const tick = now => {
      const k = Math.min(1, (now - t0) / dur), n = Math.floor(text.length * k);
      let s = "";
      for (let i = n; i < text.length; i++) s += text[i] === " " ? " " : GLY[(Math.random() * GLY.length) | 0];
      el.textContent = text.slice(0, n);
      if (s) { const sp = document.createElement("span"); sp.className = "scr"; sp.textContent = s; el.appendChild(sp); }
      if (k < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }
  decrypt($("#term-title"));
  const logEl = $("#term-log");
  let logTimer;
  function log(msg) {
    clearInterval(logTimer);
    logEl.classList.toggle("bad", /denied/.test(msg));
    if (reduced) { logEl.textContent = msg; return; }
    let i = 0; logEl.textContent = "";
    logTimer = setInterval(() => { logEl.textContent = msg.slice(0, ++i); if (i >= msg.length) clearInterval(logTimer); }, 16);
  }

  /* ------------------------------------------------------------------ modes */
  const forms = { login: $("#f-login"), register: $("#f-register"), forgot: $("#f-forgot"), reset: $("#f-reset") };
  const tabs = $(".tabs");
  const LOG = {
    login: "> secure channel open. identify yourself.",
    register: "> new operator. create your credentials.",
    forgot: "> recovery mode. we'll email a one-time link.",
    reset: "> reset token accepted. choose a new password.",
  };
  let mode = null;
  function setMode(m, push = true) {
    if (m === mode) return;
    const order = ["login", "register"];
    const dir = order.indexOf(m) < order.indexOf(mode) ? -1 : 1;
    mode = m;
    Object.entries(forms).forEach(([k, f]) => { f.hidden = k !== m; if (k === m) f.style.setProperty("--from", (dir * 14) + "px"); });
    tabs.hidden = !(m === "login" || m === "register");
    tabs.classList.toggle("reg", m === "register");
    $$("[role=tab]", tabs).forEach(t => t.setAttribute("aria-selected", t.dataset.mode === m));
    $$(".err, .ok").forEach(e => { e.textContent = ""; });
    log(LOG[m]);
    if (push && (m === "login" || m === "register")) {
      const u = new URL(location.href);
      if (m === "register") u.searchParams.set("mode", "register"); else u.searchParams.delete("mode");
      history.replaceState(null, "", u);
    }
    const first = forms[m].querySelector("input");
    if (first && matchMedia("(hover: hover)").matches) setTimeout(() => first.focus(), 60);
  }
  $$("[role=tab]", tabs).forEach(t => t.addEventListener("click", () => setMode(t.dataset.mode)));
  tabs.addEventListener("keydown", e => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    const m = mode === "login" ? "register" : "login";
    setMode(m); $(`[data-mode="${m}"][role=tab]`).focus();
  });
  $$("[data-go]").forEach(b => b.addEventListener("click", () => {
    const m = b.dataset.go;
    if (m === "forgot") forms.forgot.email.value = forms.login.email.value;
    setMode(m);
  }));

  /* show / hide password */
  $$(".eye").forEach(b => b.addEventListener("click", () => {
    const inp = b.parentElement.querySelector("input");
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    b.textContent = show ? "HIDE" : "SHOW";
    b.setAttribute("aria-label", show ? "Hide password" : "Show password");
  }));

  /* password strength (a hint only; the server has the real rules) */
  function score(pw) {
    if (!pw) return 0;
    let s = 0;
    if (pw.length >= 8) s++;
    if (pw.length >= 12) s++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
    if (/\d/.test(pw) && /[^A-Za-z0-9]/.test(pw)) s++;
    if (/^(.)\1+$/.test(pw) || /password|qwerty|123456|payguard/i.test(pw)) s = 1;
    return Math.max(1, Math.min(4, s));
  }
  const LABEL = ["", "weak", "okay", "good", "strong"];
  $$("form").forEach(f => {
    const pw = f.querySelector('input[name="password"]'), bar = f.querySelector(".strength");
    if (!pw || !bar) return;
    pw.addEventListener("input", () => { const s = score(pw.value); bar.dataset.s = s; bar.querySelector("small").textContent = LABEL[s]; });
  });

  /* ------------------------------------------------------------------ submit helpers */
  const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  function fail(f, msg, field) {
    f.querySelector(".err").textContent = msg;
    $$("input", f).forEach(i => i.classList.remove("bad"));
    if (field && f[field]) { f[field].classList.add("bad"); f[field].focus(); }
    const t = $("#term");
    t.classList.remove("shake"); void t.offsetWidth; t.classList.add("shake");
    log("> access denied.");
  }
  async function run(f, fn) {
    const btn = f.querySelector(".submit");
    if (btn.classList.contains("busy")) return;
    f.querySelector(".err").textContent = "";
    btn.classList.add("busy"); btn.disabled = true;
    try { await fn(); } catch (e) { fail(f, e.message, e.field); }
    finally { btn.classList.remove("busy"); btn.disabled = false; }
  }
  function granted(user, sub) {
    $("#pane-forms").hidden = true;
    $("#granted").hidden = false;
    $("#term").classList.add("win");
    $("#granted-sub").textContent = sub || `Welcome, ${PG.first(user)}. Redirecting…`;
    log("> access granted.");
    decrypt($(".granted-text"), 700);
    if (window.rainBurst) window.rainBurst();
    setTimeout(() => { location.href = next; }, reduced ? 400 : 1500);
  }

  forms.login.addEventListener("submit", e => {
    e.preventDefault();
    const f = forms.login, email = f.email.value.trim(), password = f.password.value;
    if (!EMAIL.test(email)) return fail(f, "Enter a valid email address.", "email");
    if (!password) return fail(f, "Enter your password.", "password");
    log("> verifying credentials…");
    run(f, async () => { const d = await PG.api("/api/auth/login", "POST", { email, password }); granted(d.user); });
  });

  forms.register.addEventListener("submit", e => {
    e.preventDefault();
    const f = forms.register;
    const body = { name: f.name.value.trim(), email: f.email.value.trim(), password: f.password.value, lang: f.lang.value };
    if (!body.name) return fail(f, "Tell us your name.", "name");
    if (!EMAIL.test(body.email)) return fail(f, "Enter a valid email address.", "email");
    if (body.password.length < 8) return fail(f, "Use at least 8 characters.", "password");
    log("> provisioning your account…");
    run(f, async () => {
      const d = await PG.api("/api/auth/signup", "POST", body);
      granted(d.user, `Account created. Check ${d.user.email} to confirm it.`);
    });
  });

  forms.forgot.addEventListener("submit", e => {
    e.preventDefault();
    const f = forms.forgot, email = f.email.value.trim();
    if (!EMAIL.test(email)) return fail(f, "Enter a valid email address.", "email");
    run(f, async () => {
      const d = await PG.api("/api/auth/forgot", "POST", { email });
      f.querySelector(".ok").textContent = d.message;
      log("> if the account exists, the link is on its way.");
    });
  });

  forms.reset.addEventListener("submit", e => {
    e.preventDefault();
    const f = forms.reset;
    if (f.password.value.length < 8) return fail(f, "Use at least 8 characters.", "password");
    if (f.password.value !== f.password2.value) return fail(f, "The two passwords don't match.", "password2");
    run(f, async () => {
      const d = await PG.api("/api/auth/reset", "POST", { token: q.get("reset"), password: f.password.value });
      history.replaceState(null, "", "/login");
      granted(d.user, "Password changed. Other devices were signed out.");
    });
  });

  /* ------------------------------------------------------------------ start */
  if (q.get("reset")) setMode("reset", false);
  else setMode(q.get("mode") === "register" ? "register" : "login", false);

  if (!q.get("reset")) PG.me().then(({ user }) => {
    if (!user) return;
    $("#pane-forms").hidden = true;
    $("#pane-signed").hidden = false;
    $("#signed-name").textContent = user.name || PG.first(user);
    $("#signed-email").textContent = user.email;
    $("#pane-signed .btn-red").href = next;
    log("> session active on this device.");
  });
  $("#signed-out").addEventListener("click", async () => {
    try { await PG.api("/api/auth/logout", "POST", {}); } catch (e) { /* ignore */ }
    location.reload();
  });
})();
