/* PayGuard access terminal: matrix rain around Clerk's sign-in / sign-up form. */
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

  /* ------------------------------------------------------------------ Clerk's form, dressed for the terminal */
  const box = $("#clerk-box"), tabs = $(".tabs"), errEl = $("#auth-err");
  const LOG = {
    login: "> secure channel open. identify yourself.",
    register: "> new operator. create your credentials.",
  };
  const APPEARANCE = {
    variables: {
      colorPrimary: "#ff1f3d", colorPrimaryForeground: "#ffffff", colorBackground: "#0b0b10", colorForeground: "#eef0f6",
      colorMutedForeground: "#8d91a6", colorInput: "#050507", colorInputForeground: "#eef0f6", colorNeutral: "#ffffff",
      colorDanger: "#ff5468", colorSuccess: "#19e68c", borderRadius: "10px", fontFamily: '"Inter", system-ui, sans-serif',
    },
    elements: { rootBox: { width: "100%" }, cardBox: { width: "100%", boxShadow: "none" }, card: { boxShadow: "none" } },
  };
  function fail(msg) {
    errEl.textContent = msg;
    const t = $("#term");
    t.classList.remove("shake"); void t.offsetWidth; t.classList.add("shake");
    log("> access denied.");
  }

  let mode = null, mounted = null;
  async function setMode(m, push = true) {
    if (m === mode) return;
    mode = m;
    tabs.classList.toggle("reg", m === "register");
    $$("[role=tab]", tabs).forEach(t => t.setAttribute("aria-selected", t.dataset.mode === m));
    box.setAttribute("aria-labelledby", "tab-" + m);
    errEl.textContent = "";
    log(LOG[m]);
    if (push) {                                       // a fresh form: drop Clerk's step (#/factor-one…) from the address
      const u = new URL(location.href);
      if (m === "register") u.searchParams.set("mode", "register"); else u.searchParams.delete("mode");
      u.hash = "";
      history.replaceState(null, "", u);
    }
    const c = await PG.clerk();
    if (!c) return fail("Sign-in isn't available right now. Every scanner still works without an account.");
    if (m !== mode) return;                           // the other tab was clicked while Clerk was loading
    if (mounted === "login") c.unmountSignIn(box);
    if (mounted === "register") c.unmountSignUp(box);
    const here = "/login?next=" + encodeURIComponent(next);
    if (m === "register") c.mountSignUp(box, { appearance: APPEARANCE, routing: "hash", forceRedirectUrl: next, signInUrl: here, signInForceRedirectUrl: next });
    else c.mountSignIn(box, { appearance: APPEARANCE, routing: "hash", forceRedirectUrl: next, signUpUrl: here + "&mode=register", signUpForceRedirectUrl: next });
    mounted = m;
  }
  $$("[role=tab]", tabs).forEach(t => t.addEventListener("click", () => setMode(t.dataset.mode)));
  tabs.addEventListener("keydown", e => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    const m = mode === "login" ? "register" : "login";
    setMode(m); $(`[data-mode="${m}"][role=tab]`).focus();
  });

  /* ------------------------------------------------------------------ start */
  async function start() {
    // the "wasn't me" link from a sign-in alert email: sign the account out everywhere, then let the owner back in
    if (q.get("reset")) {
      try {
        await PG.api("/api/auth/lockout", "POST", { token: q.get("reset") });
        $("#auth-note").textContent = "Every device was signed out of your account. Sign in, then use \"Forgot password?\" to choose a new password.";
        log("> account locked down. all sessions ended.");
      } catch (e) { fail(e.status === 400 ? "This link has expired or was already used." : e.message); }
      history.replaceState(null, "", "/login");
    }
    const c = await PG.clerk();
    const { user } = await PG.me();
    if (user) {
      $("#pane-forms").hidden = true;
      $("#pane-signed").hidden = false;
      $("#signed-name").textContent = user.name || PG.first(user);
      $("#signed-email").textContent = user.email;
      $("#pane-signed .btn-red").href = next;
      log("> session active on this device.");
      return;
    }
    if (c && c.session) {                             // Clerk says signed in, PayGuard's server didn't accept it
      tabs.hidden = true;
      $("#pane-signed").hidden = false;
      $("#pane-signed .who-line").textContent = "You're signed in, but PayGuard couldn't confirm this session (unverified email, or the server is missing its Clerk keys). Sign out and try again.";
      $("#pane-signed .row-btns").hidden = true;
      return fail("Session not accepted.");
    }
    setMode(q.get("mode") === "register" ? "register" : "login", false);
  }
  start();
  $("#signed-out").addEventListener("click", () => PG.signOut("/login"));
})();
