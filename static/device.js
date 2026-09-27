/* This phone's PayGuard identity for family protection. Loaded before every other script.
   - Keeps { device_id, secret, token } in localStorage (no passwords, no phone number needed).
   - Adds the  x-pg-device  header to this site's /api/ calls, so a protected parent's risky checks alert
     their guardians from the server side (nothing to forget on the client).
   - Caches /api/family/me and shows the unread-alerts badge in the header. */
(() => {
  const KEY = "pg_device";
  // Inside the PayGuard Android app the page shares the app's identity (so family links cover the app's checks too).
  const bridge = window.PayGuardApp && typeof window.PayGuardApp.deviceToken === "function" ? window.PayGuardApp : null;
  if (bridge) {
    try { if (!localStorage.getItem("apkx_lang") && bridge.lang()) localStorage.setItem("apkx_lang", bridge.lang()); } catch (_) {}
  }
  const read = () => {
    if (bridge) { const tk = bridge.deviceToken(); return tk ? { token: tk, device_id: tk.split(".")[0] } : null; }
    try { return JSON.parse(localStorage.getItem(KEY) || "null"); } catch (_) { return null; }
  };
  const token = () => (read() || {}).token || "";
  const ua = navigator.userAgent || "";
  const platform = /android/i.test(ua) ? "android" : (/iphone|ipad|ipod/i.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) ? "ios" : "web";
  let fam = null;
  try { fam = JSON.parse(sessionStorage.getItem("pg_fam") || "null"); } catch (_) {}

  const nativeFetch = window.fetch.bind(window);
  window.fetch = (input, init = {}) => {
    const url = typeof input === "string" ? input : input.url;
    const tok = token();
    const sameApi = url.startsWith("/api/") || url.startsWith(location.origin + "/api/");
    if (tok && sameApi) {
      const h = new Headers(init.headers || (typeof input !== "string" ? input.headers : undefined) || {});
      if (!h.has("x-pg-device")) h.set("x-pg-device", tok);
      init = { ...init, headers: h };
    }
    return nativeFetch(input, init);
  };

  function lang() { try { return localStorage.getItem("apkx_lang") || "en"; } catch (_) { return "en"; } }

  async function ensure(name) {
    const have = read();
    if (have && have.token) {
      if (name) { try { await fetch("/api/family/device", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ name }) }); } catch (_) {} }
      return have;
    }
    if (bridge) throw new Error("The app couldn't reach the PayGuard server. Check the server address in Settings.");
    const res = await nativeFetch("/api/family/device", { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ name: name || "", platform, lang: lang() }) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Couldn't set up this phone.");
    try { localStorage.setItem(KEY, JSON.stringify(data)); } catch (_) { throw new Error("This browser blocks storage (private mode?). Open PayGuard normally."); }
    return data;
  }

  function badge() {
    const b = document.getElementById("fam-badge");
    if (!b) return;
    const n = (fam && fam.unread) || 0;
    b.hidden = n < 1;
    b.textContent = n > 9 ? "9+" : String(n);
  }

  async function refresh() {
    if (!token()) { fam = null; badge(); return null; }
    try {
      const res = await fetch("/api/family/me");
      if (res.status === 401) { forgetLocal(); return null; }
      if (res.ok) {
        fam = await res.json();
        try { sessionStorage.setItem("pg_fam", JSON.stringify(fam)); } catch (_) {}
      }
    } catch (_) { /* offline: keep the cached copy */ }
    badge();
    return fam;
  }

  function forgetLocal() {
    fam = null;
    if (bridge) { try { bridge.forget(); } catch (_) {} }
    try { localStorage.removeItem(KEY); sessionStorage.removeItem("pg_fam"); } catch (_) {}
    badge();
  }

  // Tell guardians when a protected person insists on paying a risky UPI ID (server re-checks it first).
  async function event(type, body) {
    if (!token() || !fam || !(fam.protected_by || []).length) return 0;
    try {
      const res = await fetch("/api/family/event", { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ type, ...body }) });
      return res.ok ? (await res.json()).alerted : 0;
    } catch (_) { return 0; }
  }

  window.PGDev = { token, ensure, refresh, family: () => fam, forgetLocal, event, platform, nativeFetch };
  badge();
  refresh();
  setInterval(() => { if (!document.hidden && token()) refresh(); }, 60000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden && token()) refresh(); });
})();
