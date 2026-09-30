/* Shared account helpers: JSON API calls, the signed-in user, a toast, and the user menu on inner pages. */
(() => {
  "use strict";
  async function api(path, method = "GET", body) {
    const opt = { method, credentials: "same-origin", headers: {} };
    if (body !== undefined || (method !== "GET" && method !== "DELETE")) {
      opt.headers["Content-Type"] = "application/json";
      opt.body = JSON.stringify(body || {});
    }
    let r, data = {};
    try { r = await fetch(path, opt); } catch (e) { const err = new Error("No connection. Check your internet and try again."); err.status = 0; throw err; }
    try { data = await r.json(); } catch (e) { /* empty body */ }
    if (!r.ok) {
      const err = new Error(data.error || (r.status === 429 ? "Too many attempts. Wait a few minutes." : "Something went wrong. Try again."));
      err.status = r.status; err.field = data.field; err.data = data;
      throw err;
    }
    return data;
  }

  let mePromise = null;
  const me = (fresh) => {
    if (!mePromise || fresh) mePromise = api("/api/auth/me").catch(() => ({ user: null }));
    return mePromise;
  };

  let toastTimer;
  function toast(msg, kind = "") {
    let t = document.getElementById("cy-toast");
    if (!t) { t = document.createElement("div"); t.id = "cy-toast"; t.className = "cy-toast"; t.setAttribute("role", "status"); document.body.appendChild(t); }
    t.textContent = msg;
    t.className = "cy-toast show " + kind;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.className = "cy-toast " + kind; }, 3600);
  }

  // only same-site paths are allowed as a redirect target (no //evil.com, no javascript:)
  function safeNext(v) {
    if (!v || typeof v !== "string") return null;
    if (!v.startsWith("/") || v.startsWith("//") || v.startsWith("/\\")) return null;
    if (/^\/(api|login)(\/|\?|$)/.test(v)) return null;
    return v;
  }

  const initial = u => ((u.name || u.email || "?").trim()[0] || "?").toUpperCase();
  const first = u => (u.name || u.email).trim().split(/\s+/)[0].slice(0, 16);

  // <div data-usermenu></div> on any page becomes "Sign in" or an avatar dropdown
  async function mountUserMenu() {
    const slots = document.querySelectorAll("[data-usermenu]");
    if (!slots.length) return;
    const { user } = await me();
    slots.forEach(slot => {
      slot.textContent = "";
      if (!user) {
        const a = document.createElement("a");
        a.className = "btn-ghost signin-btn";
        a.href = "/login?next=" + encodeURIComponent(location.pathname + location.search);
        a.textContent = "Sign in";
        slot.appendChild(a);
        return;
      }
      slot.classList.add("umenu");
      const b = document.createElement("button");
      b.type = "button"; b.setAttribute("aria-haspopup", "menu"); b.setAttribute("aria-expanded", "false");
      const av = document.createElement("span"); av.className = "avatar"; av.textContent = initial(user);
      const nm = document.createElement("span"); nm.className = "uname"; nm.textContent = first(user);
      b.append(av, nm);
      const m = document.createElement("div"); m.className = "drop-menu"; m.setAttribute("role", "menu");
      const who = document.createElement("div"); who.className = "who";
      const wb = document.createElement("b"); wb.textContent = user.name || first(user);
      const ws = document.createElement("small"); ws.textContent = user.email;
      who.append(wb, ws);
      const link = (href, text) => { const a = document.createElement("a"); a.href = href; a.textContent = text; a.setAttribute("role", "menuitem"); return a; };
      const out = document.createElement("button"); out.type = "button"; out.className = "danger"; out.textContent = "Sign out"; out.setAttribute("role", "menuitem");
      out.onclick = async () => { try { await api("/api/auth/logout", "POST", {}); } catch (e) { /* already out */ } location.href = "/"; };
      m.append(who, link("/account", "My account"), link("/account#history", "My check history"), link("/app", "Scanner"), link("/family", "Family shield"), out);
      slot.append(b, m);
      b.onclick = e => { e.stopPropagation(); const o = slot.classList.toggle("open"); b.setAttribute("aria-expanded", o); };
      document.addEventListener("click", e => { if (!slot.contains(e.target)) { slot.classList.remove("open"); b.setAttribute("aria-expanded", "false"); } });
      document.addEventListener("keydown", e => { if (e.key === "Escape") { slot.classList.remove("open"); b.setAttribute("aria-expanded", "false"); } });
    });
  }

  // scanner page: a quiet line saying whether checks are being saved to the account
  async function mountStrip() {
    const el = document.getElementById("acct-strip");
    if (!el) return;
    const { user } = await me();
    el.textContent = "";
    const a = (href, text) => { const x = document.createElement("a"); x.href = href; x.textContent = text; return x; };
    if (user) {
      const b = document.createElement("b"); b.textContent = "● " + first(user);
      el.append(b, " · your checks are saved to ", a("/account#history", "your history"));
    } else {
      el.classList.add("anon");
      el.append("No account needed to check. ", a("/login?mode=register&next=%2Fapp", "Create one"), " to keep your history and get sign-in alerts.");
    }
    el.hidden = false;
  }

  window.PG = { api, me, toast, safeNext, mountUserMenu, initial, first };
  const boot = () => {
    mountUserMenu(); mountStrip();
    const v = new URLSearchParams(location.search).get("verified");
    if (v && location.pathname === "/app") {
      toast(v === "1" ? "Email confirmed. Thanks!" : "That confirmation link has expired or was already used.", v === "1" ? "ok" : "err");
      history.replaceState(null, "", "/app");
    }
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
