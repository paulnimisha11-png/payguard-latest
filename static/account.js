/* PayGuard account page: profile, password, devices, history, delete. */
(() => {
  "use strict";
  const $ = (s, r = document) => r.querySelector(s);
  const { api, toast } = PG;
  const KIND = { msg: ["💬", "Message"], qr: ["🔳", "QR / UPI"], shot: ["🧾", "Payment screenshot"], apk: ["📦", "App file"] };
  const LEVEL = { danger: "Scam", suspicious: "Suspicious", caution: "Careful", low: "Looks safe" };

  const fmtDate = s => new Date(s * 1000).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" });
  function ago(s) {
    const d = Date.now() / 1000 - s;
    if (d < 60) return "just now";
    if (d < 3600) return Math.floor(d / 60) + " min ago";
    if (d < 86400) return Math.floor(d / 3600) + " h ago";
    if (d < 86400 * 7) return Math.floor(d / 86400) + " d ago";
    return fmtDate(s);
  }
  function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function countTo(node, n) {
    const t0 = performance.now(), from = +node.textContent || 0;
    const tick = now => { const k = Math.min(1, (now - t0) / 900); node.textContent = Math.round(from + (n - from) * (1 - Math.pow(1 - k, 3))); if (k < 1) requestAnimationFrame(tick); };
    requestAnimationFrame(tick);
  }
  async function busy(btn, fn) {
    if (btn.disabled) return;
    btn.disabled = true;
    try { await fn(); } finally { btn.disabled = false; }
  }
  const formErr = (f, msg) => { const p = f.parentElement.querySelector(".ferr") || f.querySelector(".ferr"); if (p) p.textContent = msg || ""; };

  /* ------------------------------------------------------------------ identity */
  function paint(user, stats) {
    $("#id-av").textContent = PG.initial(user);
    $("#id-name").textContent = user.name || PG.first(user);
    $("#id-email").textContent = user.email;
    const v = $("#id-verified");
    v.className = "badge-v " + (user.email_verified ? "ok" : "no");
    v.textContent = user.email_verified ? "✔ confirmed" : "unconfirmed";
    $("#verify-note").hidden = !!user.email_verified;
    $("#id-since").textContent = "Member since " + fmtDate(user.created) + (user.last_login ? " · last sign-in " + ago(user.last_login) : "");
    if (stats) { countTo($("#st-checks"), stats.checks); countTo($("#st-threats"), stats.threats); }
    const f = $("#f-profile");
    f.name.value = user.name || "";
    f.phone.value = user.phone || "";
    f.lang.value = user.lang || "en";
    f.login_alerts.checked = !!user.login_alerts;
  }

  /* ------------------------------------------------------------------ devices */
  function deviceIcon(d) {
    return /Android|iPhone|iPad|app/i.test(d || "") ? "📱" : "💻";
  }
  async function loadDevices() {
    const { sessions } = await api("/api/auth/sessions");
    countTo($("#st-devices"), sessions.length);
    const ul = $("#devices");
    ul.textContent = "";
    sessions.forEach((s, i) => {
      const li = el("li", s.current ? "cur" : "");
      li.style.animationDelay = (i * 0.05) + "s";
      const meta = el("div", "dmeta");
      const b = el("b", "", s.device || "Unknown device");
      if (s.current) b.appendChild(el("span", "you", "THIS DEVICE"));
      meta.append(b, el("small", "", `network ${s.network} · active ${ago(s.last_seen)} · since ${fmtDate(s.created)}`));
      li.append(el("span", "dic", deviceIcon(s.device)), meta);
      if (!s.current) {
        const out = el("button", "btn-ghost small", "Sign out");
        out.type = "button";
        out.onclick = () => busy(out, async () => {
          await api("/api/auth/sessions/" + s.id, "DELETE");
          toast("That device is signed out.", "ok");
          loadDevices();
        });
        li.appendChild(out);
      }
      ul.appendChild(li);
    });
  }

  /* ------------------------------------------------------------------ history */
  async function loadHistory() {
    const { history, stats } = await api("/api/me/history?limit=100");
    countTo($("#st-checks"), stats.checks); countTo($("#st-threats"), stats.threats);
    const ul = $("#hist");
    ul.textContent = "";
    $("#hist-empty").hidden = history.length > 0;
    $("#clear-hist").hidden = history.length === 0;
    history.forEach((h, i) => {
      const li = el("li");
      li.dataset.level = h.level;
      li.style.animationDelay = Math.min(i, 12) * 0.03 + "s";
      const [icon, kindName] = KIND[h.kind] || ["🔎", h.kind];
      const t = el("div", "ht");
      const title = el("b", "", h.title || kindName);
      if (h.link) { const a = el("a"); a.href = h.link; a.appendChild(title); t.appendChild(a); } else t.appendChild(title);
      t.appendChild(el("small", "", [kindName, h.label, ago(h.created)].filter(Boolean).join(" · ")));
      li.append(el("span", "hk", icon), t, el("span", "lv", LEVEL[h.level] || h.level));
      ul.appendChild(li);
    });
  }

  /* ------------------------------------------------------------------ forms */
  $("#f-profile").addEventListener("submit", e => {
    e.preventDefault();
    const f = e.target, btn = f.querySelector("button[type=submit]");
    formErr(f, "");
    f.querySelectorAll(".bad").forEach(x => x.classList.remove("bad"));
    busy(btn, async () => {
      try {
        const { user } = await api("/api/auth/me", "PATCH", {
          name: f.name.value.trim(), phone: f.phone.value.trim(), lang: f.lang.value, login_alerts: f.login_alerts.checked,
        });
        PG.me(true);
        paint(user);
        toast("Saved.", "ok");
      } catch (err) {
        formErr(f, err.message);
        if (err.field && f[err.field]) f[err.field].classList.add("bad");
      }
    });
  });

  $("#f-pass").addEventListener("submit", e => {
    e.preventDefault();
    const f = e.target, btn = f.querySelector("button[type=submit]");
    formErr(f, "");
    if (f.new.value.length < 8) return formErr(f, "Use at least 8 characters.");
    busy(btn, async () => {
      try {
        await api("/api/auth/password", "POST", { current: f.current.value, new: f.new.value });
        f.reset();
        toast("Password changed. We've emailed you a notice.", "ok");
      } catch (err) { formErr(f, err.message); }
    });
  });

  $("#resend").addEventListener("click", e => busy(e.target, async () => {
    try {
      const { sent } = await api("/api/auth/verify/resend", "POST", {});
      toast(sent ? "Link sent. Check your inbox (and spam)." : "Your email is already confirmed.", "ok");
    } catch (err) { toast(err.message, "err"); }
  }));

  $("#clear-hist").addEventListener("click", e => {
    if (!confirm("Clear your whole check history?")) return;
    busy(e.target, async () => { await api("/api/me/history", "DELETE"); toast("History cleared.", "ok"); loadHistory(); });
  });

  $("#logout-all").addEventListener("click", e => {
    if (!confirm("Sign out on every device, including this one?")) return;
    busy(e.target, async () => { await api("/api/auth/logout-all", "POST", {}); location.href = "/login"; });
  });

  $("#logout").addEventListener("click", e => busy(e.target, async () => {
    try { await api("/api/auth/logout", "POST", {}); } catch (err) { /* already signed out */ }
    location.href = "/";
  }));

  $("#f-del").addEventListener("submit", e => {
    e.preventDefault();
    const f = e.target, btn = f.querySelector("button");
    const errP = f.parentElement.querySelector(".ferr");
    errP.textContent = "";
    if (!f.password.value) return (errP.textContent = "Enter your password to confirm.");
    if (!confirm("Delete your PayGuard account for good? This can't be undone.")) return;
    busy(btn, async () => {
      try { await api("/api/auth/delete", "POST", { password: f.password.value }); location.href = "/?deleted=1"; }
      catch (err) { errP.textContent = err.message; }
    });
  });

  /* ------------------------------------------------------------------ start */
  PG.me().then(d => {
    if (!d.user) { location.replace("/login?next=" + encodeURIComponent("/account" + location.hash)); return; }
    $("#acct").hidden = false;
    paint(d.user, d.stats);
    const q = new URLSearchParams(location.search);
    if (q.get("verified") === "1") toast("Email confirmed. Thanks!", "ok");
    Promise.all([loadDevices(), loadHistory()]).then(() => {
      if (location.hash === "#history") $("#history").scrollIntoView({ behavior: "smooth", block: "start" });
    }).catch(err => toast(err.message, "err"));
  });
})();
