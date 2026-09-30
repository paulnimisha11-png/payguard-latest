/* Scam message checker UI (SMS / WhatsApp / email). Depends on window.APKX (app.js).
   Text shared to the installed app (Android "Share → PayGuard") arrives as ?share_text=… and is checked at once. */
(() => {
  const A = window.APKX;
  const $ = (s) => document.querySelector(s);
  const esc = A.esc;
  const EXAMPLE = "Dear Consumer, your electricity power will be disconnected tonight at 9.30pm because your previous month bill was not updated. Please contact our electricity officer immediately 9876543210. Thank you";

  async function check(text) {
    text = (text || "").trim();
    if (!text) { $("#msgtext").focus(); return; }
    $("#prog-file").textContent = text.slice(0, 60) + (text.length > 60 ? "…" : "");
    $(".steps").hidden = true;
    $("#bar").style.width = "70%";
    A.show("progress");
    try {
      const res = await fetch("/api/message", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text }) });
      let data;
      try { data = await res.json(); } catch (_) { data = { error: "Server error (" + res.status + ")" }; }
      $(".steps").hidden = false;
      if (!res.ok) return A.fail(data.error || "Error " + res.status);
      $("#bar").style.width = "100%";
      A.render(data);
      A.show("result");
    } catch (_) { $(".steps").hidden = false; A.fail("Network error — is the server running?"); }
  }

  $("#msgform").addEventListener("submit", (e) => { e.preventDefault(); check($("#msgtext").value); });
  $("#msg-example").addEventListener("click", () => { $("#msgtext").value = EXAMPLE; $("#msgtext").focus(); });
  $("#msg-paste").addEventListener("click", async () => {
    try {
      const txt = await navigator.clipboard.readText();
      if (txt) { $("#msgtext").value = txt; check(txt); return; }
    } catch (_) { /* iOS/Firefox may refuse: fall back to manual paste */ }
    A.toast(A.t("paste_denied"));
    $("#msgtext").focus();
  });

  // Android share sheet → installed web app, or links like /?mode=msg&text=…
  const q = new URLSearchParams(location.search);
  const shared = [q.get("share_title"), q.get("share_text") || q.get("text"), q.get("share_url")].filter(Boolean).join("\n").trim();
  if (shared) {
    $("#msgtext").value = shared;
    history.replaceState({}, "", "/app?mode=msg" + (q.get("report") ? "&report=" + encodeURIComponent(q.get("report")) : ""));
    setTimeout(() => check(shared), 50);
  }

  const KIND_CLASS = { danger: "hl-danger", pressure: "hl-pressure", topic: "hl-topic", link: "hl-link", upi: "hl-link", phone: "hl-link" };

  function highlighted(text, spans) {
    let out = "", at = 0;
    (spans || []).forEach((s) => {
      if (s.start < at) return;
      out += esc(text.slice(at, s.start)) + `<mark class="${KIND_CLASS[s.kind] || "hl-topic"}">${esc(text.slice(s.start, s.end))}</mark>`;
      at = s.end;
    });
    return out + esc(text.slice(at));
  }

  window.renderMsgCard = (r) => {
    const d = r.details, t = A.t, L = A.lang();
    const asks = d.asks || [];
    const rows = [];
    (d.links || []).forEach((l) => rows.push(`<li><span class="ek">${esc(t("l_link"))}</span><span class="mono">${esc(l.url)}</span>
      <span class="tag ${l.official ? "ok" : l.level === "danger" || l.level === "suspicious" ? "bad" : "meh"}">${esc(l.official ? t("l_official") : t("l_notofficial"))}</span></li>`));
    (d.upi_ids || []).forEach((u) => rows.push(`<li><span class="ek">${esc(t("l_upi"))}</span><span class="mono">${esc(u)}</span></li>`));
    (d.phones || []).forEach((p) => rows.push(`<li><span class="ek">${esc(t("l_phone"))}</span><span class="mono">${esc(p)}</span></li>`));
    (d.tollfree || []).forEach((p) => rows.push(`<li><span class="ek">${esc(t("l_tollfree"))}</span><span class="mono">${esc(p)}</span></li>`));
    const risky = r.verdict.level !== "low";
    $("#msgcard").innerHTML = `
      ${asks.length ? `<h3>${esc(t("msg_asks"))}</h3><ul class="asks">${asks.map((a) => `<li class="ask ${risky ? "bad" : ""}">${esc(a.label[L] || a.label.en)}</li>`).join("")}</ul>` : ""}
      <h3>${esc(t("msg_res"))}</h3>
      <blockquote class="msgtext" lang="">${highlighted(r.payload, d.highlights)}</blockquote>
      ${(d.highlights || []).some((h) => h.kind === "danger" || h.kind === "pressure") ? `<p class="dim small">${esc(t("msg_marked"))}</p>` : ""}
      ${rows.length ? `<h3>${esc(t("msg_found"))}</h3><ul class="ents">${rows.join("")}</ul>` : ""}`;
  };
})();
