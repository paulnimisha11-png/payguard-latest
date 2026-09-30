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
      const res = await fetch("/api/message", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text, sender: ($("#msgsender").value || "").trim() || null, use_ai: $("#msgai").checked, source: "web" }) });
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

  // ---- the layered result: risk level, factors, sender, links, Scam Memory, threat intel, AI, safe actions, layers
  const RISK_TEXT = { HIGH: "HIGH RISK", MEDIUM: "MEDIUM RISK", LOW: "LOW RISK — be careful", MINIMAL: "NO SCAM SIGNS FOUND" };
  const LAYER_NAME = { rules: "Message rules", urls: "Link analysis", sender: "Sender check", memory: "Scam Memory",
    threat_intel: "Threat intelligence", ai: "AI reading (Gemini Flash)" };
  const ST = { ok: ["✓", "c-pass"], not_needed: ["–", "c-skipped"], skipped: ["–", "c-skipped"], not_provided: ["–", "c-skipped"],
    disabled: ["○", "c-skipped"], timeout: ["!", "c-warn"], error: ["!", "c-warn"] };
  const LAYER_LABEL = { rules: "rules", url: "link", sender: "sender", memory: "Scam Memory", threat_intel: "threat intel", ai: "AI" };

  function renderRisk(r) {
    const k = r.risk, d = r.details, L = A.lang(), card = $("#riskcard");
    if (!k) { card.hidden = true; return; }
    const tr = (o) => (o && (o[L] || o.en)) || "";
    const lay = k.layers || {};
    const s = d.sender || {};
    const senderTxt = s.raw ? `${s.raw} · ${(lay.sender || {}).detail || ""}${s.org ? " (" + s.org.toUpperCase() + ")" : ""}` : "Not provided";
    const links = (d.links || []).map((l) => `<li><span class="mono">${esc(l.host || l.domain)}</span>${l.path && l.path !== "/" ? `<span class="mono dim">${esc(l.path.slice(0, 40))}</span>` : ""}
      <span class="tag ${l.official ? "ok" : (l.heuristics || []).length || l.level === "danger" || l.level === "suspicious" ? "bad" : "meh"}">${l.official ? "official" : l.shortener ? "short link" : l.is_ip ? "IP address" : "not official"}</span></li>`).join("");
    const mem = (r.sms || {}).memory || { matches: [] };
    const memTxt = (mem.matches || []).length
      ? mem.matches.slice(0, 3).map((m) => `${esc(m.label)} <span class="mono">${esc(m.value)}</span>: ${m.reports} report${m.reports === 1 ? "" : "s"}${m.disputed ? " (disputed)" : ""}`).join("<br>")
      : esc((lay.memory || {}).detail || "No reports found");
    const ti = lay.threat_intel || {};
    const ai = r.ai;
    const aiTxt = ai ? `<p class="rk-ai"><b>AI (${esc(ai.risk_level.toLowerCase())} risk${ai.cached ? ", cached" : ""}):</b> ${esc(ai.reason)}</p>`
      : `<p class="rk-ai dim">AI reading: ${esc((lay.ai || {}).detail || "not used")}</p>`;
    card.className = "card riskcard rk-" + k.level.toLowerCase();
    card.innerHTML = `
      <div class="rk-head"><span class="rk-badge">${esc(RISK_TEXT[k.level] || k.level)}</span>
        <span class="rk-score" title="${esc(k.score_note)}">${k.score}/100 risk points <small>(not a probability)</small></span></div>
      ${k.factors.length ? `<ul class="rk-factors">${k.factors.slice(0, 8).map((f) => `<li class="sev-${f.severity}"><span>${esc(tr(f.title))}</span><em>${esc(LAYER_LABEL[f.layer] || f.layer)}</em></li>`).join("")}</ul>`
        : `<p class="dim">No risk factors found by any layer.</p>`}
      ${aiTxt}
      <dl class="rk-facts">
        <dt>Sender</dt><dd>${esc(senderTxt)}</dd>
        <dt>Links</dt><dd>${links ? `<ul class="rk-links">${links}</ul>` : "None"}</dd>
        <dt>Scam Memory</dt><dd>${memTxt}</dd>
        <dt>${esc(ti.service || "Threat intelligence")}</dt><dd>${esc(ti.detail || "")}</dd>
      </dl>
      <h4>What to do</h4><ul class="rk-safe">${k.safe_actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ul>
      <details class="rk-layers"><summary>How this was checked (${Object.keys(lay).length} layers)</summary>
        <ul>${Object.entries(lay).map(([id, x]) => { const [ic, cls] = ST[x.status] || ["?", "c-skipped"];
          return `<li class="${cls}"><span class="ic">${ic}</span><b>${esc(LAYER_NAME[id] || id)}</b> <span class="dim">${esc(x.detail || x.status)}</span></li>`; }).join("")}</ul>
        <p class="dim small">Score = weighted evidence from all layers; the AI can add at most 25 points, can't lower a score and can't make a message HIGH risk on its own.</p>
      </details>`;
  }

  window.renderMsgCard = (r) => {
    renderRisk(r);
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
