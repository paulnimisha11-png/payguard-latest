/* Payment screenshot checker UI. Depends on window.APKX (app.js). */
(() => {
  const A = window.APKX;
  const $ = (s) => document.querySelector(s);
  const esc = A.esc;

  async function prepImage(file) {
    if (!file || !file.type.startsWith("image/")) return file;
    // Keep screenshots under 5 MB untouched to preserve lossless text edges & pixel forensics!
    if (file.size <= 5 * 1024 * 1024) return file;
    try {
      const bmp = await createImageBitmap(file);
      const maxDim = 2400;
      if (bmp.width <= maxDim && bmp.height <= maxDim) return file;

      const scale = Math.min(maxDim / bmp.width, maxDim / bmp.height);
      const canvas = document.createElement("canvas");
      canvas.width = Math.round(bmp.width * scale);
      canvas.height = Math.round(bmp.height * scale);
      const ctx = canvas.getContext("2d");
      ctx.drawImage(bmp, 0, 0, canvas.width, canvas.height);
      const mime = file.type === "image/png" ? "image/png" : "image/jpeg";
      const blob = await new Promise((res) => canvas.toBlob(res, mime, 0.95));
      return new File([blob], file.name, { type: mime });
    } catch (_) {
      return file;
    }
  }

  async function send(file) {
    if (!file) return;
    $("#prog-file").textContent = file.name || "screenshot";
    $(".steps").hidden = true;
    $("#bar").style.width = "70%";
    A.show("progress");

    let uploadFile = file;
    try {
      uploadFile = await prepImage(file);
    } catch (_) {}

    const fd = new FormData();
    fd.append("file", uploadFile);
    fd.append("expected_amount", $("#shotexpect").value || "");
    fd.append("bank_sms", $("#shotsms").value || "");

    let res, data;
    try {
      res = await fetch("/api/screenshot", { method: "POST", body: fd });
    } catch (netErr) {
      console.error("Screenshot upload network error:", netErr);
      $(".steps").hidden = false;
      return A.fail("Network error: Could not reach the server. Please check your internet connection and try again.");
    }

    try {
      data = await res.json();
    } catch (_) {
      data = { detail: "Server returned invalid response (" + res.status + ")" };
    }

    $(".steps").hidden = false;
    if (!res.ok) {
      const msg = data.detail || data.error || ("Server error (" + res.status + ")");
      return A.fail(msg);
    }

    $("#bar").style.width = "100%";
    history.pushState({}, "", "/s/" + data.id);

    try {
      A.render(data);
      A.show("result");
    } catch (renderErr) {
      console.error("Screenshot render error:", renderErr);
      A.fail("Could not display results: " + (renderErr.message || renderErr));
    }
  }

  const drop = $("#shotdrop"), input = $("#shotfile");
  input.addEventListener("change", () => { if (input.files[0]) send(input.files[0]); input.value = ""; });
  drop.addEventListener("click", (e) => { if (e.target !== input) input.click(); });
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => e.dataTransfer.files[0] && send(e.dataTransfer.files[0]));
  document.addEventListener("paste", (e) => {
    if ($("#panel-shot").hidden || $("#home").hidden) return;
    const item = [...(e.clipboardData?.items || [])].find((i) => i.type.startsWith("image/"));
    if (item) { e.preventDefault(); send(item.getAsFile()); }
  });

  window.renderShotCard = (r) => {
    const d = r.details || {}, t = A.t;
    const findings = r.findings || [];
    const flagged = new Set(findings.filter((f) => f && f.box).map((f) => JSON.stringify(f.box)));
    const bad = { status: ["pending", "failed", "request"].includes(d.status) };
    findings.forEach((f) => {
      if (!f) return;
      const ev = Array.isArray(f.evidence) ? f.evidence.join(" ") : String(f.evidence || "");
      if (/AMOUNT/.test(f.id) || (f.id === "PATCHED_BACKGROUND" && /amount/.test(ev))) bad.amount = true;
      if (/UTR/.test(f.id)) bad.utr = true;
      if (/DATE|OLD_PAYMENT/.test(f.id)) bad.date = true;
    });
    const row = (k, v, key) => `<div class="readrow"><div class="k">${esc(t(k))}</div><div class="v ${v == null ? "missing" : bad[key] ? "bad" : ""}">${v == null ? esc(t("not_read")) : esc(v)}</div></div>`;
    const amt = d.amount != null ? "₹" + Number(d.amount).toLocaleString("en-IN", { maximumFractionDigits: 2 }) : null;
    $("#shotcard").innerHTML = `
      <figure><img src="${esc(r.annotated || "")}" alt="Uploaded screenshot with suspicious areas marked"><figcaption>${esc(t("shot_marked"))}</figcaption></figure>
      <div><h3>${esc(t("shot_read"))}</h3>
        ${row("f_status", d.status, "status")}${row("f_amount", amt, "amount")}${row("f_utr", d.utr, "utr")}
        ${row("f_date", d.date, "date")}${row("f_payee", d.payee, "payee")}${d.upi_id ? row("f_upi", d.upi_id, "upi") : ""}${row("f_app", d.app, "app")}
      </div>`;
    renderVerification(r);
  };

  // VERIFIED only with a trusted transaction source; SUSPICIOUS on tampering / inconsistency; otherwise UNVERIFIED.
  const V_LABEL = { VERIFIED: "Verified", SUSPICIOUS: "Suspicious", UNVERIFIED: "Unverified" };
  const V_SUB = {
    VERIFIED: "Confirmed by a trusted transaction source",
    SUSPICIOUS: "Signs of tampering or inconsistency",
    UNVERIFIED: "Looks consistent, but not confirmed. Check your own bank app",
  };
  const C_ICON = { pass: "✓", fail: "✗", warn: "!", skipped: "–" };
  function renderVerification(r) {
    const card = $("#verifycard");
    const v = r.verification;
    if (!v) { card.hidden = true; return; }
    card.hidden = false;
    const f = v.fields || {};
    const money = (x) => (x == null ? null : "₹" + Number(x).toLocaleString("en-IN", { maximumFractionDigits: 2 }));
    const rows = [["Amount", money(f.amount)], ["UPI ID", f.upi_id], ["Payee", f.payee_name], ["Transaction ID (UTR)", f.transaction_id],
      ["App transaction ID", f.app_transaction_id], ["Date & time", f.date_time], ["Status", f.status], ["App", f.app]]
      .filter(([k, val]) => val != null || ["Amount", "Transaction ID (UTR)", "Date & time", "Status"].includes(k));
    const qr = (f.qr || []).map((q) => `<div class="vf-qr"><b>QR / UPI code on the image</b> ${esc(q.payee_vpa || "?")}${q.amount != null ? " · " + esc(money(q.amount)) : ""}${q.valid ? "" : ` · <span class="bad">invalid format</span>`}</div>`).join("");
    const issues = (v.issues || []).filter((i) => i.severity !== "low" || i.category !== "quality");
    card.className = "card verifycard v-" + v.status.toLowerCase();
    card.innerHTML = `
      <div class="vf-head">
        <span class="vf-badge">${esc(V_LABEL[v.status] || v.status)}</span>
        <div><b>Payment verification: ${esc(v.status)}</b><small>${esc(V_SUB[v.status] || "")}</small></div>
      </div>
      <p class="vf-reason">${esc(v.reason)}</p>
      <div class="vf-grid">
        <div><h4>Extracted from the screenshot</h4>
          <dl class="vf-fields">${rows.map(([k, val]) => `<dt>${esc(k)}</dt><dd class="${val == null ? "missing" : ""}">${val == null ? "not found" : esc(val)}</dd>`).join("")}</dl>${qr}
        </div>
        <div><h4>Issues found (${issues.length})</h4>
          ${issues.length ? `<ul class="vf-issues">${issues.map((i) => `<li class="sev-${esc(i.severity)}"><span>${esc(i.category)}</span>${esc(i.title[A.lang()] || i.title.en)}</li>`).join("")}</ul>`
            : `<p class="dim">No tampering or inconsistency found.</p>`}
        </div>
      </div>
      <details class="vf-checks" ${v.status === "SUSPICIOUS" ? "" : "open"}><summary>Checks performed (${(v.checks || []).filter((c) => c.status !== "skipped").length} of ${(v.checks || []).length})</summary>
        <ul>${(v.checks || []).map((c) => `<li class="c-${esc(c.status)}"><i>${C_ICON[c.status] || "?"}</i><div><b>${esc(c.name)}</b><small>${esc(c.detail || "")}</small></div></li>`).join("")}</ul>
      </details>
      <p class="vf-note">${esc(v.note || "")}</p>`;
  }
})();
