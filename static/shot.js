/* Payment screenshot checker UI. Depends on window.APKX (app.js). */
(() => {
  const A = window.APKX;
  const $ = (s) => document.querySelector(s);
  const esc = A.esc;

  async function prepImage(file) {
    if (!file || !file.type.startsWith("image/") || file.size < 2 * 1024 * 1024) return file;
    try {
      const bmp = await createImageBitmap(file);
      const maxDim = 2048;
      if (bmp.width <= maxDim && bmp.height <= maxDim) return file;
      const scale = Math.min(maxDim / bmp.width, maxDim / bmp.height);
      const canvas = document.createElement("canvas");
      canvas.width = Math.round(bmp.width * scale);
      canvas.height = Math.round(bmp.height * scale);
      const ctx = canvas.getContext("2d");
      ctx.drawImage(bmp, 0, 0, canvas.width, canvas.height);
      const blob = await new Promise((res) => canvas.toBlob(res, "image/jpeg", 0.92));
      return new File([blob], file.name.replace(/\.[^.]+$/, ".jpg"), { type: "image/jpeg" });
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
        ${row("f_date", d.date, "date")}${row("f_payee", d.payee, "payee")}${row("f_app", d.app, "app")}
      </div>`;
  };
})();
