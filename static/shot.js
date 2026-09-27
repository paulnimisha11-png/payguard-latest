/* Payment screenshot checker UI. Depends on window.APKX (app.js). */
(() => {
  const A = window.APKX;
  const $ = (s) => document.querySelector(s);
  const esc = A.esc;

  async function send(file) {
    $("#prog-file").textContent = file.name || "screenshot";
    $(".steps").hidden = true;
    $("#bar").style.width = "70%";
    A.show("progress");
    const fd = new FormData();
    fd.append("file", file);
    fd.append("expected_amount", $("#shotexpect").value || "");
    fd.append("bank_sms", $("#shotsms").value || "");
    try {
      const res = await fetch("/api/screenshot", { method: "POST", body: fd });
      let data;
      try { data = await res.json(); } catch (_) { data = { error: "Server error (" + res.status + ")" }; }
      $(".steps").hidden = false;
      if (!res.ok) return A.fail(data.error || "Error " + res.status);
      $("#bar").style.width = "100%";
      history.pushState({}, "", "/s/" + data.id);
      A.render(data);
      A.show("result");
    } catch (_) { $(".steps").hidden = false; A.fail("Network error — is the server running?"); }
  }

  const drop = $("#shotdrop"), input = $("#shotfile");
  input.addEventListener("change", () => { if (input.files[0]) send(input.files[0]); input.value = ""; });
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
    const d = r.details, t = A.t;
    const flagged = new Set(r.findings.filter((f) => f.box).map((f) => JSON.stringify(f.box)));
    const bad = { status: ["pending", "failed", "request"].includes(d.status) };
    r.findings.forEach((f) => {
      if (/AMOUNT/.test(f.id) || (f.id === "PATCHED_BACKGROUND" && /amount/.test(f.evidence.join(" ")))) bad.amount = true;
      if (/UTR/.test(f.id)) bad.utr = true;
      if (/DATE|OLD_PAYMENT/.test(f.id)) bad.date = true;
    });
    const row = (k, v, key) => `<div class="readrow"><div class="k">${esc(t(k))}</div><div class="v ${v == null ? "missing" : bad[key] ? "bad" : ""}">${v == null ? esc(t("not_read")) : esc(v)}</div></div>`;
    const amt = d.amount != null ? "₹" + d.amount.toLocaleString("en-IN", { maximumFractionDigits: 2 }) : null;
    $("#shotcard").innerHTML = `
      <figure><img src="${r.annotated}" alt="Uploaded screenshot with suspicious areas marked"><figcaption>${esc(t("shot_marked"))}</figcaption></figure>
      <div><h3>${esc(t("shot_read"))}</h3>
        ${row("f_status", d.status, "status")}${row("f_amount", amt, "amount")}${row("f_utr", d.utr, "utr")}
        ${row("f_date", d.date, "date")}${row("f_payee", d.payee, "payee")}${row("f_app", d.app, "app")}
      </div>`;
  };
})();
