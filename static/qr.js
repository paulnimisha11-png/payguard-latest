/* PayPause: QR code / UPI link scanning UI. Depends on window.APKX from app.js. */
(() => {
  const A = window.APKX;
  const $ = (s) => document.querySelector(s);
  const JSQR_URL = "/vendor/jsQR.js";  // bundled so the installed app works without a CDN

  // ---------------------------------------------------------- mode switch
  function setMode(m) {
    document.querySelectorAll(".mode").forEach((b) => b.classList.toggle("on", b.dataset.mode === m));
    $("#panel-apk").hidden = m !== "apk";
    $("#panel-qr").hidden = m !== "qr";
    $("#panel-shot").hidden = m !== "shot";
    $("#panel-msg").hidden = m !== "msg";
    if (m !== "qr") stopCam();
    try { localStorage.setItem("apkx_mode", m); } catch (_) {}
  }
  document.querySelectorAll(".mode").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));
  let saved = "msg";
  try { saved = localStorage.getItem("apkx_mode") || "msg"; } catch (_) {}
  const qp = new URLSearchParams(location.search);
  const qm = qp.get("mode");
  if (["qr", "shot", "apk", "msg"].includes(qm)) saved = qm;
  if (qp.get("share_text") || qp.get("text")) saved = "msg";
  if (!["apk", "qr", "shot", "msg"].includes(saved)) saved = "msg";

  // ---------------------------------------------------------- submit helpers
  function progress(label) {
    $("#prog-file").textContent = label;
    $(".steps").hidden = true;
    $("#bar").style.width = "70%";
    A.show("progress");
  }
  async function handle(res) {
    let data;
    try { data = await res.json(); } catch (_) { data = { error: "Server error (" + res.status + ")" }; }
    $(".steps").hidden = false;
    if (!res.ok) return A.fail(data.error || "Error " + res.status);
    $("#bar").style.width = "100%";
    A.render(data);
    A.show("result");
  }
  async function sendText(text) {
    text = (text || "").trim();
    if (!text) return;
    progress("QR / link");
    try {
      await handle(await fetch("/api/qr/text", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text }) }));
    } catch (_) { $(".steps").hidden = false; A.fail("Network error — is the server running?"); }
  }
  async function sendImage(file) {
    progress(file.name || "QR image");
    const fd = new FormData();
    fd.append("file", file);
    try { await handle(await fetch("/api/qr/image", { method: "POST", body: fd })); }
    catch (_) { $(".steps").hidden = false; A.fail("Network error — is the server running?"); }
  }

  // ---------------------------------------------------------- image upload / paste
  const drop = $("#qrdrop"), input = $("#qrfile");
  input.addEventListener("change", () => { if (input.files[0]) sendImage(input.files[0]); input.value = ""; });
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); } });
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => e.dataTransfer.files[0] && sendImage(e.dataTransfer.files[0]));
  // paste a screenshot anywhere while in QR mode
  document.addEventListener("paste", (e) => {
    if ($("#panel-qr").hidden || $("#home").hidden) return;
    const item = [...(e.clipboardData?.items || [])].find((i) => i.type.startsWith("image/"));
    if (item) { e.preventDefault(); sendImage(item.getAsFile()); }
  });
  $("#qrform").addEventListener("submit", (e) => { e.preventDefault(); sendText($("#qrtext").value); });

  // ---------------------------------------------------------- camera
  let stream = null, raf = 0, detector = null;
  const video = $("#video");
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });

  function loadJsQR() {
    if (window.jsQR) return Promise.resolve();
    return new Promise((ok, bad) => {
      const s = document.createElement("script");
      s.src = JSQR_URL; s.onload = ok; s.onerror = bad;
      document.head.appendChild(s);
    });
  }

  async function startCam() {
    try {
      if ("BarcodeDetector" in window) {
        try { detector = new window.BarcodeDetector({ formats: ["qr_code"] }); } catch (_) { detector = null; }
      }
      if (!detector) await loadJsQR();
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" }, audio: false });
      video.srcObject = stream;
      await video.play();
      $("#cam").hidden = false;
      tick();
    } catch (err) {
      stopCam();
      A.toast(A.t("cam_denied"));
    }
  }
  function stopCam() {
    cancelAnimationFrame(raf);
    if (stream) stream.getTracks().forEach((t) => t.stop());
    stream = null;
    $("#cam").hidden = true;
  }
  async function tick() {
    if (!stream) return;
    if (video.readyState >= 2) {
      let text = null;
      try {
        if (detector) {
          const codes = await detector.detect(video);
          if (codes.length) text = codes[0].rawValue;
        } else if (window.jsQR) {
          const w = video.videoWidth, h = video.videoHeight;
          const scale = Math.min(1, 800 / Math.max(w, h));
          canvas.width = w * scale; canvas.height = h * scale;
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
          const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = window.jsQR(img.data, img.width, img.height, { inversionAttempts: "attemptBoth" });
          if (code && code.data) text = code.data;
        }
      } catch (_) {}
      if (text) {
        if (navigator.vibrate) navigator.vibrate(80);
        stopCam();
        return sendText(text);
      }
    }
    raf = requestAnimationFrame(tick);
  }
  $("#cam-btn").addEventListener("click", () => (stream ? stopCam() : startCam()));
  $("#cam-stop").addEventListener("click", stopCam);

  setMode(saved);
  const check = new URLSearchParams(location.search).get("check");
  if (check) { setMode("qr"); sendText(check); }
})();
