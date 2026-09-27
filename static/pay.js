/* After a UPI QR is checked: hand a SAFE payment to the user's UPI app (GPay / PhonePe / Paytm / BHIM / any).
   Android: Chrome intent:// links that target the app's package (falls back to the Play Store if it's missing).
   iPhone:  each app's own URL scheme.  Desktop: shows the payment QR to scan with a phone.
   Risky results never auto-open; paying anyway needs an explicit "I know this person" tick. */
(() => {
  const A = window.APKX;
  const $ = (s) => document.querySelector(s);
  const esc = A.esc;

  const APPS = [
    { id: "gpay", name: "Google Pay", pkg: "com.google.android.apps.nbu.paisa.user", ios: "tez://upi/pay", color: "#1a73e8" },
    { id: "phonepe", name: "PhonePe", pkg: "com.phonepe.app", ios: "phonepe://pay", color: "#5f259f" },
    { id: "paytm", name: "Paytm", pkg: "net.one97.paytm", ios: "paytmmp://pay", color: "#00baf2" },
    { id: "bhim", name: "BHIM", pkg: "in.org.npci.upiapp", ios: null, color: "#f47b20" },
  ];
  const S = {
    en: { safe: "Safe to pay — choose your UPI app", caution: "Check the name in your UPI app before entering your PIN", risky: "Paying is not recommended",
          other: "Other UPI app", opening: "Opening {app} in {n}…", cancel: "Cancel", override: "I know this person and I'm sure this payment is genuine",
          desk: "Open this page on your phone to pay, or scan this QR with your phone's UPI app:", hint: "If nothing opens, tap an app above.",
          your: "your UPI app" },
    hi: { safe: "पेमेंट सुरक्षित — अपना UPI ऐप चुनें", caution: "PIN डालने से पहले UPI ऐप में नाम जाँचें", risky: "पेमेंट करने की सलाह नहीं है",
          other: "दूसरा UPI ऐप", opening: "{n} सेकंड में {app} खुलेगा…", cancel: "रद्द करें", override: "मैं इस व्यक्ति को जानता/जानती हूँ और यह पेमेंट सही है",
          desk: "पेमेंट के लिए यह पेज फ़ोन पर खोलें, या यह QR फ़ोन के UPI ऐप से स्कैन करें:", hint: "कुछ न खुले तो ऊपर कोई ऐप दबाएँ।", your: "आपका UPI ऐप" },
    kn: { safe: "ಪಾವತಿ ಸುರಕ್ಷಿತ — ನಿಮ್ಮ UPI ಆ್ಯಪ್ ಆಯ್ಕೆಮಾಡಿ", caution: "PIN ಹಾಕುವ ಮೊದಲು UPI ಆ್ಯಪ್‌ನಲ್ಲಿ ಹೆಸರು ಪರಿಶೀಲಿಸಿ", risky: "ಪಾವತಿಸಲು ಶಿಫಾರಸು ಮಾಡುವುದಿಲ್ಲ",
          other: "ಇತರ UPI ಆ್ಯಪ್", opening: "{n} ಸೆಕೆಂಡಿನಲ್ಲಿ {app} ತೆರೆಯುತ್ತದೆ…", cancel: "ರದ್ದುಮಾಡಿ", override: "ನನಗೆ ಈ ವ್ಯಕ್ತಿ ಗೊತ್ತು ಮತ್ತು ಈ ಪಾವತಿ ನಿಜವಾದದ್ದು",
          desk: "ಪಾವತಿಸಲು ಈ ಪುಟವನ್ನು ಫೋನ್‌ನಲ್ಲಿ ತೆರೆಯಿರಿ, ಅಥವಾ ಈ QR ಅನ್ನು ಫೋನ್‌ನ UPI ಆ್ಯಪ್‌ನಿಂದ ಸ್ಕ್ಯಾನ್ ಮಾಡಿ:", hint: "ಏನೂ ತೆರೆಯದಿದ್ದರೆ ಮೇಲಿನ ಆ್ಯಪ್ ಒತ್ತಿ.", your: "ನಿಮ್ಮ UPI ಆ್ಯಪ್" },
    ta: { safe: "பணம் செலுத்துவது பாதுகாப்பானது — உங்கள் UPI செயலியைத் தேர்ந்தெடுக்கவும்", caution: "உங்கள் PIN-ஐ உள்ளிடுவதற்கு முன் UPI செயலியில் பெயரைச் சரிபார்க்கவும்", risky: "பணம் செலுத்த பரிந்துரைக்கப்படவில்லை",
          other: "மற்றொரு UPI செயலி", opening: "{n} வினாடிகளில் {app} திறக்கும்…", cancel: "ரத்து செய்", override: "எனக்கு இந்த நபரைத் தெரியும், இந்த கட்டணம் உண்மையானது என்பதில் உறுதியாக உள்ளேன்",
          desk: "பணம் செலுத்த இந்தப் பக்கத்தை உங்கள் தொலைபேசியில் திறக்கவும் அல்லது உங்கள் தொலைபேசியின் UPI செயலி மூலம் இந்த QR ஐ ஸ்கேன் செய்யவும்:", hint: "எதுவும் திறக்கவில்லை என்றால், மேலே உள்ள ஒரு செயலியைத் தட்டவும்.", your: "உங்கள் UPI செயலி" },
    te: { safe: "చెల్లింపు సురక్షితం — మీ UPI యాప్‌ని ఎంచుకోండి", caution: "మీ PIN నమోదు చేసే ముందు UPI యాప్‌లో పేరును తనిఖీ చేయండి", risky: "చెల్లింపు చేయడం సిఫార్సు చేయబడదు",
          other: "మరో UPI యాప్", opening: "{n} సెకన్లలో {app} తెరుచుకుంటుంది…", cancel: "రద్దు చేయండి", override: "నాకు ఈ వ్యక్తి తెలుసు మరియు ఈ చెల్లింపు నిజమైనదని నేను ఖచ్చితంగా అనుకుంటున్నాను",
          desk: "చెల్లించడానికి మీ ఫోన్‌లో ఈ పేజీని తెరవండి లేదా మీ ఫోన్ UPI యాప్‌తో ఈ QR ని స్కాన్ చేయండి:", hint: "ఏదీ తెరవకపోతే, పైన ఉన్న యాప్‌ను నొక్కండి.", your: "మీ UPI యాప్" },
    mr: { safe: "पेमेंट सुरक्षित — तुमचे UPI अ‍ॅप निवडा", caution: "तुमचा PIN टाकण्यापूर्वी UPI अ‍ॅपमधील नाव तपासा", risky: "पेमेंट करण्याची शिफारस नाही",
          other: "दुसरे UPI अ‍ॅप", opening: "{n} सेकंदात {app} उघडेल…", cancel: "रद्द करा", override: "मी या व्यक्तीला ओळखतो/ओळखते आणि हे पेमेंट खरे असल्याची माझी खात्री आहे",
          desk: "पेमेंट करण्यासाठी हे पेज तुमच्या फोनवर उघडा, किंवा तुमच्या फोनच्या UPI अ‍ॅपद्वारे हा QR स्कॅन करा:", hint: "काही उघडले नाही तर वर एका अ‍ॅपवर टॅप करा.", your: "तुमचे UPI अ‍ॅप" },
    bn: { safe: "পেমেন্ট নিরাপদ — আপনার UPI অ্যাপ বেছে নিন", caution: "আপনার PIN দেওয়ার আগে UPI অ্যাপে নামটি যাচাই করুন", risky: "টাকা দেওয়া অনুচিত",
          other: "অন্য UPI অ্যাপ", opening: "{n} সেকেন্ডে {app} খুলবে…", cancel: "বাতিল করুন", override: "আমি এই ব্যক্তিকে চিনি এবং এই পেমেন্টটি আসল বলে নিশ্চিত",
          desk: "টাকা দিতে আপনার ফোনে এই পৃষ্ঠাটি খুলুন, অথবা ফোনের UPI অ্যাপ দিয়ে এই QR টি স্ক্যান করুন:", hint: "কিছু না খুললে উপরের কোনো অ্যাপে ট্যাপ করুন।", your: "আপনার UPI অ্যাপ" },
  };
  const t = (k, v = {}) => ((S[A.lang()] || S.en)[k] || S.en[k]).replace(/\{(\w+)\}/g, (_, x) => v[x]);

  const ua = navigator.userAgent || "";
  const platform = /android/i.test(ua) ? "android"
    : (/iphone|ipad|ipod/i.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) ? "ios" : "desktop";

  function query(payload) {
    const i = payload.indexOf("?");
    return i >= 0 ? payload.slice(i + 1) : "";
  }
  function hrefFor(app, payload) {
    let q = query(payload);
    // Google Pay strictly requires cu=INR parameter; append if missing
    if (q && !/(?:^|&)cu=/i.test(q)) {
      q += "&cu=INR";
    }
    const upiUri = `upi://pay?${q}`;
    if (!app) return upiUri;        // any UPI app (system chooser on Android)
    if (platform === "android") {
      return `intent://pay?${q}#Intent;action=android.intent.action.VIEW;category=android.intent.category.BROWSABLE;scheme=upi;package=${app.pkg};end`;
    }
    if (platform === "ios" && app.ios) return `${app.ios}?${q}`;
    return upiUri;
  }
  const saved = () => { try { return localStorage.getItem("pg_upi_app") || ""; } catch (_) { return ""; } };
  const save = (id) => { try { localStorage.setItem("pg_upi_app", id); } catch (_) {} };

  let timer = null;
  function stop() { if (timer) { clearInterval(timer); timer = null; } const c = $("#pay-count"); if (c) c.hidden = true; }

  window.renderPay = (r) => {
    stop();
    const card = $("#paycard");
    const d = r.details || {};
    if (r.kind !== "qr" || d.type !== "upi" || d.action && !/^pay$/i.test(d.action)) { card.hidden = true; return; }
    card.hidden = false;
    const level = r.verdict.level;
    const risky = level === "danger" || level === "suspicious";
    const apps = APPS.filter((a) => platform !== "ios" || a.ios);
    const buttons = apps.map((a) => `<a class="payapp" data-app="${a.id}" href="${esc(hrefFor(a, r.payload))}" style="--c:${a.color}">
        <span class="dot" aria-hidden="true">${esc(a.name[0])}</span>${esc(a.name)}</a>`).join("")
      + `<a class="payapp" data-app="" href="${esc(hrefFor(null, r.payload))}" style="--c:#475569"><span class="dot" aria-hidden="true">₹</span>${esc(t("other"))}</a>`;

    if (platform === "desktop") {
      card.innerHTML = `<h3>${esc(risky ? t("risky") : level === "low" ? t("safe") : t("caution"))}</h3>
        ${risky ? "" : `<div class="pay-desk"><img alt="" width="150" height="150" src="/api/qr/render.png?data=${encodeURIComponent(r.payload)}"><p class="dim">${esc(t("desk"))}</p></div>`}`;
      return;
    }
    card.innerHTML = `<h3 class="${risky ? "bad" : ""}">${esc(risky ? t("risky") : level === "low" ? t("safe") : t("caution"))}</h3>
      ${risky ? `<label class="pay-override"><input type="checkbox" id="pay-ok"> ${esc(t("override"))}</label>` : ""}
      <div class="payapps" id="payapps" ${risky ? "hidden" : ""}>${buttons}</div>
      <div class="pay-count" id="pay-count" hidden><span id="pay-count-text"></span> <button type="button" class="btn ghost small" id="pay-cancel">${esc(t("cancel"))}</button></div>
      <p class="dim small">${esc(t("hint"))}</p>`;
    if (risky) {
      $("#pay-ok").addEventListener("change", (e) => {
        $("#payapps").hidden = !e.target.checked;
        // a protected family member insisting on a risky payment: tell their guardians now
        if (e.target.checked && window.PGDev) window.PGDev.event("pay_anyway", { kind: "qr", payload: r.payload });
      });
      return;
    }
    // Safe: count down and open the user's usual UPI app (or the system chooser). Any tap cancels.
    if (level === "low") {
      const pref = APPS.find((a) => a.id === saved() && (platform !== "ios" || a.ios)) || null;
      const target = hrefFor(pref, r.payload);
      const name = pref ? pref.name : t("your");
      let n = 3;
      $("#pay-count").hidden = false;
      $("#pay-count-text").textContent = t("opening", { app: name, n });
      timer = setInterval(() => {
        n -= 1;
        if (n <= 0) { stop(); location.href = target; return; }
        $("#pay-count-text").textContent = t("opening", { app: name, n });
      }, 1000);
      $("#pay-cancel").addEventListener("click", stop);
    }
  };

  document.addEventListener("click", (e) => {
    const a = e.target.closest(".payapp");
    if (a) { stop(); save(a.dataset.app); }
    if (e.target.closest("[data-act='again'], .lang button, .back")) stop();
  });
  document.addEventListener("visibilitychange", () => { if (document.hidden) stop(); });
})();
