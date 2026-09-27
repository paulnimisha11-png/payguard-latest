/* Install PayGuard as an app: Android/desktop Chrome use the install prompt; iPhone/iPad Safari shows how to
   "Add to Home Screen". Registers the service worker. */
(() => {
  const $ = (s) => document.querySelector(s);
  const ua = navigator.userAgent || "";
  const ios = /iphone|ipad|ipod/i.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
  const standalone = window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
  const L = () => (window.APKX ? window.APKX.lang() : "en");
  const S = {
    en: { install: "Install app", ios: "To install PayGuard on your iPhone: tap the Share button (square with an arrow) at the bottom of Safari, then “Add to Home Screen”.", close: "Got it" },
    hi: { install: "ऐप इंस्टॉल करें", ios: "iPhone पर PayGuard इंस्टॉल करने के लिए: Safari में नीचे Share बटन (तीर वाला चौकोर) दबाएँ, फिर “Add to Home Screen”।", close: "ठीक है" },
    kn: { install: "ಆ್ಯಪ್ ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಿ", ios: "iPhone ನಲ್ಲಿ PayGuard ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಲು: Safari ಕೆಳಗಿನ Share ಬಟನ್ (ಬಾಣದ ಚೌಕ) ಒತ್ತಿ, ನಂತರ “Add to Home Screen”.", close: "ಸರಿ" },
    ta: { install: "ஆப் நிறுவவும்", ios: "உங்கள் iPhone இல் PayGuard ஐ நிறுவ: Safari இன் கீழே உள்ள பகிர் பொத்தானை (அம்புக்குறியுடன் கூடிய சதுரம்) தட்டி, பின்னர் “Add to Home Screen” என்பதைத் தேர்ந்தெடுக்கவும்.", close: "புரிந்தது" },
    te: { install: "యాప్ ఇన్‌స్టాల్ చేయండి", ios: "మీ iPhone లో PayGuard ఇన్‌స్టాల్ చేయడానికి: Safari అడుగున ఉన్న Share బటన్‌ను (బాణంతో ఉన్న చతురస్రం) నొక్కి, ఆపై “Add to Home Screen” ఎంచుకోండి.", close: "సరే" },
    mr: { install: "ॲप इन्स्टॉल करा", ios: "तुमच्या iPhone वर PayGuard इन्स्टॉल करण्यासाठी: Safari मध्ये खाली शेअर बटण (बाण असलेला चौकोन) दाबा, नंतर “Add to Home Screen” निवडा.", close: "समजले" },
    bn: { install: "অ্যাপ ইনস্টল করুন", ios: "আপনার iPhone-এ PayGuard ইনস্টল করতে: Safari-এর নিচে শেয়ার বোতাম (তীরযুক্ত বাক্স) ট্যাপ করুন, তারপর “Add to Home Screen” বেছে নিন।", close: "বুঝেছি" },
  };
  const t = (k) => (S[L()] || S.en)[k];

  if (standalone) document.documentElement.classList.add("standalone");
  if ("serviceWorker" in navigator && (location.protocol === "https:" || location.hostname === "localhost" || location.hostname === "127.0.0.1")) {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  }

  const btn = $("#install-btn");
  let deferred = null;
  function label() { if (btn) btn.textContent = "⬇ " + t("install"); }
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferred = e;
    if (btn && !standalone) { btn.hidden = false; label(); }
  });
  if (btn && ios && !standalone) { btn.hidden = false; label(); }
  btn && btn.addEventListener("click", async () => {
    if (deferred) {
      deferred.prompt();
      await deferred.userChoice.catch(() => {});
      deferred = null;
      btn.hidden = true;
      return;
    }
    const sheet = $("#ios-sheet");
    sheet.querySelector("p").textContent = t("ios");
    sheet.querySelector("button").textContent = t("close");
    sheet.hidden = false;
  });
  const sheet = $("#ios-sheet");
  sheet && sheet.querySelector("button").addEventListener("click", () => (sheet.hidden = true));
  window.addEventListener("appinstalled", () => btn && (btn.hidden = true));
  document.querySelectorAll(".lang button").forEach((b) => b.addEventListener("click", label));

  // Home-screen shortcut "Scan QR to pay" opens straight into the camera.
  if (new URLSearchParams(location.search).get("scan") === "1") {
    setTimeout(() => { const c = $("#cam-btn"); if (c) c.click(); }, 400);
  }
})();
