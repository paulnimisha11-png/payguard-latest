/* One-tap scam reports: "It got me" / "It's fake". Depends on window.APKX (app.js). */
(() => {
  const A = window.APKX;
  const $ = (s) => document.querySelector(s);
  const esc = A.esc;

  const S = {
    en: { title: "Is this a scam?", sub: "One tap warns the next person who checks it. Reports are anonymous.",
          got: "It got me — I lost money", fake: "It's fake — I spotted it", count: "Reported by {n} people",
          none: "No one has reported this yet.", thanks: "Thanks — your report was added.", already: "You've already reported this.",
          complaint: "Prepare my complaint (1930 / cybercrime.gov.in)", err: "Couldn't send the report. Try again.",
          genuine: "I know this is genuine", genuine_done: "Thanks — we noted that this is genuine.", disputed: "{n} people say it's genuine" },
    hi: { title: "क्या यह ठगी है?", sub: "एक टैप से अगले जाँचने वाले को चेतावनी मिलती है। रिपोर्ट गुमनाम रहती है।",
          got: "मैं फँस गया — पैसे गए", fake: "यह नकली है — मैंने पहचान लिया", count: "{n} लोगों ने रिपोर्ट किया",
          none: "अभी तक किसी ने रिपोर्ट नहीं किया।", thanks: "धन्यवाद — आपकी रिपोर्ट जुड़ गई।", already: "आप पहले ही रिपोर्ट कर चुके हैं।",
          complaint: "मेरी शिकायत तैयार करें (1930 / cybercrime.gov.in)", err: "रिपोर्ट नहीं भेजी जा सकी। फिर कोशिश करें।",
          genuine: "मुझे पता है यह असली है", genuine_done: "धन्यवाद — हमने दर्ज किया कि यह असली है।", disputed: "{n} लोग इसे असली बताते हैं" },
    kn: { title: "ಇದು ವಂಚನೆಯೇ?", sub: "ಒಂದು ಟ್ಯಾಪ್ ಮುಂದಿನ ಪರಿಶೀಲಕರಿಗೆ ಎಚ್ಚರಿಕೆ ನೀಡುತ್ತದೆ. ವರದಿಗಳು ಅನಾಮಧೇಯ.",
          got: "ನಾನು ಮೋಸಹೋದೆ — ಹಣ ಹೋಯಿತು", fake: "ಇದು ನಕಲಿ — ನಾನು ಗುರುತಿಸಿದೆ", count: "{n} ಜನರು ವರದಿ ಮಾಡಿದ್ದಾರೆ",
          none: "ಇನ್ನೂ ಯಾರೂ ವರದಿ ಮಾಡಿಲ್ಲ.", thanks: "ಧನ್ಯವಾದ — ನಿಮ್ಮ ವರದಿ ಸೇರಿಸಲಾಗಿದೆ.", already: "ನೀವು ಈಗಾಗಲೇ ವರದಿ ಮಾಡಿದ್ದೀರಿ.",
          complaint: "ನನ್ನ ದೂರು ಸಿದ್ಧಪಡಿಸಿ (1930 / cybercrime.gov.in)", err: "ವರದಿ ಕಳುಹಿಸಲಾಗಲಿಲ್ಲ. ಮತ್ತೆ ಪ್ರಯತ್ನಿಸಿ.",
          genuine: "ಇದು ನಿಜವಾದದ್ದು ಎಂದು ನನಗೆ ಗೊತ್ತು", genuine_done: "ಧನ್ಯವಾದ — ಇದು ನಿಜವಾದದ್ದು ಎಂದು ದಾಖಲಿಸಿದ್ದೇವೆ.", disputed: "{n} ಜನ ಇದು ನಿಜವಾದದ್ದು ಎನ್ನುತ್ತಾರೆ" },
    ta: { title: "இது மோசடியா?", sub: "ஒரு தட்டுதல் மூலம் அடுத்த பயனருக்கு எச்சரிக்கை தெரிவிக்கலாம். அறிக்கைகள் அநாமதேயமானவை.",
          got: "நான் ஏமாந்துவிட்டேன் — பணத்தை இழந்தேன்", fake: "இது போலி — நான் கண்டறிந்துவிட்டேன்", count: "{n} பேர் புகார் தெரிவித்துள்ளனர்",
          none: "இதுவரை யாரும் புகார் தெரிவிக்கவில்லை.", thanks: "நன்றி — உங்கள் புகார் சேர்க்கப்பட்டது.", already: "நீங்கள் ஏற்கனவே புகார் அளித்துள்ளீர்கள்.",
          complaint: "என் புகாரைத் தயார் செய்க (1930 / cybercrime.gov.in)", err: "புகாரை அனுப்ப முடியவில்லை. மீண்டும் முயற்சிக்கவும்.",
          genuine: "இது உண்மையானது என எனக்குத் தெரியும்", genuine_done: "நன்றி — இது உண்மையானது எனப் பதிவு செய்துள்ளோம்.", disputed: "{n} பேர் இது உண்மையானது என்கிறார்கள்" },
    te: { title: "ఇది మోసమా?", sub: "ఒక్క ట్యాప్‌తో తర్వాత చూసేవారిని హెచ్చరించవచ్చు. రిపోర్టులు అనామకం.",
          got: "నేను మోసపోయాను — డబ్బు పోయింది", fake: "ఇది నకిలీ — నేను కనిపెట్టాను", count: "{n} మంది నివేదించారు",
          none: "ఇంకా ఎవరూ నివేదించలేదు.", thanks: "ధన్యవాదాలు — మీ నివేదిక చేర్చబడింది.", already: "మీరు ఇప్పటికే నివేదించారు.",
          complaint: "నా ఫిర్యాదును సిద్ధం చేయండి (1930 / cybercrime.gov.in)", err: "నివేదికను పంపలేకపోయాము. మళ్లీ ప్రయత్నించండి.",
          genuine: "ఇది నిజమైనదని నాకు తెలుసు", genuine_done: "ధన్యవాదాలు — ఇది నిజమైనదని నమోదు చేశాము.", disputed: "{n} మంది ఇది నిజమైనదని చెబుతున్నారు" },
    mr: { title: "ही फसवणूक आहे का?", sub: "एका टॅपने नंतर तपासणाऱ्याला सावध केले जाते. तक्रारी निनावी राहतात.",
          got: "मी अडकलो — पैसे गेले", fake: "हे बनावट आहे — मी ओळखले", count: "{n} लोकांनी नोंदवले",
          none: "अजून कोणीही नोंदवले नाही.", thanks: "धन्यवाद — तुमची तक्रार नोंदवली गेली.", already: "तुम्ही आधीच तक्रार नोंदवली आहे.",
          complaint: "माझी तक्रार तयार करा (1930 / cybercrime.gov.in)", err: "तक्रार पाठवता आली नाही. पुन्हा प्रयत्न करा.",
          genuine: "मला माहीत आहे हे खरे आहे", genuine_done: "धन्यवाद — आम्ही नोंदवले की हे खरे आहे.", disputed: "{n} लोक हे खरे असल्याचे सांगतात" },
    bn: { title: "এটি কি কোনো প্রতারণা?", sub: "একটি ট্যাপে পরবর্তী ব্যবহারকারীকে সতর্ক করা যায়। রিপোর্টগুলি বেনামী।",
          got: "আমি ফাঁদে পড়েছি — টাকা হারিয়েছি", fake: "এটি ভুয়ো — আমি ধরে ফেলেছি", count: "{n} জন রিপোর্ট করেছেন",
          none: "এখনও পর্যন্ত কেউ রিপোর্ট করেননি।", thanks: "ধন্যবাদ — আপনার রিপোর্ট যোগ করা হয়েছে।", already: "আপনি ইতিমধ্যেই রিপোর্ট করেছেন।",
          complaint: "আমার অভিযোগ প্রস্তুত করুন (1930 / cybercrime.gov.in)", err: "রিপোর্ট পাঠানো যায়নি। আবার চেষ্টা করুন।",
          genuine: "আমি জানি এটি আসল", genuine_done: "ধন্যবাদ — আমরা নথিভুক্ত করেছি যে এটি আসল।", disputed: "{n} জন বলছেন এটি আসল" },
  };
  const t = (k, v = {}) => ((S[A.lang()] || S.en)[k] || S.en[k]).replace(/\{(\w+)\}/g, (_, x) => v[x]).replace(/\bby 1 people\b/, "by 1 person");

  function voter() {
    try {
      let v = localStorage.getItem("pg_voter");
      if (!v) {
        v = (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()).slice(2) + Date.now());
        localStorage.setItem("pg_voter", v);
      }
      return v;
    } catch (_) { return ""; }
  }
  const target = (r) => (r.kind === "qr" || r.kind === "msg" ? { kind: r.kind, payload: r.payload } : r.kind === "shot" ? { kind: "shot", id: r.id } : { kind: "apk", id: r.file.sha256 });
  const keyOf = (r) => { const x = target(r); return x.kind + ":" + (x.id || x.payload); };
  const voted = (r) => { try { return JSON.parse(localStorage.getItem("pg_voted") || "{}")[keyOf(r)]; } catch (_) { return null; } };
  const remember = (r, reason) => { try { const m = JSON.parse(localStorage.getItem("pg_voted") || "{}"); m[keyOf(r)] = reason; localStorage.setItem("pg_voted", JSON.stringify(m)); } catch (_) {} };

  let current = null, autoDone = false;

  window.renderVote = (r) => {
    current = r;
    const card = $("#votecard");
    if (!r.community || !r.community.can_report) { card.hidden = true; return; }
    card.hidden = false;
    const n = r.community.reports || 0, mine = voted(r);
    card.innerHTML = `
      <div class="vote-head"><div><h3>${esc(t("title"))}</h3><p class="dim">${esc(t("sub"))}</p></div>
        <div class="vote-count ${n ? "on" : ""}" id="vote-count">${esc(n ? t("count", { n }) : t("none"))}</div></div>
      <div class="vote-btns">
        <button class="btn vote got" type="button" data-vote="got_me" ${mine ? "disabled" : ""}>😞 ${esc(t("got"))}</button>
        <button class="btn vote fake" type="button" data-vote="fake" ${mine ? "disabled" : ""}>🚩 ${esc(t("fake"))}</button>
      </div>
      <p class="vote-msg" id="vote-msg" ${mine ? "" : "hidden"}>${mine ? "✓ " + esc(t("already")) : ""}</p>
      <button class="btn light vote-complaint" type="button" id="vote-complaint" ${mine === "got_me" ? "" : "hidden"}>📝 ${esc(t("complaint"))}</button>
      ${(r.kind === "qr" || r.kind === "msg") && !mine ? `<button class="linkbtn vote-genuine" type="button" data-vote="not_scam">✓ ${esc(t("genuine"))}</button>` : ""}
      ${r.community.disputes ? `<p class="dim small">${esc(t("disputed", { n: r.community.disputes }))}</p>` : ""}`;
    // the Android app hands scams over with ?report=got_me
    const want = new URLSearchParams(location.search).get("report");
    if (!autoDone && want === "got_me" && (r.kind === "qr" || r.kind === "msg")) { autoDone = true; openComplaint(); }
  };

  function openComplaint() {
    const btn = $("#report-btn");
    if (!btn) return;
    btn.hidden = false;
    btn.click();
    setTimeout(() => { const y = $("#lost-yes"); if (y) { y.checked = true; y.dispatchEvent(new Event("change")); } }, 50);
  }

  document.addEventListener("click", async (e) => {
    if (e.target.closest("#vote-complaint")) return openComplaint();
    const b = e.target.closest("[data-vote]");
    if (!b || !current) return;
    const reason = b.dataset.vote;
    document.querySelectorAll("[data-vote]").forEach((x) => (x.disabled = true));
    try {
      const res = await fetch("/api/reports", { method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ ...target(current), reason, voter: voter() }) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "error");
      remember(current, reason);
      if (reason === "not_scam") {
        const msg = $("#vote-msg"); msg.hidden = false; msg.textContent = "✓ " + t("genuine_done");
        const g = document.querySelector(".vote-genuine"); if (g) g.hidden = true;
        return;
      }
      current.community.reports = data.reports;
      $("#vote-count").textContent = t("count", { n: data.reports });
      $("#vote-count").classList.add("on");
      const pill = $("#reported"); pill.hidden = false; pill.textContent = A.t("reported_by", { n: data.reports });
      const msg = $("#vote-msg"); msg.hidden = false; msg.textContent = "✓ " + (data.already ? t("already") : t("thanks"));
      if (reason === "got_me") $("#vote-complaint").hidden = false;
    } catch (err) {
      document.querySelectorAll("[data-vote]").forEach((x) => (x.disabled = false));
      A.toast(err.message && err.message !== "error" ? err.message : t("err"));
    }
  });

  document.querySelectorAll(".lang button").forEach((b) => b.addEventListener("click", () => current && window.renderVote(current)));
})();
