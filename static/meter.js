/* Risk meter + plain-language checkpoints, shared by every result screen.

   Why no numbers: a scam check can't be precise to the point, so PayGuard shows WHICH ZONE the result falls in
   (very low / low / medium / high risk) on a speedometer-style dial, and the checkpoints that put it there, in words
   anyone can follow. The needle points at the middle of the zone, never at a fake-precise value.

   window.PGMeter = { level(r), label(level, lang), svg(level, opts), checkpoints(r, lang) }                       */
(() => {
  "use strict";
  const ZONES = ["low", "caution", "suspicious", "danger"];           // the existing verdict levels, left to right
  const COLORS = { low: "#19e68c", caution: "#ffd43b", suspicious: "#ff8a3d", danger: "#ff1f3d" };
  const LABEL = {
    en: { low: "VERY LOW RISK", caution: "LOW RISK", suspicious: "MEDIUM RISK", danger: "HIGH RISK", lo: "LOW", hi: "HIGH" },
    hi: { low: "बहुत कम जोखिम", caution: "कम जोखिम", suspicious: "मध्यम जोखिम", danger: "ज़्यादा जोखिम", lo: "कम", hi: "ज़्यादा" },
    kn: { low: "ತುಂಬಾ ಕಡಿಮೆ ಅಪಾಯ", caution: "ಕಡಿಮೆ ಅಪಾಯ", suspicious: "ಮಧ್ಯಮ ಅಪಾಯ", danger: "ಹೆಚ್ಚಿನ ಅಪಾಯ", lo: "ಕಡಿಮೆ", hi: "ಹೆಚ್ಚು" },
  };
  // things that were checked and came out fine, in plain words
  const GOOD = {
    en: {
      not_reported: "Nobody has reported this to PayGuard", link_not_listed: "The link isn't on Google's danger list",
      sender_ok: "Sent from the organisation's registered SMS sender", no_links: "No links to open",
      no_asks: "Doesn't ask for an OTP, PIN, money or an app", upi_valid: "The payment link is correctly formed",
      official: "Goes to an official website", no_editing: "No signs of editing in the file", pixels_ok: "Numbers and text look untouched",
      status_ok: "Payment status says completed", amount_ok: "Amounts on the receipt match", date_ok: "Date and time make sense",
      utr_ok: "Reference number looks valid", qr_ok: "QR code on the receipt matches it", history_ok: "Not a copy of an earlier receipt",
      not_confirmed: "Payment not confirmed by a bank: check your bank app", no_triad: "Doesn't combine SMS reading, screen control and overlays",
      signed_ok: "The app is properly signed", none: "No warning signs found in the checks PayGuard ran",
      ml_ok: "Pattern check: looks like normal payments",
    },
    hi: {
      not_reported: "किसी ने इसे PayGuard पर रिपोर्ट नहीं किया", link_not_listed: "लिंक Google की ख़तरनाक सूची में नहीं है",
      sender_ok: "संस्था के पंजीकृत SMS सेंडर से आया", no_links: "खोलने के लिए कोई लिंक नहीं",
      no_asks: "OTP, PIN, पैसे या ऐप नहीं माँगता", upi_valid: "पेमेंट लिंक सही रूप में है", official: "आधिकारिक वेबसाइट पर जाता है",
      no_editing: "फ़ाइल में एडिटिंग के निशान नहीं", pixels_ok: "अंक और अक्षर बदले हुए नहीं लगते", status_ok: "पेमेंट स्टेटस पूरा दिखाता है",
      amount_ok: "रसीद की रकम आपस में मेल खाती है", date_ok: "तारीख़ और समय सही लगते हैं", utr_ok: "रेफ़रेंस नंबर सही लगता है",
      qr_ok: "रसीद का QR कोड उससे मेल खाता है", history_ok: "पुरानी रसीद की नकल नहीं",
      not_confirmed: "बैंक ने पेमेंट की पुष्टि नहीं की: अपना बैंक ऐप देखें", no_triad: "SMS पढ़ना, स्क्रीन कंट्रोल और ओवरले एक साथ नहीं",
      signed_ok: "ऐप सही तरह साइन है", none: "PayGuard की जाँच में कोई चेतावनी नहीं मिली", ml_ok: "पैटर्न जाँच: सामान्य पेमेंट जैसा",
    },
    kn: {
      not_reported: "ಯಾರೂ ಇದನ್ನು PayGuard ಗೆ ವರದಿ ಮಾಡಿಲ್ಲ", link_not_listed: "ಲಿಂಕ್ Google ನ ಅಪಾಯ ಪಟ್ಟಿಯಲ್ಲಿಲ್ಲ",
      sender_ok: "ಸಂಸ್ಥೆಯ ನೋಂದಾಯಿತ SMS ಕಳುಹಿಸುವವರಿಂದ ಬಂದಿದೆ", no_links: "ತೆರೆಯಲು ಯಾವುದೇ ಲಿಂಕ್ ಇಲ್ಲ",
      no_asks: "OTP, PIN, ಹಣ ಅಥವಾ ಆ್ಯಪ್ ಕೇಳುವುದಿಲ್ಲ", upi_valid: "ಪಾವತಿ ಲಿಂಕ್ ಸರಿಯಾದ ರೂಪದಲ್ಲಿದೆ", official: "ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್‌ಗೆ ಹೋಗುತ್ತದೆ",
      no_editing: "ಫೈಲ್‌ನಲ್ಲಿ ಎಡಿಟ್ ಗುರುತುಗಳಿಲ್ಲ", pixels_ok: "ಅಂಕಿ ಮತ್ತು ಅಕ್ಷರಗಳು ಬದಲಾದಂತಿಲ್ಲ", status_ok: "ಪಾವತಿ ಸ್ಥಿತಿ ಪೂರ್ಣ ಎಂದು ತೋರಿಸುತ್ತದೆ",
      amount_ok: "ರಸೀದಿಯ ಮೊತ್ತಗಳು ಹೊಂದುತ್ತವೆ", date_ok: "ದಿನಾಂಕ ಮತ್ತು ಸಮಯ ಸರಿಯಾಗಿವೆ", utr_ok: "ಉಲ್ಲೇಖ ಸಂಖ್ಯೆ ಸರಿಯಾಗಿದೆ",
      qr_ok: "ರಸೀದಿಯ QR ಕೋಡ್ ಹೊಂದುತ್ತದೆ", history_ok: "ಹಳೆಯ ರಸೀದಿಯ ನಕಲಲ್ಲ",
      not_confirmed: "ಬ್ಯಾಂಕ್ ಪಾವತಿಯನ್ನು ದೃಢೀಕರಿಸಿಲ್ಲ: ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಆ್ಯಪ್ ನೋಡಿ", no_triad: "SMS ಓದುವುದು, ಪರದೆ ನಿಯಂತ್ರಣ ಮತ್ತು ಓವರ್‌ಲೇ ಒಟ್ಟಿಗೆ ಇಲ್ಲ",
      signed_ok: "ಆ್ಯಪ್ ಸರಿಯಾಗಿ ಸಹಿ ಮಾಡಲಾಗಿದೆ", none: "PayGuard ಪರಿಶೀಲನೆಯಲ್ಲಿ ಯಾವುದೇ ಎಚ್ಚರಿಕೆ ಇಲ್ಲ", ml_ok: "ಮಾದರಿ ಪರಿಶೀಲನೆ: ಸಾಮಾನ್ಯ ಪಾವತಿಯಂತಿದೆ",
    },
  };
  const L = (lang) => (LABEL[lang] ? lang : "en");
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const tr = (o, lang) => (o && (o[lang] || o.en)) || "";

  /** The zone to show. A screenshot that looks fine is never "very low": a screenshot can't prove a payment. */
  function level(r) {
    let lv = (r && r.verdict && r.verdict.level) || "caution";
    const vs = r && r.kind === "shot" && r.verification ? r.verification.status : null;
    if (vs === "SUSPICIOUS" && ZONES.indexOf(lv) < 2) lv = "suspicious";
    if (vs === "UNVERIFIED" && lv === "low") lv = "caution";
    if (vs === "VERIFIED") lv = "low";
    return lv;
  }
  const label = (lv, lang) => LABEL[L(lang)][lv] || LABEL.en[lv];

  /** Speedometer-style dial: four coloured zones, tick marks, a needle, no numbers. */
  function svg(lv, opts = {}) {
    const lang = L(opts.lang);
    const cx = 100, cy = 100, R = 80, W = 16;
    const pt = (deg, r) => { const a = (Math.PI * (180 - deg)) / 180; return [cx + r * Math.cos(a), cy - r * Math.sin(a)]; };
    const arc = (d0, d1) => { const [x0, y0] = pt(d0, R), [x1, y1] = pt(d1, R); return `M${x0.toFixed(1)} ${y0.toFixed(1)}A${R} ${R} 0 0 1 ${x1.toFixed(1)} ${y1.toFixed(1)}`; };
    const idx = Math.max(0, ZONES.indexOf(lv));
    const zones = ZONES.map((z, i) => {
      const d0 = i * 45 + 1.5, d1 = (i + 1) * 45 - 1.5;
      return `<path d="${arc(d0, d1)}" class="pm-zone${i === idx ? " on" : ""}" style="color:${COLORS[z]}" stroke="${COLORS[z]}" stroke-width="${W}"/>`;
    }).join("");
    let ticks = "";
    for (let d = 0; d <= 180; d += 15) {
      const major = d % 45 === 0, [x0, y0] = pt(d, R - W / 2 - 4), [x1, y1] = pt(d, R - W / 2 - (major ? 13 : 8));
      ticks += `<line x1="${x0.toFixed(1)}" y1="${y0.toFixed(1)}" x2="${x1.toFixed(1)}" y2="${y1.toFixed(1)}" class="pm-tick${major ? " major" : ""}"/>`;
    }
    const angle = idx * 45 + 22.5;                    // middle of the zone: deliberately not a precise value
    const t = label(lv, lang);
    return `<svg class="pm-dial" viewBox="0 0 200 128" role="img" aria-label="${esc(t)}">
      <path d="${arc(0.5, 179.5)}" class="pm-track" stroke-width="${W + 6}"/>${zones}${ticks}
      <text x="22" y="122" class="pm-end">${esc(LABEL[lang].lo)}</text><text x="178" y="122" class="pm-end" text-anchor="end">${esc(LABEL[lang].hi)}</text>
      <g class="pm-needle" style="--a:${angle - 90}deg; --c:${COLORS[lv] || "#fff"}">
        <path d="M${cx - 4} ${cy} L${cx} ${cy - R + W + 4} L${cx + 4} ${cy} Z"/><circle cx="${cx}" cy="${cy}" r="9"/><circle cx="${cx}" cy="${cy}" r="4" class="pm-hub"/>
      </g></svg>`;
  }

  // ---------------------------------------------------------------- checkpoints: why it landed in that zone
  const BAD_SEV = { critical: 0, high: 1, medium: 2 };

  function warnings(r, lang) {
    if (r.kind === "msg" && r.risk && r.risk.factors) {
      return r.risk.factors.filter((f) => f.severity in BAD_SEV).map((f) => ({ ok: false, sev: f.severity, text: tr(f.title, lang) }));
    }
    return (r.findings || []).filter((f) => f.severity in BAD_SEV).sort((a, b) => BAD_SEV[a.severity] - BAD_SEV[b.severity])
      .map((f) => ({ ok: false, sev: f.severity, text: tr(f.title, lang) }));
  }

  function goods(r) {
    const g = [], d = r.details || {}, ids = new Set((r.findings || []).map((f) => f.id));
    const reported = (r.community && r.community.reports) || 0;
    if (r.kind === "msg") {
      const lay = (r.risk && r.risk.layers) || {}, s = d.sender || {};
      if (!(d.asks || []).length) g.push("no_asks");
      if (!(d.links || []).length) g.push("no_links");
      else if ((lay.threat_intel || {}).status === "ok" && !((r.sms || {}).threat_intel || {}).matches?.length) g.push("link_not_listed");
      if (s.matches_claim) g.push("sender_ok");
      if ((lay.memory || {}).status === "ok" && !((r.sms || {}).memory || {}).found && !reported) g.push("not_reported");
    } else if (r.kind === "qr") {
      if (d.type === "upi" && d.upi_format && d.upi_format.valid) g.push("upi_valid");
      if (d.official) g.push("official");
      if (r.ml && r.ml.status === "ok" && r.ml.prediction === "Legitimate") g.push("ml_ok");
      if (!reported) g.push("not_reported");
    } else if (r.kind === "shot" && r.verification) {
      const map = { metadata: "no_editing", pixels: "pixels_ok", status: "status_ok", amount: "amount_ok", datetime: "date_ok",
        reference: "utr_ok", qr: "qr_ok", history: "history_ok" };
      r.verification.checks.forEach((c) => { if (c.status === "pass" && map[c.id]) g.push(map[c.id]); });
    } else if (r.kind === "apk" || !r.kind) {
      if (!ids.has("BANKING_TROJAN_TRIAD")) g.push("no_triad");
      if (!ids.has("UNSIGNED") && !ids.has("DEBUG_CERTIFICATE")) g.push("signed_ok");
      if (!reported) g.push("not_reported");
    }
    return g;
  }

  /** Up to `max` plain-language checkpoints: warnings first (✗), then what checked out fine (✓). */
  function checkpoints(r, lang, max = 5) {
    lang = L(lang);
    const W = GOOD[lang] || GOOD.en, out = [];
    const seen = new Set();
    for (const w of warnings(r, lang)) { if (w.text && !seen.has(w.text)) { seen.add(w.text); out.push(w); } }
    const bad = out.slice(0, out.length > 2 ? max - 1 : max - 2);
    const notice = r.kind === "shot" && r.verification && r.verification.status === "UNVERIFIED" ? [{ ok: null, text: W.not_confirmed }] : [];
    let good = goods(r).map((k) => ({ ok: true, text: W[k] || GOOD.en[k] }));
    if (level(r) === "danger" && out.length >= 3) return out.slice(0, max);   // high risk: just say why, no mixed signals
    if (!bad.length && !good.length) good = [{ ok: true, text: W.none }];
    return [...notice, ...bad, ...good].slice(0, max);
  }

  function checkpointsHTML(r, lang, max) {
    return `<ul class="pm-cps">${checkpoints(r, lang, max).map((c) =>
      `<li class="${c.ok === true ? "ok" : c.ok === false ? "bad" : "note"}"><span class="pm-ic" aria-hidden="true">${c.ok === true ? "✓" : c.ok === false ? "✗" : "!"}</span><span>${esc(c.text)}</span></li>`).join("")}</ul>`;
  }

  window.PGMeter = { ZONES, COLORS, level, label, svg, checkpoints, checkpointsHTML };
})();
