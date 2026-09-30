"""URL verification (heuristics) for links found in messages. Nothing is opened or fetched.

check_url(parts) -> {"url", "domain", "official", "level", "signals": [...]}

Each link goes through PayGuard's existing link checks (qr.analyzer: fake brand domains, IP hosts, punycode, "@"
tricks, link shorteners, throw-away domains, bait words, APK downloads, no https, deep subdomains) plus the extra
checks below that matter for SMS phishing. Every signal is a hint with a weight, never proof on its own: the risk
engine (risk.py) decides how signals combine.
"""
from __future__ import annotations

import re

from ..analyzer.rules import T
from ..qr.analyzer import BRAND_DOMAINS, SHORTENERS, analyze_payload

# official domains of brands scammers copy (registrable part); used for the typosquatting check
OFFICIAL = sorted({d for doms in BRAND_DOMAINS.values() for d in doms} | {
    "airtel.in", "jio.com", "bsnl.co.in", "irctc.co.in", "epfindia.gov.in", "pnbindia.in", "bankofbaroda.in",
    "canarabank.com", "unionbankofindia.co.in", "idfcfirstbank.com", "indusind.com", "yesbank.in", "licindia.in",
    "myntra.com", "swiggy.com", "zomato.com", "netflix.com", "apple.com", "microsoft.com", "instagram.com",
    "facebook.com", "icicidirect.com", "zerodha.com", "groww.in", "mobikwik.com", "cred.club", "bhimupi.org.in"})
_BRAND_LABELS = sorted({d.split(".")[0] for d in OFFICIAL if len(d.split(".")[0]) >= 4})
_CONFUSABLE = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("7", "t"), ("@", "a"), ("$", "s")]
EXECUTABLE = (".exe", ".scr", ".bat", ".cmd", ".msi", ".jar", ".vbs", ".ps1", ".dmg", ".pif", ".com.exe")
REDIRECT_KEYS = {"url", "u", "redirect", "redirect_uri", "redirect_url", "redir", "next", "goto", "target", "dest",
                 "destination", "continue", "return", "returnurl", "return_url", "r", "link", "out", "to"}


def _sig(id_, sev, pts, title, detail, ev):
    return {"id": id_, "severity": sev, "points": pts, "title": title, "detail": detail, "evidence": [e for e in ev if e]}


def _dl(a: str, b: str) -> int:
    """Damerau-Levenshtein distance (optimal string alignment), small strings only."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def _unconfuse(s: str) -> str:
    s = s.lower().replace("-", "")
    for a, b in _CONFUSABLE:
        s = s.replace(a, b)
    return s


def typosquat_of(reg: str) -> str | None:
    """Official domain this registrable domain imitates by a small misspelling (hdfcbnak.com, paytrn.in, 0nlinesbi...)."""
    if not reg or reg in OFFICIAL:
        return None
    label = reg.split(".")[0]
    if label.startswith("xn--") or len(label) < 4:
        return None
    norm = _unconfuse(label)
    tokens = re.split(r"[-_]", label.lower())
    for b in _BRAND_LABELS:
        if label == b:
            return None                                  # same name on another ending (e.g. .in): not a misspelling
        limit = 1 if len(b) <= 7 else 2
        close = lambda x: x == b or (abs(len(x) - len(b)) <= limit and _dl(x, b) <= limit)
        if close(norm) or (len(tokens) > 1 and any(close(_unconfuse(tok)) for tok in tokens if len(tok) >= 4)):
            return min((o for o in OFFICIAL if o.split(".")[0] == b), key=len)
    return None


def is_official(host: str, reg: str) -> bool:
    return reg in OFFICIAL or any(host == o or host.endswith("." + o) for o in OFFICIAL) or host.endswith((".gov.in", ".nic.in"))


def extra_signals(p: dict, official: bool) -> list[dict]:
    """Checks the existing link rules don't cover."""
    S = []
    reg, host, path, query = p["registered_domain"], p["host"], p["path"], p["query"]
    sq = typosquat_of(reg) if not official and not p["is_ip"] else None
    if sq:
        S.append(_sig("TYPOSQUAT_DOMAIN", "high", 25,
                      T(f"Misspelled copy of {sq}", f"{sq} की ग़लत वर्तनी वाली नकल", f"{sq} ನ ತಪ್ಪು ಕಾಗುಣಿತದ ನಕಲು"),
                      T(f"“{reg}” differs from the real {sq} by a letter or two. Scammers register such look-alike names hoping you won't notice.",
                        f"“{reg}” असली {sq} से एक-दो अक्षर अलग है। ठग ऐसे मिलते-जुलते नाम इसलिए रखते हैं ताकि आप ध्यान न दें।",
                        f"“{reg}” ನಿಜವಾದ {sq} ಗಿಂತ ಒಂದೆರಡು ಅಕ್ಷರ ಬೇರೆ. ನೀವು ಗಮನಿಸಬಾರದೆಂದು ವಂಚಕರು ಇಂತಹ ಹೆಸರು ನೋಂದಾಯಿಸುತ್ತಾರೆ."),
                      [f"Link domain: {reg}", f"Real domain: {sq}"]))
    if p["is_ip"] and re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", host, re.I):
        S.append(_sig("DISGUISED_IP", "high", 25,
                      T("Server address written as one long number", "सर्वर का पता एक लंबे नंबर में छिपाया गया है", "ಸರ್ವರ್ ವಿಳಾಸವನ್ನು ಒಂದು ಉದ್ದ ಸಂಖ್ಯೆಯಾಗಿ ಬರೆಯಲಾಗಿದೆ"),
                      T("Writing an IP address as a single number hides that there is no website name at all. Legitimate companies never do this.",
                        "IP पते को एक नंबर में लिखकर यह छिपाया जाता है कि कोई वेबसाइट नाम ही नहीं है। असली कंपनियाँ ऐसा नहीं करतीं।",
                        "IP ವಿಳಾಸವನ್ನು ಒಂದೇ ಸಂಖ್ಯೆಯಾಗಿ ಬರೆದು ವೆಬ್‌ಸೈಟ್ ಹೆಸರೇ ಇಲ್ಲ ಎಂಬುದನ್ನು ಮರೆಮಾಡಲಾಗುತ್ತದೆ. ನಿಜವಾದ ಕಂಪನಿಗಳು ಹೀಗೆ ಮಾಡುವುದಿಲ್ಲ."),
                      [f"Host: {host}"]))
    if p["port"] and p["port"] not in (80, 443):
        S.append(_sig("UNUSUAL_PORT", "medium", 10,
                      T("Link uses an unusual server port", "लिंक असामान्य सर्वर पोर्ट इस्तेमाल करता है", "ಲಿಂಕ್ ಅಸಾಮಾನ್ಯ ಸರ್ವರ್ ಪೋರ್ಟ್ ಬಳಸುತ್ತದೆ"),
                      T("Normal websites don't put a port number (like :8080) in their links; throw-away phishing servers often do.",
                        "सामान्य वेबसाइटें लिंक में पोर्ट नंबर (जैसे :8080) नहीं डालतीं; अस्थायी फ़िशिंग सर्वर अक्सर डालते हैं।",
                        "ಸಾಮಾನ್ಯ ವೆಬ್‌ಸೈಟ್‌ಗಳು ಲಿಂಕ್‌ನಲ್ಲಿ ಪೋರ್ಟ್ ಸಂಖ್ಯೆ (:8080) ಹಾಕುವುದಿಲ್ಲ; ತಾತ್ಕಾಲಿಕ ಫಿಶಿಂಗ್ ಸರ್ವರ್‌ಗಳು ಹಾಕುತ್ತವೆ."),
                      [f"Port: {p['port']}"]))
    redir = [x for x in p["params"] if x["name"].lower() in REDIRECT_KEYS and re.search(r"(https?:|%3a%2f%2f|www\.|\.[a-z]{2,}/)", x["value"], re.I)]
    if redir:
        S.append(_sig("REDIRECT_LINK", "medium", 12,
                      T("Link forwards you to another website", "लिंक आपको दूसरी वेबसाइट पर भेज देता है", "ಲಿಂಕ್ ನಿಮ್ಮನ್ನು ಬೇರೆ ವೆಬ್‌ಸೈಟ್‌ಗೆ ಕಳುಹಿಸುತ್ತದೆ"),
                      T("A parameter in the link carries a second address. Redirects are used to pass a trusted-looking link through filters and then land you somewhere else.",
                        "लिंक के अंदर एक दूसरा पता है। रीडायरेक्ट से भरोसेमंद दिखने वाला लिंक फ़िल्टर पार करके आपको कहीं और पहुँचा देता है।",
                        "ಲಿಂಕ್‌ನೊಳಗೆ ಇನ್ನೊಂದು ವಿಳಾಸ ಇದೆ. ನಂಬಲರ್ಹವಾಗಿ ಕಾಣುವ ಲಿಂಕ್ ಫಿಲ್ಟರ್ ದಾಟಿ ನಿಮ್ಮನ್ನು ಬೇರೆಡೆ ಕರೆದೊಯ್ಯಲು ರೀಡೈರೆಕ್ಟ್ ಬಳಸುತ್ತಾರೆ."),
                      [f"{x['name']}={x['value'][:80]}" for x in redir[:2]]))
    enc_host = "%" in p["url"].split("/")[2] if p["url"].count("/") >= 2 else False
    pct = len(re.findall(r"%[0-9a-f]{2}", path + "?" + query, re.I))
    b64 = [x for x in p["params"] if re.fullmatch(r"[A-Za-z0-9+/_\-]{40,}={0,2}", x["value"] or "")]
    if enc_host or re.search(r"%25[0-9a-f]{2}|%2e|%2f|%40|%5c", path, re.I) or pct >= 8 or b64:
        S.append(_sig("ENCODED_LINK", "medium", 10,
                      T("Parts of the link are encoded to hide them", "लिंक के हिस्से छिपाने के लिए कोड में लिखे गए हैं", "ಲಿಂಕ್‌ನ ಭಾಗಗಳನ್ನು ಮರೆಮಾಡಲು ಎನ್‌ಕೋಡ್ ಮಾಡಲಾಗಿದೆ"),
                      T("Heavily encoded characters (%2F, %2E, long random strings) make a link hard to read and are used to slip past filters.",
                        "बहुत ज़्यादा कोड किए गए अक्षर (%2F, %2E, लंबी बेतरतीब स्ट्रिंग) लिंक को पढ़ना मुश्किल बनाते हैं और फ़िल्टर से बचने में काम आते हैं।",
                        "ಅತಿಯಾಗಿ ಎನ್‌ಕೋಡ್ ಮಾಡಿದ ಅಕ್ಷರಗಳು (%2F, %2E, ಉದ್ದ ಯಾದೃಚ್ಛಿಕ ಸ್ಟ್ರಿಂಗ್) ಲಿಂಕ್ ಓದಲು ಕಷ್ಟ ಮಾಡುತ್ತವೆ, ಫಿಲ್ಟರ್ ತಪ್ಪಿಸಲು ಬಳಸುತ್ತಾರೆ."),
                      [f"Encoded characters: {pct}" if pct else "", "Long encoded value in the link" if b64 else ""]))
    if path.lower().endswith(EXECUTABLE):
        S.append(_sig("EXECUTABLE_LINK", "high", 25,
                      T("Link downloads a program file", "लिंक एक प्रोग्राम फ़ाइल डाउनलोड करता है", "ಲಿಂಕ್ ಪ್ರೋಗ್ರಾಂ ಫೈಲ್ ಡೌನ್‌ಲೋಡ್ ಮಾಡುತ್ತದೆ"),
                      T("A message link that downloads a program (.exe, .jar, .bat...) is a common way to install malware.",
                        "प्रोग्राम (.exe, .jar, .bat...) डाउनलोड करने वाला मैसेज लिंक मैलवेयर इंस्टॉल कराने का आम तरीका है।",
                        "ಪ್ರೋಗ್ರಾಂ (.exe, .jar, .bat...) ಡೌನ್‌ಲೋಡ್ ಮಾಡುವ ಸಂದೇಶ ಲಿಂಕ್ ಮಾಲ್‌ವೇರ್ ಅಳವಡಿಸುವ ಸಾಮಾನ್ಯ ದಾರಿ."),
                      [f"File: {path.rsplit('/', 1)[-1][:80]}"]))
    label = reg.split(".")[0]
    if not official and not p["is_ip"] and (len(label) > 24 or label.count("-") >= 3):
        S.append(_sig("LONG_DOMAIN", "low", 6,
                      T("Unusually long or hyphen-heavy website name", "असामान्य रूप से लंबा या कई हाइफ़न वाला वेबसाइट नाम", "ಅಸಾಮಾನ್ಯವಾಗಿ ಉದ್ದ ಅಥವಾ ಹೆಚ್ಚು ಹೈಫನ್ ಇರುವ ವೆಬ್‌ಸೈಟ್ ಹೆಸರು"),
                      T("Names like 'secure-kyc-update-verify-now' are built to look official. Real brands use short names.",
                        "'secure-kyc-update-verify-now' जैसे नाम आधिकारिक दिखने के लिए बनाए जाते हैं। असली ब्रांड छोटे नाम रखते हैं।",
                        "'secure-kyc-update-verify-now' ನಂತಹ ಹೆಸರುಗಳು ಅಧಿಕೃತವಾಗಿ ಕಾಣಲು ಮಾಡಿದವು. ನಿಜವಾದ ಬ್ರ್ಯಾಂಡ್‌ಗಳು ಚಿಕ್ಕ ಹೆಸರು ಬಳಸುತ್ತವೆ."),
                      [f"Domain: {reg}"]))
    if p.get("obfuscation"):
        S.append(_sig("OBFUSCATED_LINK", "medium", 15,
                      T("Link is written in a disguised way", "लिंक छिपे हुए तरीके से लिखा गया है", "ಲಿಂಕ್ ಅನ್ನು ಮರೆಮಾಚಿ ಬರೆಯಲಾಗಿದೆ"),
                      T("The link is broken up (hxxp, [.], invisible characters) so that spam filters don't recognise it. Genuine senders don't do this.",
                        "लिंक को तोड़कर लिखा गया है (hxxp, [.], अदृश्य अक्षर) ताकि स्पैम फ़िल्टर पहचान न सकें। असली भेजने वाले ऐसा नहीं करते।",
                        "ಸ್ಪ್ಯಾಮ್ ಫಿಲ್ಟರ್ ಗುರುತಿಸದಂತೆ ಲಿಂಕ್ ಅನ್ನು ಒಡೆದು ಬರೆಯಲಾಗಿದೆ (hxxp, [.], ಅದೃಶ್ಯ ಅಕ್ಷರಗಳು). ನಿಜವಾದವರು ಹೀಗೆ ಮಾಡುವುದಿಲ್ಲ."),
                      [f"Link: {p['host']}", "Tricks: " + ", ".join(p["obfuscation"])]))
    return S


def check_url(p: dict) -> dict:
    """Existing link rules + extra heuristics for one parsed link."""
    try:
        r = analyze_payload(p["url"])
        d, base = r["details"], r["findings"]
        level, score = r["verdict"]["level"], r["verdict"]["score"]
    except Exception:
        d, base, level, score = {}, [], "caution", 0
    official = bool(d.get("official")) or is_official(p["host"], p["registered_domain"])
    extra = extra_signals(p, official)
    if any(f["id"] == "LOOKALIKE_DOMAIN" for f in base):      # already flagged as a fake brand site: don't count twice
        extra = [x for x in extra if x["id"] != "TYPOSQUAT_DOMAIN"]
    signals = [{"id": f["id"], "severity": f["severity"], "points": f["points"], "title": f["title"], "source": "link_rules"}
               for f in base if f["severity"] != "info"]
    signals += [{"id": s["id"], "severity": s["severity"], "points": s["points"], "title": s["title"], "source": "url_heuristics"} for s in extra]
    return {
        "url": p["url"], "raw": p["raw"], "host": p["host"], "domain": p["registered_domain"], "path": p["path"],
        "query": p["query"][:200], "subdomain_levels": p["subdomain_levels"], "is_ip": p["is_ip"], "idn": p["idn"],
        "port": p["port"], "https": p["scheme"] == "https", "official": official,
        "shortener": p["host"] in SHORTENERS or p["registered_domain"] in SHORTENERS,
        "whatsapp": p["registered_domain"] in ("wa.me", "whatsapp.com"),
        "rule_level": level, "rule_score": score, "signals": signals, "extra": extra,
    }
