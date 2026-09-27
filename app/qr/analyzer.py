"""PayPause: QR code / UPI link / URL scam analysis.

decode_qr_image(bytes) -> list[str]         (OpenCV, several pre-processing passes)
analyze_payload(text)  -> report dict       (UPI intent, URL, tel/sms/wifi/text)

The core fact this module teaches the user: scanning a UPI QR code or
approving a UPI request ALWAYS sends money out of your account. Nobody ever
needs your QR scan or UPI PIN to send you money.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import parse_qs, unquote, urlsplit

from ..analyzer.rules import SEVERITY_ORDER, T, Finding

# ---------------------------------------------------------------- knowledge

KNOWN_PSP_HANDLES = {
    # PhonePe, Google Pay, Paytm, BHIM, Amazon Pay, WhatsApp Pay, banks, fintechs
    "ybl", "ibl", "axl", "okaxis", "okhdfcbank", "okicici", "oksbi", "okbizaxis", "paytm", "pthdfc", "ptaxis",
    "ptyes", "ptsbi", "upi", "apl", "yapl", "rapl", "axisbank", "axisb", "icici", "sbi", "hdfcbank", "kotak",
    "kbl", "federal", "fbl", "idfcbank", "idfcfirst", "indus", "boi", "pnb", "barodampay", "cnrb", "unionbank",
    "uboi", "yesbank", "yescred", "ikwik", "freecharge", "airtel", "jio", "jupiteraxis", "fam", "slice",
    "naviaxis", "waicici", "waaxis", "wahdfcbank", "wasbi", "aubank", "dbs", "citi", "hsbc", "sc", "rbl",
    "equitas", "ujjivan", "abfspay", "superyes", "tapicici", "mbk", "pingpay", "timecosmos", "ratn", "idbi",
    "centralbank", "cboi", "indianbank", "iob", "ucobank", "psb", "dlb", "kvb", "tjsb", "saraswat", "hdfcbankjd",
    "icicipay", "pockets", "myicici", "cmsidfc", "axisbiz", "payzapp", "kmbl", "sib", "csbpay", "jkb", "ezeepay",
}
MERCHANT_VPA_HINTS = ("paytmqr", "bharatpe", "q.", "pinelabs", "razorpay", "cashfree", "mswipe", "gpay-", "merchant",
                      "biz", "shop", "store", ".rzp", "payu", "phonepemerchant", "ezetap", "yespay.", "mab.")

LURE_WORDS = [
    "refund", "cashback", "cash back", "reward", "prize", "lottery", "winning", "winner", "won", "receive",
    "received", "credit", "credited", "bonus", "kyc", "verify", "verification", "unblock", "blocked", "gift",
    "lucky", "offer", "claim", "customs", "parcel", "security deposit", "advance", "army", "registration fee",
    "processing fee", "electricity", "bill pending", "disconnection", "income tax", "rebate", "scholarship",
    "loan approved", "job", "task", "investment", "double",
]
AUTHORITY_WORDS = ["customer care", "customer support", "helpline", "support", "care", "refund", "police", "cyber cell",
                   "government", "govt", "income tax", "electricity", "bescom", "mpeb", "rbi", "npci", "sbi", "hdfc",
                   "icici", "axis", "kotak", "paytm", "phonepe", "google pay", "gpay", "amazon", "flipkart", "olx",
                   "courier", "india post", "fedex", "bluedart", "delhivery"]

SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "t.ly", "is.gd", "rb.gy", "shorturl.at", "tiny.cc", "ow.ly",
              "rebrand.ly", "s.id", "shrtco.de", "v.gd", "qr.io", "qrco.de", "short.gy", "bitly.com", "t.co",
              "surl.li", "u.to", "clck.ru", "lnkd.in", "urlz.fr", "goo.su"}
SUSPICIOUS_TLDS = (".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".click", ".icu", ".rest", ".cyou",
                   ".sbs", ".monster", ".work", ".link", ".live", ".online", ".site", ".shop", ".store", ".fun",
                   ".vip", ".win", ".loan", ".support", ".help", ".info", ".cc", ".pw", ".ngrok.io",
                   ".ngrok-free.app", ".trycloudflare.com", ".duckdns.org", ".000webhostapp.com", ".web.app",
                   ".firebaseapp.com", ".netlify.app", ".vercel.app", ".glitch.me", ".weebly.com", ".blogspot.com")
URL_BAIT_WORDS = ["kyc", "refund", "reward", "verify", "update", "login", "secure", "bonus", "gift", "offer", "claim",
                  "prize", "cashback", "unblock", "pan", "aadhaar", "aadhar", "challan", "bill", "electricity", "otp",
                  "account", "wallet", "free", "win", "lucky", "parcel", "customs", "tax"]
BRAND_DOMAINS = {
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "yonobusiness.sbi", "sbicard.com"],
    "yono": ["sbi.co.in", "onlinesbi.sbi", "yonobusiness.sbi"],
    "hdfc": ["hdfcbank.com", "hdfc.com", "hdfcbank.bank.in"], "icici": ["icicibank.com", "icicibank.bank.in"],
    "axis": ["axisbank.com", "axisbank.bank.in"], "kotak": ["kotak.com", "kotak.bank.in"],
    "paytm": ["paytm.com", "paytm.in", "paytmbank.com"], "phonepe": ["phonepe.com"],
    "gpay": ["google.com", "pay.google.com"], "googlepay": ["google.com"], "npci": ["npci.org.in"],
    "bhim": ["bhimupi.org.in", "npci.org.in"], "uidai": ["uidai.gov.in"], "aadhaar": ["uidai.gov.in"],
    "incometax": ["incometax.gov.in"], "indiapost": ["indiapost.gov.in"], "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"], "whatsapp": ["whatsapp.com", "wa.me"], "rbi": ["rbi.org.in"],
    "parivahan": ["parivahan.gov.in"], "echallan": ["parivahan.gov.in"], "bescom": ["bescom.co.in", "bescom.karnataka.gov.in"],
}

VPA_RE = re.compile(r"^[A-Za-z0-9.\-_]{2,256}@[A-Za-z0-9]{2,64}$")


# ---------------------------------------------------------------- decoding

def decode_qr_image(data: bytes) -> list[str]:
    import cv2
    import numpy as np

    arr = np.frombuffer(data, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Could not read this image. Please upload a PNG or JPG screenshot of the QR code.")
    h, w = img.shape[:2]
    if max(h, w) > 2400:
        s = 2400 / max(h, w)
        img = cv2.resize(img, (int(w * s), int(h * s)), interpolation=cv2.INTER_AREA)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    variants = [img, gray,
                cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC),
                cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 5),
                cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1],
                255 - gray]
    det = cv2.QRCodeDetector()
    found: list[str] = []
    for v in variants:
        try:
            ok, texts, _, _ = det.detectAndDecodeMulti(v)
            if ok:
                found += [t for t in texts if t]
            if not found:
                t, _, _ = det.detectAndDecode(v)
                if t:
                    found.append(t)
        except Exception:
            continue
        if found:
            break
    seen, out = set(), []
    for t in found:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


# ---------------------------------------------------------------- helpers

def _has_word(text: str, words: list[str]) -> list[str]:
    low = text.lower()
    return [w for w in words if re.search(rf"(?<![a-z]){re.escape(w)}(?![a-z])", low)]


def _host_is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "gov", "org", "net", "ac", "nic", "bank", "edu", "res") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ---------------------------------------------------------------- UPI

def _analyze_upi(text: str) -> tuple[dict, list[Finding]]:
    sp = urlsplit(text)
    action = (sp.netloc or sp.path.strip("/")).lower() or "pay"
    q = {k.lower(): unquote(v[0]).strip() for k, v in parse_qs(sp.query, keep_blank_values=True).items()}
    pa, pn = q.get("pa", ""), q.get("pn", "")
    am, tn, mc = q.get("am", ""), q.get("tn", ""), q.get("mc", "")
    handle = pa.split("@")[-1].lower() if "@" in pa else ""
    local = pa.split("@")[0].lower() if "@" in pa else ""
    amount = None
    try:
        amount = float(am) if am else None
    except ValueError:
        pass
    is_merchant = bool(mc and mc != "0000") or bool(q.get("sign")) or any(h in pa.lower() for h in MERCHANT_VPA_HINTS)
    phone_vpa = bool(re.fullmatch(r"(\+?91)?[6-9]\d{9}", local))
    details = {
        "type": "upi", "action": action, "payee_vpa": pa, "payee_name": pn, "amount": amount, "currency": q.get("cu") or "INR",
        "note": tn, "merchant_code": mc or None, "transaction_ref": q.get("tr") or None, "signed": bool(q.get("sign")),
        "is_merchant": is_merchant, "psp_handle": handle, "known_psp": handle in KNOWN_PSP_HANDLES,
        "money_direction": "out", "params": q,
    }
    F: list[Finding] = []
    amt_en = f"₹{amount:,.2f}" if amount else "money"
    amt_hi = f"₹{amount:,.2f}" if amount else "पैसे"
    amt_kn = f"₹{amount:,.2f}" if amount else "ಹಣ"

    # Always: direction of money
    F.append(Finding(
        "MONEY_GOES_OUT", "info", 0,
        T(f"Scanning this sends {amt_en} FROM your account", f"इसे स्कैन करने से आपके खाते से {amt_hi} जाएँगे",
          f"ಇದನ್ನು ಸ್ಕ್ಯಾನ್ ಮಾಡಿದರೆ ನಿಮ್ಮ ಖಾತೆಯಿಂದ {amt_kn} ಹೋಗುತ್ತದೆ"),
        T("A UPI QR code is always a request for YOU to pay. You never scan a QR code or enter your UPI PIN to receive money.",
          "UPI QR कोड हमेशा आपसे पैसे भेजने की माँग होता है। पैसे पाने के लिए कभी QR स्कैन या UPI PIN डालने की ज़रूरत नहीं होती।",
          "UPI QR ಕೋಡ್ ಯಾವಾಗಲೂ ನೀವು ಹಣ ಪಾವತಿಸುವ ವಿನಂತಿ. ಹಣ ಪಡೆಯಲು QR ಸ್ಕ್ಯಾನ್ ಅಥವಾ UPI PIN ಎಂದಿಗೂ ಬೇಕಾಗುವುದಿಲ್ಲ."),
        [f"Payee: {pn or '(no name)'} <{pa or '?'}>"] + ([f"Amount: {amt_en}"] if amount else []),
    ))

    if action in ("mandate", "autopay") or q.get("recur") or q.get("mn"):
        F.append(Finding(
            "AUTOPAY_MANDATE", "critical", 45,
            T("Sets up AUTOMATIC repeated payments from your account", "आपके खाते से अपने-आप बार-बार पैसे कटने की मंज़ूरी लेता है",
              "ನಿಮ್ಮ ಖಾತೆಯಿಂದ ಸ್ವಯಂಚಾಲಿತ ಪುನರಾವರ್ತಿತ ಪಾವತಿ ಹೊಂದಿಸುತ್ತದೆ"),
            T("This is a UPI AutoPay mandate. Approving it lets the payee take money again and again without asking you.",
              "यह UPI AutoPay मैंडेट है। इसे मंज़ूर करते ही सामने वाला बिना पूछे बार-बार पैसे निकाल सकता है।",
              "ಇದು UPI AutoPay ಮ್ಯಾಂಡೇಟ್. ಒಪ್ಪಿದರೆ ಪಾವತಿ ಪಡೆಯುವವರು ನಿಮ್ಮನ್ನು ಕೇಳದೆ ಮತ್ತೆ ಮತ್ತೆ ಹಣ ತೆಗೆಯಬಹುದು."),
            [f"Action: {action}"] + [f"{k}={v}" for k, v in q.items() if k in ("recur", "mn", "validitystart", "validityend")],
        ))
    if action == "collect":
        F.append(Finding(
            "COLLECT_REQUEST", "high", 25,
            T("This is a 'collect' request — it asks YOU to pay", "यह 'कलेक्ट' रिक्वेस्ट है — इसमें आपसे पैसे माँगे जा रहे हैं",
              "ಇದು 'ಕಲೆಕ್ಟ್' ವಿನಂತಿ — ಇದು ನಿಮ್ಮಿಂದ ಹಣ ಕೇಳುತ್ತದೆ"),
            T("Scammers send collect requests saying 'accept to receive money'. Accepting and entering your PIN pays them.",
              "ठग 'पैसे पाने के लिए स्वीकार करें' कहकर कलेक्ट रिक्वेस्ट भेजते हैं। स्वीकार करके PIN डालते ही पैसे उनके पास चले जाते हैं।",
              "ವಂಚಕರು 'ಹಣ ಪಡೆಯಲು ಒಪ್ಪಿಕೊಳ್ಳಿ' ಎಂದು ಕಲೆಕ್ಟ್ ವಿನಂತಿ ಕಳುಹಿಸುತ್ತಾರೆ. ಒಪ್ಪಿ PIN ಹಾಕಿದರೆ ಹಣ ಅವರಿಗೆ ಹೋಗುತ್ತದೆ."),
            [f"Action: {action}"],
        ))

    lure = _has_word(f"{tn} {pn}", LURE_WORDS)
    if lure:
        F.append(Finding(
            "RECEIVE_MONEY_LURE", "critical", 50,
            T("Pretends you will RECEIVE money — but you will PAY", "दिखाता है कि आपको पैसे मिलेंगे — असल में आप पैसे देंगे",
              "ನಿಮಗೆ ಹಣ ಬರುತ್ತದೆ ಎಂದು ನಟಿಸುತ್ತದೆ — ಆದರೆ ನೀವೇ ಪಾವತಿಸುತ್ತೀರಿ"),
            T("The payment note or name talks about a refund, prize, cashback or KYC. That is the classic trick: you think you are "
              "receiving money, but scanning and entering your PIN sends money to the scammer.",
              "पेमेंट नोट या नाम में रिफ़ंड, इनाम, कैशबैक या KYC की बात है। यही सबसे आम चाल है: आपको लगता है पैसे मिल रहे हैं, "
              "पर स्कैन करके PIN डालते ही पैसे ठग के पास चले जाते हैं।",
              "ಪಾವತಿ ಟಿಪ್ಪಣಿ ಅಥವಾ ಹೆಸರಿನಲ್ಲಿ ರೀಫಂಡ್, ಬಹುಮಾನ, ಕ್ಯಾಶ್‌ಬ್ಯಾಕ್ ಅಥವಾ KYC ಬಗ್ಗೆ ಇದೆ. ಇದೇ ಸಾಮಾನ್ಯ ತಂತ್ರ: ಹಣ ಬರುತ್ತಿದೆ "
              "ಎಂದು ನೀವು ಭಾವಿಸುತ್ತೀರಿ, ಆದರೆ ಸ್ಕ್ಯಾನ್ ಮಾಡಿ PIN ಹಾಕಿದರೆ ಹಣ ವಂಚಕರಿಗೆ ಹೋಗುತ್ತದೆ."),
            [f"Note: “{tn}”" if tn else "", f"Name: “{pn}”" if pn else "", "Words: " + ", ".join(lure)],
        ))

    auth = _has_word(pn, AUTHORITY_WORDS)
    if auth and not is_merchant:
        F.append(Finding(
            "IMPERSONATION", "high", 30,
            T("Name looks official, but money goes to a personal account", "नाम सरकारी/कंपनी जैसा है, पर पैसे निजी खाते में जाते हैं",
              "ಹೆಸರು ಅಧಿಕೃತದಂತೆ ಕಾಣುತ್ತದೆ, ಆದರೆ ಹಣ ವೈಯಕ್ತಿಕ ಖಾತೆಗೆ ಹೋಗುತ್ತದೆ"),
            T(f"The payee calls itself “{pn}”, but this is not a registered merchant account. Banks, companies and government "
              "offices never collect money through a personal UPI ID.",
              f"पाने वाला खुद को “{pn}” बताता है, पर यह रजिस्टर्ड मर्चेंट खाता नहीं है। बैंक, कंपनियाँ और सरकारी दफ़्तर कभी "
              "निजी UPI ID से पैसे नहीं लेते।",
              f"ಪಾವತಿ ಪಡೆಯುವವರು ತಮ್ಮನ್ನು “{pn}” ಎಂದು ಕರೆದುಕೊಳ್ಳುತ್ತಾರೆ, ಆದರೆ ಇದು ನೋಂದಾಯಿತ ವ್ಯಾಪಾರಿ ಖಾತೆ ಅಲ್ಲ. ಬ್ಯಾಂಕ್‌ಗಳು, "
              "ಕಂಪನಿಗಳು ಮತ್ತು ಸರ್ಕಾರಿ ಕಚೇರಿಗಳು ವೈಯಕ್ತಿಕ UPI ID ಮೂಲಕ ಹಣ ಪಡೆಯುವುದಿಲ್ಲ."),
            [f"UPI ID: {pa}", "Merchant code: " + (mc or "none")] + (["UPI ID is a phone number"] if phone_vpa else []),
        ))

    if not pa or not VPA_RE.match(pa):
        F.append(Finding(
            "INVALID_UPI_ID", "high", 25,
            T("The payment address is broken or missing", "पेमेंट का पता गलत है या नहीं है", "ಪಾವತಿ ವಿಳಾಸ ತಪ್ಪಾಗಿದೆ ಅಥವಾ ಇಲ್ಲ"),
            T("A genuine UPI QR always has a valid UPI ID like name@bank. This one does not.",
              "असली UPI QR में हमेशा name@bank जैसी सही UPI ID होती है। इसमें नहीं है।",
              "ನಿಜವಾದ UPI QR ನಲ್ಲಿ ಯಾವಾಗಲೂ name@bank ನಂತಹ ಸರಿಯಾದ UPI ID ಇರುತ್ತದೆ. ಇದರಲ್ಲಿ ಇಲ್ಲ."),
            [f"pa = {pa or '(missing)'}"],
        ))
    elif handle not in KNOWN_PSP_HANDLES:
        F.append(Finding(
            "UNUSUAL_UPI_HANDLE", "low", 8,
            T("Unusual UPI handle", "अनजाना UPI हैंडल", "ಅಪರಿಚಿತ UPI ಹ್ಯಾಂಡಲ್"),
            T(f"“@{handle}” is not one of the common bank / app handles we know. It may be fine, but check the name your UPI app shows.",
              f"“@{handle}” हमारे जाने-पहचाने बैंक/ऐप हैंडल में नहीं है। यह ठीक भी हो सकता है, पर UPI ऐप में दिखने वाला नाम ज़रूर जाँचें।",
              f"“@{handle}” ನಮಗೆ ತಿಳಿದಿರುವ ಸಾಮಾನ್ಯ ಬ್ಯಾಂಕ್/ಆ್ಯಪ್ ಹ್ಯಾಂಡಲ್ ಅಲ್ಲ. ಇದು ಸರಿಯಿರಬಹುದು, ಆದರೆ UPI ಆ್ಯಪ್ ತೋರಿಸುವ ಹೆಸರನ್ನು ಪರಿಶೀಲಿಸಿ."),
            [f"Handle: @{handle}"],
        ))

    if amount is not None and amount >= 10000:
        F.append(Finding(
            "LARGE_AMOUNT", "medium", 12,
            T(f"Large pre-filled amount: {amt_en}", f"पहले से भरी बड़ी रकम: {amt_hi}", f"ಮೊದಲೇ ತುಂಬಿದ ದೊಡ್ಡ ಮೊತ್ತ: {amt_kn}"),
            T("The amount is already filled in. Scammers pre-fill amounts so you just enter the PIN without thinking.",
              "रकम पहले से भरी है। ठग रकम पहले से भर देते हैं ताकि आप बिना सोचे PIN डाल दें।",
              "ಮೊತ್ತವನ್ನು ಮೊದಲೇ ತುಂಬಲಾಗಿದೆ. ನೀವು ಯೋಚಿಸದೆ PIN ಹಾಕಲೆಂದು ವಂಚಕರು ಮೊತ್ತವನ್ನು ಮೊದಲೇ ತುಂಬುತ್ತಾರೆ."),
            [f"am = {am}"],
        ))

    if re.search(r"https?://|www\.|\b[6-9]\d{9}\b", tn):
        F.append(Finding(
            "CONTACT_IN_NOTE", "medium", 12,
            T("Payment note contains a link or phone number", "पेमेंट नोट में लिंक या फ़ोन नंबर है", "ಪಾವತಿ ಟಿಪ್ಪಣಿಯಲ್ಲಿ ಲಿಂಕ್ ಅಥವಾ ಫೋನ್ ನಂಬರ್ ಇದೆ"),
            T("Real payment notes are short descriptions. A link or number is a way to pull you into a follow-up scam call.",
              "असली पेमेंट नोट छोटा विवरण होता है। लिंक या नंबर आपको आगे ठगी वाली कॉल में फँसाने के लिए होता है।",
              "ನಿಜವಾದ ಪಾವತಿ ಟಿಪ್ಪಣಿ ಚಿಕ್ಕ ವಿವರಣೆ. ಲಿಂಕ್ ಅಥವಾ ನಂಬರ್ ನಿಮ್ಮನ್ನು ಮುಂದಿನ ವಂಚನೆ ಕರೆಗೆ ಸೆಳೆಯಲು ಇರುತ್ತದೆ."),
            [f"Note: “{tn}”"],
        ))
    return details, F


# ---------------------------------------------------------------- URL

def _analyze_url(text: str) -> tuple[dict, list[Finding]]:
    raw = text.strip()
    if not re.match(r"^[a-z][a-z0-9+.\-]*://", raw, re.I):
        raw = "http://" + raw
    sp = urlsplit(raw)
    host = (sp.hostname or "").lower()
    reg = _registrable(host) if host and not _host_is_ip(host) else host
    details = {"type": "url", "url": text.strip(), "scheme": sp.scheme, "host": host, "registered_domain": reg,
               "path": sp.path, "https": sp.scheme == "https", "official": False}
    F: list[Finding] = []
    host_words = re.split(r"[.\-_]", host)

    official = False
    for brand, doms in BRAND_DOMAINS.items():
        squashed = host.replace("-", "").replace("_", "")
        if brand in host_words or (len(brand) >= 5 and brand in squashed
                                   and not any(x in squashed for x in ("amazonaws", "whatsappcdn", "paytmpayments"))):
            if any(host == d or host.endswith("." + d) for d in doms):
                official = True
            else:
                F.append(Finding(
                    "LOOKALIKE_DOMAIN", "critical", 45,
                    T(f"Fake '{brand.upper()}' website", f"नकली '{brand.upper()}' वेबसाइट", f"ನಕಲಿ '{brand.upper()}' ವೆಬ್‌ಸೈಟ್"),
                    T(f"The address uses the name “{brand}”, but it is not {brand.upper()}'s real website ({', '.join(doms[:2])}).",
                      f"पते में “{brand}” नाम है, पर यह {brand.upper()} की असली वेबसाइट ({', '.join(doms[:2])}) नहीं है।",
                      f"ವಿಳಾಸದಲ್ಲಿ “{brand}” ಹೆಸರಿದೆ, ಆದರೆ ಇದು {brand.upper()} ನ ನಿಜವಾದ ವೆಬ್‌ಸೈಟ್ ({', '.join(doms[:2])}) ಅಲ್ಲ."),
                    [f"Actual website: {reg}", "Real: " + ", ".join(doms)],
                ))
                break
    details["official"] = official
    gov = host.endswith((".gov.in", ".nic.in"))

    if sp.path.lower().endswith((".apk", ".xapk", ".apks")) or "apk" in sp.query.lower():
        F.append(Finding(
            "APK_DOWNLOAD", "high", 40,
            T("This link downloads an app file (APK)", "यह लिंक ऐप की फ़ाइल (APK) डाउनलोड करता है", "ಈ ಲಿಂಕ್ ಆ್ಯಪ್ ಫೈಲ್ (APK) ಡೌನ್‌ಲೋಡ್ ಮಾಡುತ್ತದೆ"),
            T("Apps from links (not the Play Store) are how banking trojans get onto phones. Don't install it — or check the file with APK X-Ray first.",
              "लिंक से आए ऐप (Play Store से नहीं) ही बैंकिंग ट्रोजन फ़ोन में पहुँचाते हैं। इसे इंस्टॉल न करें — या पहले APK X-Ray से जाँचें।",
              "ಲಿಂಕ್‌ನಿಂದ ಬರುವ ಆ್ಯಪ್‌ಗಳ (Play Store ಅಲ್ಲ) ಮೂಲಕವೇ ಬ್ಯಾಂಕಿಂಗ್ ಟ್ರೋಜನ್‌ಗಳು ಫೋನ್‌ಗೆ ಬರುತ್ತವೆ. ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಬೇಡಿ — ಅಥವಾ ಮೊದಲು APK X-Ray ನಲ್ಲಿ ಪರಿಶೀಲಿಸಿ."),
            [f"Path: {sp.path}"],
        ))
    if _host_is_ip(host):
        F.append(Finding(
            "IP_ADDRESS_HOST", "high", 30,
            T("Website has no name, only a number", "वेबसाइट का कोई नाम नहीं, सिर्फ़ नंबर है", "ವೆಬ್‌ಸೈಟ್‌ಗೆ ಹೆಸರಿಲ್ಲ, ಕೇವಲ ಸಂಖ್ಯೆ"),
            T("Real banks and companies always use a proper website name. A bare IP address is typical of scam servers.",
              "असली बैंक और कंपनियाँ हमेशा सही वेबसाइट नाम इस्तेमाल करती हैं। सिर्फ़ IP नंबर वाले पते ठगी के सर्वर होते हैं।",
              "ನಿಜವಾದ ಬ್ಯಾಂಕ್‌ಗಳು ಮತ್ತು ಕಂಪನಿಗಳು ಯಾವಾಗಲೂ ಸರಿಯಾದ ವೆಬ್‌ಸೈಟ್ ಹೆಸರು ಬಳಸುತ್ತವೆ. ಕೇವಲ IP ಸಂಖ್ಯೆ ವಂಚನೆ ಸರ್ವರ್‌ಗಳ ಲಕ್ಷಣ."),
            [f"Host: {host}"],
        ))
    if "xn--" in host:
        F.append(Finding(
            "PUNYCODE", "high", 30,
            T("Uses look-alike letters in the address", "पते में मिलते-जुलते नकली अक्षर हैं", "ವಿಳಾಸದಲ್ಲಿ ಒಂದೇ ರೀತಿ ಕಾಣುವ ನಕಲಿ ಅಕ್ಷರಗಳಿವೆ"),
            T("The address contains special characters that look like normal letters, to imitate a real website.",
              "पते में ऐसे खास अक्षर हैं जो सामान्य अक्षरों जैसे दिखते हैं, ताकि असली वेबसाइट की नकल हो सके।",
              "ನಿಜವಾದ ವೆಬ್‌ಸೈಟ್ ಅನ್ನು ಅನುಕರಿಸಲು ವಿಳಾಸದಲ್ಲಿ ಸಾಮಾನ್ಯ ಅಕ್ಷರಗಳಂತೆ ಕಾಣುವ ವಿಶೇಷ ಅಕ್ಷರಗಳಿವೆ."),
            [f"Host: {host}"],
        ))
    if "@" in (sp.netloc or ""):
        F.append(Finding(
            "USERINFO_TRICK", "high", 25,
            T("Address hides the real website", "पता असली वेबसाइट को छिपाता है", "ವಿಳಾಸ ನಿಜವಾದ ವೆಬ್‌ಸೈಟ್ ಮರೆಮಾಡುತ್ತದೆ"),
            T("Everything before the “@” is ignored by the browser — the real site is the part after it.",
              "“@” से पहले का सब कुछ ब्राउज़र अनदेखा करता है — असली साइट उसके बाद वाला हिस्सा है।",
              "“@” ಗಿಂತ ಮೊದಲಿನದನ್ನು ಬ್ರೌಸರ್ ಕಡೆಗಣಿಸುತ್ತದೆ — ನಿಜವಾದ ಸೈಟ್ ಅದರ ನಂತರದ ಭಾಗ."),
            [f"Real host: {host}"],
        ))
    if host in SHORTENERS or reg in SHORTENERS:
        F.append(Finding(
            "URL_SHORTENER", "medium", 15,
            T("Short link hides where it really goes", "छोटा लिंक असली मंज़िल छिपाता है", "ಚಿಕ್ಕ ಲಿಂಕ್ ನಿಜವಾದ ಗಮ್ಯಸ್ಥಾನವನ್ನು ಮರೆಮಾಡುತ್ತದೆ"),
            T("Link shorteners are often used in scam QR codes so you can't see the real website before opening it.",
              "ठगी वाले QR कोड में अक्सर छोटे लिंक होते हैं ताकि खोलने से पहले असली वेबसाइट न दिखे।",
              "ತೆರೆಯುವ ಮೊದಲು ನಿಜವಾದ ವೆಬ್‌ಸೈಟ್ ಕಾಣದಂತೆ ವಂಚನೆ QR ಕೋಡ್‌ಗಳಲ್ಲಿ ಚಿಕ್ಕ ಲಿಂಕ್‌ಗಳನ್ನು ಬಳಸಲಾಗುತ್ತದೆ."),
            [f"Shortener: {host}"],
        ))
    if host.endswith(SUSPICIOUS_TLDS) and not official:
        F.append(Finding(
            "CHEAP_DOMAIN", "medium", 15,
            T("Uses a cheap, throw-away type of web address", "सस्ता, इस्तेमाल करके फेंकने वाला वेब पता", "ಅಗ್ಗದ, ಬಿಸಾಡುವ ರೀತಿಯ ವೆಬ್ ವಿಳಾಸ"),
            T("Domains like .xyz, .top or free hosting sites are cheap and anonymous, and are heavily used for phishing pages.",
              ".xyz, .top जैसे डोमेन या मुफ़्त होस्टिंग सस्ते और गुमनाम होते हैं, और फ़िशिंग में बहुत इस्तेमाल होते हैं।",
              ".xyz, .top ನಂತಹ ಡೊಮೇನ್‌ಗಳು ಅಥವಾ ಉಚಿತ ಹೋಸ್ಟಿಂಗ್ ಅಗ್ಗ ಮತ್ತು ಅನಾಮಧೇಯ, ಫಿಶಿಂಗ್‌ಗೆ ಹೆಚ್ಚು ಬಳಕೆಯಾಗುತ್ತವೆ."),
            [f"Domain: {reg}"],
        ))
    bait = [w for w in URL_BAIT_WORDS if w in host_words or w in re.split(r"[/\-_.?=&]", sp.path.lower())]
    if bait and not official and not gov:
        F.append(Finding(
            "BAIT_WORDS_IN_URL", "medium", 15,
            T("Address uses scam bait words", "पते में ठगी वाले शब्द हैं", "ವಿಳಾಸದಲ್ಲಿ ವಂಚನೆಯ ಆಮಿಷ ಪದಗಳಿವೆ"),
            T("Words like KYC, refund, reward or verify in a random website address are a common phishing pattern.",
              "किसी अनजान वेबसाइट के पते में KYC, रिफ़ंड, इनाम या वेरिफ़ाई जैसे शब्द फ़िशिंग का आम तरीका है।",
              "ಅಪರಿಚಿತ ವೆಬ್‌ಸೈಟ್ ವಿಳಾಸದಲ್ಲಿ KYC, ರೀಫಂಡ್, ಬಹುಮಾನ ಅಥವಾ ವೆರಿಫೈ ನಂತಹ ಪದಗಳು ಸಾಮಾನ್ಯ ಫಿಶಿಂಗ್ ಮಾದರಿ."),
            ["Words: " + ", ".join(sorted(set(bait)))],
        ))
    if sp.scheme == "http" and not _host_is_ip(host):
        F.append(Finding(
            "NO_HTTPS", "low", 8,
            T("Connection is not secure (no https)", "कनेक्शन सुरक्षित नहीं है (https नहीं)", "ಸಂಪರ್ಕ ಸುರಕ್ಷಿತವಲ್ಲ (https ಇಲ್ಲ)"),
            T("Never type passwords, OTPs or card details on a page without https.",
              "https के बिना वाले पेज पर कभी पासवर्ड, OTP या कार्ड डिटेल न डालें।",
              "https ಇಲ್ಲದ ಪುಟದಲ್ಲಿ ಎಂದಿಗೂ ಪಾಸ್‌ವರ್ಡ್, OTP ಅಥವಾ ಕಾರ್ಡ್ ವಿವರ ಹಾಕಬೇಡಿ."),
            [f"Scheme: {sp.scheme}"],
        ))
    if host.count(".") >= 4 and not official:
        F.append(Finding(
            "DEEP_SUBDOMAIN", "low", 8,
            T("Very long, layered web address", "बहुत लंबा, कई हिस्सों वाला वेब पता", "ತುಂಬಾ ಉದ್ದವಾದ, ಬಹು ಪದರದ ವೆಬ್ ವಿಳಾಸ"),
            T("Scam sites stack names like 'sbi.kyc.update.example.xyz' so the start looks real. Only the end decides the real website.",
              "ठगी वाली साइटें 'sbi.kyc.update.example.xyz' जैसे नाम जोड़ती हैं ताकि शुरुआत असली लगे। असली वेबसाइट आख़िरी हिस्सा तय करता है।",
              "ವಂಚನೆ ಸೈಟ್‌ಗಳು ಆರಂಭ ನಿಜವೆನಿಸಲು 'sbi.kyc.update.example.xyz' ನಂತೆ ಹೆಸರು ಜೋಡಿಸುತ್ತವೆ. ಕೊನೆಯ ಭಾಗವೇ ನಿಜವಾದ ವೆಬ್‌ಸೈಟ್."),
            [f"Real website: {reg}"],
        ))
    if official or gov:
        F.append(Finding(
            "OFFICIAL_DOMAIN", "info", 0,
            T("Points to an official website", "आधिकारिक वेबसाइट पर ले जाता है", "ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್‌ಗೆ ಕರೆದೊಯ್ಯುತ್ತದೆ"),
            T("The domain belongs to the organisation it names. Still, never share OTPs or PINs with anyone who calls you.",
              "यह डोमेन उसी संस्था का है। फिर भी, फ़ोन करने वाले किसी को भी OTP या PIN कभी न बताएँ।",
              "ಈ ಡೊಮೇನ್ ಆ ಸಂಸ್ಥೆಗೇ ಸೇರಿದೆ. ಆದರೂ, ಕರೆ ಮಾಡುವ ಯಾರಿಗೂ OTP ಅಥವಾ PIN ಹೇಳಬೇಡಿ."),
            [f"Domain: {reg}"],
        ))
    return details, F


# ---------------------------------------------------------------- other payloads

def _analyze_other(text: str) -> tuple[dict, list[Finding]]:
    low = text.strip().lower()
    F: list[Finding] = []
    if low.startswith(("sms:", "smsto:")):
        m = re.match(r"smsto?:([^:?]*)[:?]?(?:body=)?(.*)", text.strip(), re.I)
        num, body = (m.group(1), unquote(m.group(2))) if m else ("", "")
        F.append(Finding(
            "SENDS_SMS", "high", 40,
            T("Makes your phone send an SMS", "आपके फ़ोन से SMS भिजवाता है", "ನಿಮ್ಮ ಫೋನ್‌ನಿಂದ SMS ಕಳುಹಿಸುವಂತೆ ಮಾಡುತ್ತದೆ"),
            T("This QR pre-fills an SMS. Scammers use this to link your SIM to UPI on their phone, or to charge premium rates.",
              "यह QR पहले से भरा SMS तैयार करता है। ठग इससे आपका SIM अपने फ़ोन के UPI से जोड़ते हैं या महँगे शुल्क काटते हैं।",
              "ಈ QR ಮೊದಲೇ ತುಂಬಿದ SMS ಸಿದ್ಧಪಡಿಸುತ್ತದೆ. ವಂಚಕರು ಇದರಿಂದ ನಿಮ್ಮ SIM ಅನ್ನು ತಮ್ಮ ಫೋನ್‌ನ UPI ಗೆ ಜೋಡಿಸುತ್ತಾರೆ ಅಥವಾ ದುಬಾರಿ ಶುಲ್ಕ ವಿಧಿಸುತ್ತಾರೆ."),
            [f"To: {num}", f"Text: {body[:120]}"],
        ))
        return {"type": "sms", "number": num, "body": body}, F
    if low.startswith("tel:"):
        num = text.strip()[4:]
        ussd = bool(re.search(r"[*#]", num))
        F.append(Finding(
            "CALL_OR_USSD", "critical" if ussd else "low", 45 if ussd else 5,
            T("Dials a USSD code (can forward your calls)" if ussd else "Calls a phone number",
              "USSD कोड डायल करता है (आपकी कॉल फ़ॉरवर्ड कर सकता है)" if ussd else "एक फ़ोन नंबर पर कॉल करता है",
              "USSD ಕೋಡ್ ಡಯಲ್ ಮಾಡುತ್ತದೆ (ನಿಮ್ಮ ಕರೆ ಫಾರ್ವರ್ಡ್ ಮಾಡಬಹುದು)" if ussd else "ಫೋನ್ ನಂಬರ್‌ಗೆ ಕರೆ ಮಾಡುತ್ತದೆ"),
            T("Codes starting with * or # can turn on call forwarding so the scammer receives your bank's OTP calls." if ussd
              else "Check that this number is the official one printed on your bank card or bill, not one from a message.",
              "* या # से शुरू होने वाले कोड कॉल फ़ॉरवर्डिंग चालू कर सकते हैं, जिससे बैंक की OTP कॉल ठग को मिलती हैं।" if ussd
              else "जाँचें कि यह नंबर आपके बैंक कार्ड या बिल पर छपा आधिकारिक नंबर है, किसी मैसेज वाला नहीं।",
              "* ಅಥವಾ # ನಿಂದ ಆರಂಭವಾಗುವ ಕೋಡ್‌ಗಳು ಕರೆ ಫಾರ್ವರ್ಡ್ ಆನ್ ಮಾಡಬಹುದು, ಆಗ ಬ್ಯಾಂಕ್ OTP ಕರೆಗಳು ವಂಚಕರಿಗೆ ಹೋಗುತ್ತವೆ." if ussd
              else "ಈ ನಂಬರ್ ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಕಾರ್ಡ್ ಅಥವಾ ಬಿಲ್‌ನಲ್ಲಿರುವ ಅಧಿಕೃತ ನಂಬರ್ ಎಂದು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಿ, ಸಂದೇಶದಲ್ಲಿ ಬಂದದ್ದಲ್ಲ."),
            [f"Number: {num}"],
        ))
        return {"type": "tel", "number": num}, F
    if low.startswith("wifi:"):
        ssid = re.search(r"S:([^;]*)", text)
        F.append(Finding(
            "WIFI_JOIN", "low", 5,
            T("Connects you to a Wi-Fi network", "आपको एक Wi-Fi नेटवर्क से जोड़ता है", "ನಿಮ್ಮನ್ನು Wi-Fi ನೆಟ್‌ವರ್ಕ್‌ಗೆ ಸಂಪರ್ಕಿಸುತ್ತದೆ"),
            T("Only join Wi-Fi you trust. Avoid banking on unknown networks.",
              "सिर्फ़ भरोसेमंद Wi-Fi से जुड़ें। अनजान नेटवर्क पर बैंकिंग न करें।",
              "ನಂಬಿಕೆಯ Wi-Fi ಗೆ ಮಾತ್ರ ಸೇರಿ. ಅಪರಿಚಿತ ನೆಟ್‌ವರ್ಕ್‌ನಲ್ಲಿ ಬ್ಯಾಂಕಿಂಗ್ ಮಾಡಬೇಡಿ."),
            [f"Network: {ssid.group(1) if ssid else '?'}"],
        ))
        return {"type": "wifi"}, F
    if low.startswith("intent:"):
        F.append(Finding(
            "ANDROID_INTENT", "medium", 15,
            T("Opens an app on your phone directly", "आपके फ़ोन का कोई ऐप सीधे खोलता है", "ನಿಮ್ಮ ಫೋನ್‌ನ ಆ್ಯಪ್ ಅನ್ನು ನೇರವಾಗಿ ತೆರೆಯುತ್ತದೆ"),
            T("This QR launches an app directly. Check which app opens before doing anything in it.",
              "यह QR सीधे कोई ऐप खोलता है। उसमें कुछ भी करने से पहले देखें कौन-सा ऐप खुला है।",
              "ಈ QR ನೇರವಾಗಿ ಆ್ಯಪ್ ತೆರೆಯುತ್ತದೆ. ಏನಾದರೂ ಮಾಡುವ ಮೊದಲು ಯಾವ ಆ್ಯಪ್ ತೆರೆದಿದೆ ಎಂದು ನೋಡಿ."),
            [text[:150]],
        ))
        return {"type": "intent"}, F
    lure = _has_word(text, LURE_WORDS)
    if lure:
        F.append(Finding(
            "LURE_TEXT", "medium", 15,
            T("Text uses scam bait words", "टेक्स्ट में ठगी वाले शब्द हैं", "ಪಠ್ಯದಲ್ಲಿ ವಂಚನೆಯ ಆಮಿಷ ಪದಗಳಿವೆ"),
            T("Be careful of any message about refunds, prizes or KYC that asks you to act quickly.",
              "रिफ़ंड, इनाम या KYC के बारे में जल्दी कुछ करने को कहने वाले किसी भी मैसेज से सावधान रहें।",
              "ರೀಫಂಡ್, ಬಹುಮಾನ ಅಥವಾ KYC ಬಗ್ಗೆ ತಕ್ಷಣ ಏನಾದರೂ ಮಾಡಲು ಹೇಳುವ ಸಂದೇಶದ ಬಗ್ಗೆ ಎಚ್ಚರವಿರಲಿ."),
            ["Words: " + ", ".join(lure)],
        ))
    return {"type": "text", "text": text[:500]}, F


# ---------------------------------------------------------------- verdict

QR_VERDICTS = [
    (70, "danger", T("Do NOT pay / do NOT open", "पैसे न भेजें / इसे न खोलें", "ಪಾವತಿಸಬೇಡಿ / ತೆರೆಯಬೇಡಿ"),
     T("This matches a known payment scam. Do not scan it in your UPI app or enter your PIN. If you already paid, call 1930 "
       "immediately and report at cybercrime.gov.in — fast reporting can freeze the money.",
       "यह जानी-मानी पेमेंट ठगी से मेल खाता है। इसे UPI ऐप में स्कैन न करें और PIN न डालें। अगर पैसे भेज चुके हैं, तो तुरंत 1930 पर "
       "कॉल करें और cybercrime.gov.in पर शिकायत करें — जल्दी शिकायत से पैसे रोके जा सकते हैं।",
       "ಇದು ತಿಳಿದಿರುವ ಪಾವತಿ ವಂಚನೆಗೆ ಹೊಂದುತ್ತದೆ. UPI ಆ್ಯಪ್‌ನಲ್ಲಿ ಸ್ಕ್ಯಾನ್ ಮಾಡಬೇಡಿ, PIN ಹಾಕಬೇಡಿ. ಈಗಾಗಲೇ ಪಾವತಿಸಿದ್ದರೆ ತಕ್ಷಣ 1930 ಗೆ "
       "ಕರೆ ಮಾಡಿ ಮತ್ತು cybercrime.gov.in ನಲ್ಲಿ ದೂರು ನೀಡಿ — ಬೇಗ ದೂರು ನೀಡಿದರೆ ಹಣ ತಡೆಹಿಡಿಯಬಹುದು.")),
    (40, "suspicious", T("Very suspicious — don't pay", "बहुत संदिग्ध — पैसे न भेजें", "ತುಂಬಾ ಸಂಶಯಾಸ್ಪದ — ಪಾವತಿಸಬೇಡಿ"),
     T("Several warning signs. Only pay if you personally know who this is and why you owe them money.",
       "कई खतरे के संकेत हैं। पैसे तभी भेजें जब आप खुद जानते हों कि यह कौन है और आप उन्हें पैसे क्यों दे रहे हैं।",
       "ಹಲವು ಎಚ್ಚರಿಕೆಯ ಲಕ್ಷಣಗಳಿವೆ. ಇವರು ಯಾರು ಮತ್ತು ನೀವು ಏಕೆ ಹಣ ಕೊಡಬೇಕು ಎಂದು ನಿಮಗೆ ಖಚಿತವಾಗಿ ಗೊತ್ತಿದ್ದರೆ ಮಾತ್ರ ಪಾವತಿಸಿ.")),
    (15, "caution", T("Check before you pay", "पैसे भेजने से पहले जाँचें", "ಪಾವತಿಸುವ ಮೊದಲು ಪರಿಶೀಲಿಸಿ"),
     T("Something here deserves a second look. Confirm the name your UPI app shows before entering your PIN.",
       "यहाँ कुछ चीज़ों पर ध्यान देना ज़रूरी है। PIN डालने से पहले UPI ऐप में दिखने वाला नाम पक्का करें।",
       "ಇಲ್ಲಿ ಕೆಲವು ವಿಷಯಗಳನ್ನು ಗಮನಿಸಬೇಕು. PIN ಹಾಕುವ ಮೊದಲು UPI ಆ್ಯಪ್ ತೋರಿಸುವ ಹೆಸರನ್ನು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಿ.")),
    (0, "low", T("No scam signs found", "ठगी के कोई संकेत नहीं मिले", "ವಂಚನೆಯ ಲಕ್ಷಣಗಳು ಕಂಡುಬಂದಿಲ್ಲ"),
     T("Remember: scanning a QR code is only ever for paying. You never need to scan or enter your UPI PIN to receive money.",
       "याद रखें: QR कोड स्कैन करना सिर्फ़ पैसे भेजने के लिए होता है। पैसे पाने के लिए कभी स्कैन करने या UPI PIN डालने की ज़रूरत नहीं होती।",
       "ನೆನಪಿಡಿ: QR ಕೋಡ್ ಸ್ಕ್ಯಾನ್ ಮಾಡುವುದು ಪಾವತಿಸಲು ಮಾತ್ರ. ಹಣ ಪಡೆಯಲು ಸ್ಕ್ಯಾನ್ ಮಾಡುವ ಅಥವಾ UPI PIN ಹಾಕುವ ಅಗತ್ಯ ಎಂದಿಗೂ ಇಲ್ಲ.")),
]


def analyze_payload(text: str) -> dict:
    text = (text or "").strip()
    if not text:
        raise ValueError("Nothing to analyse.")
    text = text[:4000]
    low = text.lower()
    if low.startswith("upi://") or low.startswith(("phonepe://pay", "paytmmp://pay", "tez://upi", "gpay://upi", "bhim://")):
        details, findings = _analyze_upi(text)
    elif re.match(r"^(https?://|www\.)", low) or re.match(r"^[a-z0-9\-]+(\.[a-z0-9\-]+)+(/|$)", low):
        details, findings = _analyze_url(text)
        # UPI deep link hidden inside a URL
        m = re.search(r"upi://[^\s\"']+", unquote(text), re.I)
        if m:
            _, extra = _analyze_upi(m.group(0))
            findings += [f for f in extra if f.id != "MONEY_GOES_OUT"]
    else:
        details, findings = _analyze_other(text)
    findings = [f for f in findings if f]
    for f in findings:
        f.evidence = [e for e in f.evidence if e]
    findings.sort(key=lambda x: (SEVERITY_ORDER[x.severity], -x.points))
    score = min(100, sum(f.points for f in findings))
    if any(f.severity == "critical" for f in findings):
        score = max(score, 70)
    for threshold, level, headline, advice in QR_VERDICTS:
        if score >= threshold:
            break
    return {
        "kind": "qr",
        "id": hashlib.sha256(text.encode()).hexdigest(),
        "payload": text,
        "details": details,
        "verdict": {"score": score, "level": level, "headline": headline, "advice": advice},
        "findings": [f.to_dict() for f in findings],
        "limitations": ["The QR content is checked against known scam patterns; websites are not visited. "
                        "A clean result cannot confirm who is behind a UPI ID — always check the name your UPI app shows."],
    }
