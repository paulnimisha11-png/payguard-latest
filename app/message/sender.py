"""Sender analysis for SMS: what kind of sender this is and whether it fits what the message claims.

Indian commercial SMS must come from a registered DLT "header" shown as XX-ABCDEF (e.g. AD-HDFCBK, VM-SBIINB-S; the
optional -S/-T/-P/-G suffix marks service / transactional / promotional / government). Banks, telecoms and government
offices do not send alerts from ordinary 10-digit mobile numbers or foreign numbers.

The sender is a hint, never proof: a sender shown on the phone can be spoofed (SMS gateways abroad, RCS / chat apps,
SIM-box operators), a genuine header can still carry a scam (a compromised or careless business), and a personal
number can be a real friend. It is weighed with everything else by the risk engine.
"""
from __future__ import annotations

import re

from ..analyzer.rules import T

DLT_RE = re.compile(r"^([A-Z]{2})-([A-Z0-9]{6})(?:-([STPG]))?$", re.I)
BARE_HEADER_RE = re.compile(r"^[A-Z]{6}$")
MOBILE_RE = re.compile(r"^(?:\+?91|0)?([6-9]\d{9})$")
INTL_RE = re.compile(r"^(?:\+|00)(\d{1,3})\d{6,12}$")
SHORT_CODE_RE = re.compile(r"^\d{3,6}$")

# header code (6 chars after the prefix) -> organisation. Only well-known ones; unknown headers are simply "unknown".
KNOWN_HEADERS = {
    "SBIINB": "sbi", "SBIPSG": "sbi", "SBIBNK": "sbi", "CBSSBI": "sbi", "SBICRD": "sbi", "SBIUPI": "sbi", "ATMSBI": "sbi",
    "HDFCBK": "hdfc", "HDFCBN": "hdfc", "ICICIB": "icici", "ICICIT": "icici", "AXISBK": "axis", "AXISMR": "axis",
    "KOTAKB": "kotak", "KOTAKM": "kotak", "PNBSMS": "pnb", "BOBTXN": "bank of baroda", "BOBSMS": "bank of baroda",
    "CANBNK": "canara", "UNIONB": "union bank", "IDFCFB": "idfc", "YESBNK": "yes bank", "INDUSB": "indusind",
    "PAYTMB": "paytm", "IPAYTM": "paytm", "PHONPE": "phonepe", "GPAYIN": "google pay", "AMAZON": "amazon", "AMZNIN": "amazon",
    "FLPKRT": "flipkart", "JIOINF": "jio", "JIOPAY": "jio", "AIRTEL": "airtel", "AIRPAY": "airtel", "BSNLIN": "bsnl",
    "VIINFO": "vi", "UIDAIG": "uidai", "ITDEPT": "income tax", "EPFOHO": "epfo", "IRCTCI": "irctc", "BESCOM": "bescom",
    "NPCIIN": "npci", "LICIND": "lic", "INDPST": "india post", "DLVHRY": "delhivery", "BLUDRT": "blue dart",
}
# words in the message that claim to be from an organisation -> organisation key used above
CLAIMS = [
    (r"\bsbi\b|state bank|yono", "sbi"), (r"\bhdfc\b", "hdfc"), (r"\bicici\b", "icici"), (r"\baxis bank\b", "axis"),
    (r"\bkotak\b", "kotak"), (r"\bpnb\b|punjab national", "pnb"), (r"bank of baroda|\bbob\b", "bank of baroda"),
    (r"\bcanara\b", "canara"), (r"union bank", "union bank"), (r"\bidfc\b", "idfc"), (r"yes bank", "yes bank"),
    (r"indusind", "indusind"), (r"\bpaytm\b", "paytm"), (r"phone ?pe", "phonepe"), (r"google ?pay|\bgpay\b", "google pay"),
    (r"\bamazon\b", "amazon"), (r"flipkart", "flipkart"), (r"\bjio\b", "jio"), (r"\bairtel\b", "airtel"),
    (r"\bbsnl\b", "bsnl"), (r"\bvodafone\b|\bvi\b", "vi"), (r"uidai|aadhaa?r", "uidai"), (r"income ?tax|\bitr\b", "income tax"),
    (r"\bepfo?\b|provident fund", "epfo"), (r"\birctc\b", "irctc"), (r"bescom", "bescom"), (r"\bnpci\b", "npci"),
    (r"\blic\b", "lic"), (r"india ?post", "india post"), (r"delhivery", "delhivery"), (r"blue ?dart", "blue dart"),
    (r"\btrai\b", "trai"), (r"\bpolice\b|\bcbi\b|cyber ?cell|customs", "police/government"),
    (r"electricity|power (supply|cut)|bijli", "electricity board"), (r"\bbank\b", "a bank"),
]
ORG_TOPICS = {"kyc_bank", "electricity", "telecom", "challan", "fastag", "parcel", "digital_arrest", "refund_prize", "loan"}


def _sig(id_, sev, pts, title, detail, ev):
    return {"id": id_, "severity": sev, "points": pts, "title": title, "detail": detail, "evidence": [e for e in ev if e], "source": "sender"}


def classify(sender: str | None) -> dict:
    raw = (sender or "").strip()[:40]
    out = {"raw": raw, "type": "unknown", "header": None, "route": None, "org": None, "number": None, "country_code": None}
    if not raw:
        return out
    m = DLT_RE.match(raw)
    if m or (BARE_HEADER_RE.match(raw.upper()) and raw.isalpha()):
        code = (m.group(2) if m else raw).upper()
        route = {"S": "service", "T": "transactional", "P": "promotional", "G": "government"}.get((m.group(3) or "").upper()) if m else None
        out.update(type="dlt_header", header=code, route=route, org=KNOWN_HEADERS.get(code))
        return out
    s = re.sub(r"[\s().\-]", "", raw)
    m = MOBILE_RE.match(s)
    if m:
        out.update(type="mobile", number=m.group(1))
    elif INTL_RE.match(s) and not re.match(r"^(\+|00)91", s):
        out.update(type="international", number=s, country_code="+" + re.sub(r"^(\+|00)", "", s)[:2])
    elif SHORT_CODE_RE.match(s):
        out.update(type="short_code", number=s)
    elif "@" in s:
        out.update(type="email")
    else:
        out.update(type="other_name")
    return out


def claimed_org(text: str) -> str | None:
    low = (text or "").lower()
    for rx, org in CLAIMS:
        if re.search(rx, low):
            return org
    return None


def analyze_sender(sender: str | None, text: str, category: str | None) -> tuple[dict, list[dict]]:
    """(sender info, signals). No sender given -> type "unknown" and no signals."""
    info = classify(sender)
    claim = claimed_org(text)
    info["claims_to_be"] = claim
    S: list[dict] = []
    org_claim = bool(claim) or category in ORG_TOPICS
    t = info["type"]
    if t == "mobile" and org_claim:
        who = (claim.upper() if len(claim) <= 5 else claim.title()) if claim else "an organisation"
        S.append(_sig("ORG_FROM_PERSONAL_NUMBER", "high", 25,
                      T(f"Claims to be {who} but came from a personal mobile number", f"{who} होने का दावा, पर एक निजी मोबाइल नंबर से आया",
                        f"{who} ಎಂದು ಹೇಳುತ್ತದೆ, ಆದರೆ ವೈಯಕ್ತಿಕ ಮೊಬೈಲ್ ನಂಬರ್‌ನಿಂದ ಬಂದಿದೆ"),
                      T("Banks, telecoms, courier companies and government offices send SMS from registered headers like 'VM-SBIINB', not from a 10-digit mobile number.",
                        "बैंक, टेलीकॉम, कूरियर कंपनियाँ और सरकारी विभाग 'VM-SBIINB' जैसे पंजीकृत हेडर से SMS भेजते हैं, 10 अंकों के मोबाइल नंबर से नहीं।",
                        "ಬ್ಯಾಂಕ್, ಟೆಲಿಕಾಂ, ಕೊರಿಯರ್ ಕಂಪನಿಗಳು ಮತ್ತು ಸರ್ಕಾರಿ ಕಚೇರಿಗಳು 'VM-SBIINB' ನಂತಹ ನೋಂದಾಯಿತ ಹೆಡರ್‌ನಿಂದ SMS ಕಳುಹಿಸುತ್ತವೆ, 10 ಅಂಕಿಯ ಮೊಬೈಲ್ ನಂಬರ್‌ನಿಂದಲ್ಲ."),
                      [f"Sender: {info['raw']}", f"Claims: {who}"]))
    elif t == "international":
        pts = 20 if org_claim else 10
        S.append(_sig("FOREIGN_SENDER", "medium", pts,
                      T("Sent from a foreign phone number", "विदेशी फ़ोन नंबर से भेजा गया", "ವಿದೇಶಿ ಫೋನ್ ನಂಬರ್‌ನಿಂದ ಕಳುಹಿಸಲಾಗಿದೆ"),
                      T("Indian banks, companies and government offices don't message you from foreign numbers. Scam gangs often use them.",
                        "भारतीय बैंक, कंपनियाँ और सरकारी विभाग विदेशी नंबर से मैसेज नहीं करते। ठग गिरोह अक्सर इन्हें इस्तेमाल करते हैं।",
                        "ಭಾರತೀಯ ಬ್ಯಾಂಕ್, ಕಂಪನಿ ಮತ್ತು ಸರ್ಕಾರಿ ಕಚೇರಿಗಳು ವಿದೇಶಿ ನಂಬರ್‌ನಿಂದ ಸಂದೇಶ ಕಳುಹಿಸುವುದಿಲ್ಲ. ವಂಚಕರ ಗುಂಪುಗಳು ಇವನ್ನು ಬಳಸುತ್ತವೆ."),
                      [f"Sender: {info['raw']}"]))
    elif t == "dlt_header" and info["org"] and claim and claim not in ("a bank", "police/government", "electricity board") and claim != info["org"]:
        S.append(_sig("SENDER_BRAND_MISMATCH", "medium", 15,
                      T(f"Sender is {info['org'].upper()} but the message talks about {claim.upper()}", f"भेजने वाला {info['org'].upper()} है, पर मैसेज {claim.upper()} की बात करता है",
                        f"ಕಳುಹಿಸಿದವರು {info['org'].upper()}, ಆದರೆ ಸಂದೇಶ {claim.upper()} ಬಗ್ಗೆ ಹೇಳುತ್ತದೆ"),
                      T("A message about one company sent from another company's header is unusual. Check it in the real company's own app.",
                        "एक कंपनी के बारे में मैसेज किसी दूसरी कंपनी के हेडर से आना असामान्य है। असली कंपनी के अपने ऐप में जाँचें।",
                        "ಒಂದು ಕಂಪನಿಯ ಬಗ್ಗೆ ಸಂದೇಶ ಇನ್ನೊಂದು ಕಂಪನಿಯ ಹೆಡರ್‌ನಿಂದ ಬರುವುದು ಅಸಾಮಾನ್ಯ. ನಿಜವಾದ ಕಂಪನಿಯ ಆ್ಯಪ್‌ನಲ್ಲಿ ಪರಿಶೀಲಿಸಿ."),
                      [f"Header: {info['header']}", f"Message mentions: {claim}"]))
    elif t == "other_name" and org_claim:
        S.append(_sig("ODD_SENDER_FORMAT", "low", 8,
                      T("Sender name isn't a registered SMS header", "भेजने वाले का नाम पंजीकृत SMS हेडर नहीं है", "ಕಳುಹಿಸಿದವರ ಹೆಸರು ನೋಂದಾಯಿತ SMS ಹೆಡರ್ ಅಲ್ಲ"),
                      T("Registered Indian SMS senders look like 'AD-HDFCBK'. Names like 'SBI-Alert' or 'Bank Support' can come from spoofing services.",
                        "पंजीकृत भारतीय SMS भेजने वाले 'AD-HDFCBK' जैसे दिखते हैं। 'SBI-Alert' या 'Bank Support' जैसे नाम नकली सेवाओं से आ सकते हैं।",
                        "ನೋಂದಾಯಿತ ಭಾರತೀಯ SMS ಕಳುಹಿಸುವವರು 'AD-HDFCBK' ರೀತಿ ಇರುತ್ತಾರೆ. 'SBI-Alert' ಅಥವಾ 'Bank Support' ನಂತಹ ಹೆಸರು ನಕಲಿ ಸೇವೆಗಳಿಂದ ಬರಬಹುದು."),
                      [f"Sender: {info['raw']}"]))
    if t == "dlt_header" and info["org"] and (claim == info["org"] or claim in (None, "a bank")):
        info["matches_claim"] = True
    return info, S
