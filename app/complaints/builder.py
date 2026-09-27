"""Turn a scan + the victim's answers into a ready-to-file complaint.

Everything about the *scam* (findings, suspect identifiers, hashes) is
recomputed on the server from the original scan, never taken from the
browser, so the evidence in the complaint can't be edited to say something
the scanner didn't find.

Output:
  * portal_fields   – field-by-field values to paste into cybercrime.gov.in
  * complaint_text  – full narrative (always >= 200 characters)
  * call_script     – what to say on 1930 first, in en / hi / kn
  * checklist       – ordered next steps, most urgent first
  * suspects        – identifiers of the scammer (UPI ID, domain, phone, app)
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import secrets
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

IST = dt.timezone(dt.timedelta(hours=5, minutes=30))
VPA_RE = re.compile(r"^[A-Za-z0-9.\-_]{2,256}@[A-Za-z0-9]{2,64}$")
TXN_RE = re.compile(r"^[A-Za-z0-9\-]{6,35}$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9 \-]{5,17}$")

PORTAL_URL = "https://cybercrime.gov.in"
CHAKSHU_URL = "https://sancharsaathi.gov.in/sfc/"
HELPLINE = "1930"

CHANNELS = {
    "whatsapp": "WhatsApp", "sms": "SMS", "call": "Phone call", "email": "Email", "social": "Social media",
    "website": "Website / online ad", "in_person": "In person", "other": "Other",
}
METHODS = {"upi": "UPI", "card": "Debit/Credit card", "netbanking": "Internet banking", "wallet": "E-wallet", "other": "Other"}


# ------------------------------------------------------------------ input model

class ComplaintIn(BaseModel):
    source: Literal["apk", "qr", "screenshot", "message"]
    sha256: str | None = Field(None, description="APK scan to report")
    payload: str | None = Field(None, max_length=5000, description="QR/UPI/link content, or the scam message text, to report")
    lang: Literal["en", "hi", "kn", "ta", "te", "mr", "bn"] = "en"

    lost_money: bool = False
    amount: float | None = Field(None, gt=0, le=100_000_000)
    incident_time: dt.datetime | None = None
    transaction_ids: list[str] = Field(default_factory=list, max_length=5)
    payment_method: Literal["upi", "card", "netbanking", "wallet", "other"] | None = None
    victim_bank: str | None = Field(None, max_length=80)
    paid_to: str | None = Field(None, max_length=120)

    channel: Literal["whatsapp", "sms", "call", "email", "social", "website", "in_person", "other"] | None = None
    sender_contact: str | None = Field(None, max_length=80)
    app_installed: bool | None = None
    description: str | None = Field(None, max_length=2000)

    victim_name: str | None = Field(None, max_length=100)
    victim_mobile: str | None = Field(None, max_length=20)
    victim_email: str | None = Field(None, max_length=120)

    @field_validator("transaction_ids")
    @classmethod
    def _txn(cls, v):
        out = []
        for t in v:
            t = re.sub(r"\s+", "", t or "")
            if not t:
                continue
            if not TXN_RE.match(t):
                raise ValueError(f"Transaction ID '{t}' looks wrong. UPI transaction IDs (UTR) are usually 12 digits.")
            out.append(t)
        return out

    @field_validator("paid_to")
    @classmethod
    def _paid_to(cls, v):
        v = (v or "").strip()
        if v and "@" in v and not VPA_RE.match(v):
            raise ValueError("The UPI ID you paid to doesn't look valid. It should look like name@bank.")
        return v or None

    @field_validator("sender_contact", "victim_mobile")
    @classmethod
    def _phone(cls, v):
        v = (v or "").strip()
        if v and not v.startswith("@") and re.search(r"\d", v) and not PHONE_RE.match(v):
            raise ValueError(f"'{v}' doesn't look like a phone number.")
        return v or None

    @field_validator("victim_email")
    @classmethod
    def _email(cls, v):
        v = (v or "").strip()
        if v and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("Email address doesn't look valid.")
        return v or None

    @field_validator("incident_time")
    @classmethod
    def _time(cls, v):
        if v is None:
            return v
        if v.tzinfo is None:
            v = v.replace(tzinfo=IST)
        now = dt.datetime.now(dt.timezone.utc)
        if v > now + dt.timedelta(minutes=10):
            raise ValueError("The incident time is in the future.")
        if v < now - dt.timedelta(days=3 * 365):
            raise ValueError("The incident time is more than 3 years ago.")
        return v

    @model_validator(mode="after")
    def _check(self):
        if self.source in ("apk", "screenshot") and not (self.sha256 and re.fullmatch(r"[0-9a-fA-F]{64}", self.sha256)):
            raise ValueError("Missing or invalid scan reference.")
        if self.source == "qr" and not (self.payload and self.payload.strip()):
            raise ValueError("Missing QR / link content.")
        if self.source == "message" and not (self.payload and self.payload.strip()):
            raise ValueError("Missing message text.")
        if not self.lost_money:
            self.amount, self.transaction_ids, self.payment_method, self.paid_to = None, [], None, self.paid_to
        return self


# ------------------------------------------------------------------ helpers

def new_ref() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I confusion when read over the phone
    return "PG-" + dt.datetime.now(IST).strftime("%y%m%d") + "-" + "".join(secrets.choice(alphabet) for _ in range(6))


def new_token() -> str:
    return secrets.token_urlsafe(24)


def norm_phone(p: str) -> str:
    d = re.sub(r"\D", "", p or "")
    if len(d) == 12 and d.startswith("91"):
        d = d[2:]
    return d


def fmt_inr(x: float | None) -> str:
    if x is None:
        return "—"
    s = f"{x:,.2f}"
    # Indian grouping: 12,34,567.00
    whole, frac = s.replace(",", "").split(".")
    if len(whole) > 3:
        head, tail = whole[:-3], whole[-3:]
        head = ",".join([head[max(i - 2, 0):i] for i in range(len(head), 0, -2)][::-1])
        whole = head + "," + tail
    return f"₹{whole}.{frac}"


def fmt_time(t: dt.datetime | None) -> str:
    return t.astimezone(IST).strftime("%d %b %Y, %I:%M %p IST") if t else "Not provided"


# ------------------------------------------------------------------ suspects from the scan

def suspects_from_scan(source: str, scan: dict, c: ComplaintIn) -> list[dict]:
    """Identifiers of the scammer, as (kind, value, label). Kinds are used for the community counter."""
    out: list[dict] = []

    def add(kind, value, label):
        value = (value or "").strip()
        if value and not any(s["kind"] == kind and s["value"].lower() == value.lower() for s in out):
            out.append({"kind": kind, "value": value, "label": label})

    if source == "apk":
        a, f = scan["app"], scan["file"]
        add("apk_sha256", f["sha256"], "Malicious app file (SHA-256)")
        add("package", a.get("package"), "App package name")
        if a.get("name"):
            add("app_name", a["name"], "App name shown to victim")
        if scan.get("signing", {}).get("sha256"):
            add("cert", scan["signing"]["sha256"], "App signing certificate (SHA-256)")
        for u in (scan.get("network", {}).get("raw_ip_urls") or [])[:3] + (scan.get("network", {}).get("suspicious_tld_urls") or [])[:3]:
            add("url", u, "Server the app contacts")
        for t in (scan.get("code", {}).get("telegram") or [])[:2]:
            add("telegram", t, "Telegram bot used to steal data")
    elif source == "screenshot":
        d = scan["details"]
        add("shot_sha256", scan["file"]["sha256"], "Fake payment screenshot (SHA-256)")
        if d.get("utr"):
            add("utr_claimed", d["utr"], "Reference number shown on the screenshot")
        if d.get("amount"):
            add("amount_claimed", f"{fmt_inr(d['amount'])}", "Amount the screenshot claims was paid")
    elif source == "message":
        d = scan["details"]
        for u in d.get("upi_ids", []):
            add("upi", u.lower(), "UPI ID in the message")
        for l in d.get("links", []):
            if not l.get("official") and not l.get("whatsapp"):
                add("domain", l.get("domain"), "Scam website in the message")
                add("url", l.get("url"), "Full link in the message")
        for ph in d.get("phones", []):
            add("phone", norm_phone(ph), "Number in the message")
    else:
        d = scan["details"]
        if d.get("type") == "upi":
            add("upi", (d.get("payee_vpa") or "").lower(), "Scammer's UPI ID")
            if d.get("payee_name"):
                add("payee_name", d["payee_name"], "Name shown on the UPI request")
        elif d.get("type") == "url":
            add("domain", d.get("registered_domain") or d.get("host"), "Scam website")
            add("url", d.get("url"), "Full link")
        elif d.get("type") in ("tel", "sms"):
            add("phone", norm_phone(d.get("number")), "Number in the QR")
        add("qr_payload", scan.get("payload"), "Exact QR content")

    if c.paid_to:
        add("upi" if "@" in c.paid_to else "account", c.paid_to.lower(), "Account the money was sent to")
    if c.sender_contact:
        digits = norm_phone(c.sender_contact)
        v = digits if len(digits) >= 6 and not c.sender_contact.startswith("@") else c.sender_contact
        add("phone" if v.isdigit() else "handle", v, f"Who sent it ({CHANNELS.get(c.channel or 'other', 'contact')})")
    return out


# The kinds that are safe and useful to count across complaints (no victim data).
COUNTABLE = {"upi", "domain", "phone", "apk_sha256", "package", "cert", "account", "shot_sha256", "utr_claimed"}


# ------------------------------------------------------------------ category

def suggest_category(source: str, scan: dict, c: ComplaintIn) -> dict:
    note = ("Pick the closest match on the portal if the wording differs; the description carries the details.")
    if source == "screenshot":
        return {"category": "Online Financial Fraud" if c.lost_money else "Online Financial Fraud (attempt)",
                "subcategory": "Fake payment proof / fake UPI payment screenshot", "note": note}
    if c.lost_money:
        sub = {"upi": "UPI Related Frauds", "card": "Debit/Credit Card Fraud/Sim Swap Fraud",
               "netbanking": "Internet Banking Related Fraud", "wallet": "E-Wallet Related Fraud"}.get(c.payment_method or "")
        if not sub:
            d = scan.get("details") or {}
            sub = "UPI Related Frauds" if (source == "qr" and d.get("type") == "upi") or (source == "message" and d.get("upi_ids")) else \
                  "Internet Banking Related Fraud" if source == "apk" or (source == "message" and d.get("links")) else "Fraud Call/Vishing"
        return {"category": "Online Financial Fraud", "subcategory": sub, "note": note}
    if source == "screenshot":
        return {"category": "Online Financial Fraud" if c.lost_money else "Online Financial Fraud (attempt)",
                "subcategory": "Fake payment proof / fake UPI payment screenshot", "note": note}
    if source == "apk":
        return {"category": "Any Other Cyber Crime", "subcategory": "Malicious app / malware sent to victim (attempted fraud)", "note": note}
    if source == "message":
        return {"category": "Online Financial Fraud (attempt)", "subcategory": "Phishing SMS / WhatsApp / email message — no money lost yet", "note": note}
    return {"category": "Online Financial Fraud (attempt)", "subcategory": "UPI / phishing attempt — no money lost yet", "note": note}


# ------------------------------------------------------------------ text

def _top_findings(scan: dict, n=5) -> list[dict]:
    return [f for f in scan["findings"] if f["severity"] in ("critical", "high")][:n] or scan["findings"][:n]


def complaint_text(source: str, scan: dict, c: ComplaintIn, suspects: list[dict], ref: str) -> str:
    ch = CHANNELS.get(c.channel or "", "a message")
    when = fmt_time(c.incident_time) if c.incident_time else "a recent date (exact time not recorded)"
    parts = []
    if source == "screenshot":
        d = scan["details"]
        parts.append(f"On {when}, a person" + (f" ({c.sender_contact})" if c.sender_contact else "") + f" showed/sent me, via {ch}, "
                     f"a screenshot claiming they had paid me" + (f" {fmt_inr(d.get('amount'))}" if d.get("amount") else "")
                     + (f" with UPI reference number {d.get('utr')}" if d.get("utr") else "")
                     + (f", dated {d.get('date')}" if d.get("date") else "") + ". No such payment reached my account.")
        if c.lost_money:
            parts.append("Relying on the screenshot, I handed over goods/money worth " + fmt_inr(c.amount) + ".")
            parts.append("I request that the person be identified and action be taken to recover my loss.")
    elif source == "apk":
        a = scan["app"]
        parts.append(f"On {when}, I received an Android app file named \"{scan['file']['name']}\" "
                     f"(app name \"{a.get('name') or 'unknown'}\", package {a.get('package')}) via {ch}"
                     + (f" from {c.sender_contact}" if c.sender_contact else "") + ".")
        parts.append("I " + ("installed it" if c.app_installed else "did not install it" if c.app_installed is False
                             else "am not sure whether it was installed") + ".")
    elif source == "message":
        d = scan["details"]
        txt = " ".join((scan.get("payload") or "").split())
        parts.append(f"On {when}, I received the following message via {ch}"
                     + (f" from {c.sender_contact}" if c.sender_contact else "") + f": “{txt[:700]}{'…' if len(txt) > 700 else ''}”.")
        if d.get("category_name"):
            parts.append(f"It matches the known \"{d['category_name']['en']}\" pattern.")
    else:
        d = scan["details"]
        if d.get("type") == "upi":
            parts.append(f"On {when}, I received a UPI QR code / payment request via {ch}"
                         + (f" from {c.sender_contact}" if c.sender_contact else "")
                         + f". It requests payment to UPI ID {d.get('payee_vpa')} (name shown: \"{d.get('payee_name') or '—'}\")"
                         + (f" for {fmt_inr(d.get('amount'))}" if d.get("amount") else "")
                         + (f" with the note \"{d.get('note')}\"" if d.get("note") else "") + ".")
        elif d.get("type") == "url":
            parts.append(f"On {when}, I received a link / QR code via {ch}"
                         + (f" from {c.sender_contact}" if c.sender_contact else "")
                         + f" pointing to {d.get('url')} (website: {d.get('registered_domain') or d.get('host')}).")
        else:
            parts.append(f"On {when}, I received a QR code via {ch} containing: {scan.get('payload')}.")
    if c.lost_money and source != "screenshot":
        parts.append(f"I lost {fmt_inr(c.amount)}" + (f" via {METHODS.get(c.payment_method or '', 'online payment')}" if c.payment_method else "")
                     + (f" from my {c.victim_bank} account" if c.victim_bank else "")
                     + (f" to {c.paid_to}" if c.paid_to else "")
                     + (". Transaction ID(s)/UTR: " + ", ".join(c.transaction_ids) if c.transaction_ids else "") + ".")
        parts.append("I request that the beneficiary account be traced and the amount be put on hold and refunded.")
    elif not c.lost_money:
        parts.append("I did not lose money. I am reporting this so that the sender and the accounts involved can be blocked before others are cheated.")
    tops = _top_findings(scan)
    if tops:
        parts.append("An automated safety check (PayGuard, report " + ref + ") found: "
                     + "; ".join(f["title"]["en"] for f in tops) + f". Risk score {scan['verdict']['score']}/100.")
    sus = [s for s in suspects if s["kind"] in ("upi", "domain", "phone", "package", "account", "telegram", "utr_claimed")]
    if sus:
        parts.append("Suspect identifiers: " + "; ".join(f"{s['label']}: {s['value']}" for s in sus) + ".")
    if c.description:
        parts.append("Additional details: " + c.description.strip())
    parts.append("Screenshots and the PayGuard evidence report are attached.")
    return " ".join(parts)


def call_script(source: str, scan: dict, c: ComplaintIn, suspects: list[dict]) -> dict:
    to = c.paid_to or next((s["value"] for s in suspects if s["kind"] == "upi"), None)
    amt = fmt_inr(c.amount) if c.lost_money and c.amount else None
    utr = ", ".join(c.transaction_ids) if c.transaction_ids else None
    when = fmt_time(c.incident_time) if c.incident_time else "recently"
    what_en = {"apk": "a fake app file", "screenshot": "a fake payment screenshot", "message": "a scam message"}.get(source, "a fraudulent QR code / payment request")
    what_hi = {"apk": "नकली ऐप फ़ाइल", "screenshot": "नकली पेमेंट स्क्रीनशॉट", "message": "ठगी वाले मैसेज"}.get(source, "धोखाधड़ी वाला QR कोड / पेमेंट रिक्वेस्ट")
    what_kn = {"apk": "ನಕಲಿ ಆ್ಯಪ್ ಫೈಲ್", "screenshot": "ನಕಲಿ ಪಾವತಿ ಸ್ಕ್ರೀನ್‌ಶಾಟ್", "message": "ವಂಚನೆ ಸಂದೇಶ"}.get(source, "ವಂಚನೆಯ QR ಕೋಡ್ / ಪಾವತಿ ವಿನಂತಿ")
    what_ta = {"apk": "போலி ஆப் கோப்பு", "screenshot": "போலி கட்டண ரசீது", "message": "மோசடி செய்தி"}.get(source, "மோசடி QR குறியீடு / கட்டணக் கோரிக்கை")
    what_te = {"apk": "నకిలీ యాప్ ఫైల్", "screenshot": "నకిలీ చెల్లింపు స్క్రీన్‌షాట్", "message": "మోసపు సందేశం"}.get(source, "మోసపూరిత QR కోడ్ / చెల్లింపు అభ్యర్థన")
    what_mr = {"apk": "बनावट ॲप फाइल", "screenshot": "बनावट पेमेंट स्क्रीनशॉट", "message": "फसवणूक मेसेज"}.get(source, "फसवणूक करणारा QR कोड / पेमेंट विनंती")
    what_bn = {"apk": "ভুয়ো অ্যাপ ফাইল", "screenshot": "ভুয়ো পেমেন্ট স্ক্রিনশট", "message": "প্রতারণামূলক মেসেজ"}.get(source, "প্রতারণামূলক QR কোড / পেমেন্ট অনুরোধ")
    if c.lost_money:
        en = [f"“I want to report an online financial fraud. I lost {amt or 'money'}.”",
              f"“It happened on {when}" + (f", the money went to {to}" if to else "") + ".”",
              f"“Transaction ID (UTR): {utr}.”" if utr else "Have your bank SMS open — they will ask for the transaction ID (UTR).",
              f"“My bank is {c.victim_bank}.”" if c.victim_bank else "Tell them which bank the money left from.",
              f"“It started with {what_en} sent by {c.sender_contact or 'an unknown sender'}.”",
              "Ask them for the acknowledgement / complaint number and write it down."]
        hi = [f"“मुझे ऑनलाइन वित्तीय धोखाधड़ी की शिकायत करनी है। मेरे {amt or 'पैसे'} गए हैं।”",
              f"“यह {when} को हुआ" + (f", पैसे {to} पर गए" if to else "") + "।”",
              f"“ट्रांज़ैक्शन ID (UTR): {utr}।”" if utr else "बैंक का SMS खोलकर रखें — वे ट्रांज़ैक्शन ID (UTR) पूछेंगे।",
              f"“मेरा बैंक {c.victim_bank} है।”" if c.victim_bank else "बताएँ कि पैसे किस बैंक से गए।",
              f"“यह {c.sender_contact or 'एक अनजान नंबर'} से आए {what_hi} से शुरू हुआ।”",
              "उनसे शिकायत / पावती नंबर माँगें और लिख लें।"]
        kn = [f"“ನಾನು ಆನ್‌ಲೈನ್ ಆರ್ಥಿಕ ವಂಚನೆ ದೂರು ನೀಡಬೇಕು. ನನ್ನ {amt or 'ಹಣ'} ಹೋಗಿದೆ.”",
              f"“ಇದು {when} ರಂದು ನಡೆಯಿತು" + (f", ಹಣ {to} ಗೆ ಹೋಗಿದೆ" if to else "") + ".”",
              f"“ವಹಿವಾಟು ID (UTR): {utr}.”" if utr else "ಬ್ಯಾಂಕ್ SMS ತೆರೆದಿಡಿ — ಅವರು ವಹಿವಾಟು ID (UTR) ಕೇಳುತ್ತಾರೆ.",
              f"“ನನ್ನ ಬ್ಯಾಂಕ್ {c.victim_bank}.”" if c.victim_bank else "ಹಣ ಯಾವ ಬ್ಯಾಂಕ್‌ನಿಂದ ಹೋಯಿತು ಎಂದು ತಿಳಿಸಿ.",
              f"“ಇದು {c.sender_contact or 'ಅಪರಿಚಿತ ನಂಬರ್'} ಕಳುಹಿಸಿದ {what_kn} ನಿಂದ ಶುರುವಾಯಿತು.”",
              "ದೂರು / ಸ್ವೀಕೃತಿ ಸಂಖ್ಯೆ ಕೇಳಿ ಬರೆದುಕೊಳ್ಳಿ."]
        ta = [f"“நான் ஆன்லைன் நிதி மோசடி குறித்து புகார் அளிக்க வேண்டும். எனது {amt or 'பணம்'} இழக்கப்பட்டது.”",
              f"“இது {when} அன்று நடந்தது" + (f", பணம் {to} க்குச் சென்றது" if to else "") + ".”",
              f"“பரிவர்த்தனை ID (UTR): {utr}.”" if utr else "உங்கள் வங்கி SMS ஐ திறந்து வைக்கவும் — அவர்கள் பரிவர்த்தனை ID (UTR) கேட்பார்கள்.",
              f"“எனது வங்கி {c.victim_bank}.”" if c.victim_bank else "பணம் எந்த வங்கியிலிருந்து சென்றது என்று அவர்களிடம் தெரிவிக்கவும்.",
              f"“இது {c.sender_contact or 'தெரியாத எண்'} அனுப்பிய {what_ta} மூலம் தொடங்கியது.”",
              "அவர்களிடம் புகார் / ஒப்புதல் எண்ணைக் கேட்டு எழுதிக்கொள்ளவும்."]
        te = [f"“నేను ఆన్‌లైన్ ఆర్థిక మోసం గురించి ఫిర్యాదు చేయాలనుకుంటున్నాను. నా {amt or 'డబ్బు'} పోయింది.”",
              f"“ఇది {when} న జరిగింది" + (f", డబ్బు {to}కి వెళ్లింది" if to else "") + ".”",
              f"“లావాదేవీ ID (UTR): {utr}.”" if utr else "బ్యాంక్ SMS తెరిచి ఉంచండి — వారు లావాదేవీ ID (UTR) అడుగుతారు.",
              f"“నా బ్యాంక్ {c.victim_bank}.”" if c.victim_bank else "డబ్బు ఏ బ్యాంక్ నుండి పోయిందో వారికి చెప్పండి.",
              f"“ఇది {c.sender_contact or 'తెలియని నంబర్'} పంపిన {what_te}తో మొదలైంది.”",
              "ఫిర్యాదు / రసీదు సంఖ్యను అడిగి రాసుకోండి."]
        mr = [f"“मला ऑनलाइन आर्थिक फसवणुकीची तक्रार करायची आहे. माझे {amt or 'पैसे'} गेले आहेत.”",
              f"“हे {when} रोजी घडले" + (f", पैसे {to} ला गेले" if to else "") + ".”",
              f"“व्यवहार ID (UTR): {utr}.”" if utr else "बँक SMS उघडून ठेवा — ते व्यवहार ID (UTR) विचारतील.",
              f"“माझी बँक {c.victim_bank} आहे.”" if c.victim_bank else "पैसे कोणत्या बँकेतून गेले ते त्यांना सांगा.",
              f"“हे {c.sender_contact or 'अनोळखी नंबर'} कडून आलेल्या {what_mr} ने सुरू झाले.”",
              "तक्रार / पावती क्रमांक विचारून लिहून घ्या."]
        bn = [f"“আমি একটি অনলাইন আর্থিক প্রতারণার অভিযোগ জানাতে চাই। আমার {amt or 'টাকা'} খোয়া গেছে।”",
              f"“এটি {when}-এ ঘটেছে" + (f", টাকা {to}-তে গেছে" if to else "") + "।”",
              f"“লেনদেন ID (UTR): {utr}।”" if utr else "ব্যাঙ্ক SMS খুলে রাখুন — তারা লেনদেন ID (UTR) জানতে চাইবে।",
              f"“আমার ব্যাঙ্ক {c.victim_bank}।”" if c.victim_bank else "কোন ব্যাঙ্ক থেকে টাকা কেটেছে তাদের জানান।",
              f"“এটি {c.sender_contact or 'অজানা নম্বর'} থেকে আসা {what_bn} দিয়ে শুরু হয়েছিল।”",
              "তাদের কাছ থেকে অভিযোগ / প্রাপ্তিস্বীকার নম্বর চেয়ে লিখে রাখুন।"]
    else:
        en = [f"“I want to report {what_en}. I have not lost money.”",
              f"“It was sent by {c.sender_contact or 'an unknown sender'} via {CHANNELS.get(c.channel or '', 'a message')} on {when}.”",
              f"“The scammer's UPI ID / website is {next((s['value'] for s in suspects if s['kind'] in ('upi', 'domain')), 'in my report')}.”",
              "1930 mainly handles money already lost. If they redirect you, file it on cybercrime.gov.in with the fields below."]
        hi = [f"“मुझे {what_hi} की शिकायत करनी है। मेरे पैसे नहीं गए हैं।”",
              f"“यह {when} को {c.sender_contact or 'एक अनजान नंबर'} ने {CHANNELS.get(c.channel or '', 'मैसेज')} पर भेजा।”",
              f"“ठग की UPI ID / वेबसाइट {next((s['value'] for s in suspects if s['kind'] in ('upi', 'domain')), 'मेरी रिपोर्ट में है')} है।”",
              "1930 मुख्य रूप से पैसे जाने के मामले देखता है। अगर वे मना करें, तो नीचे दिए फ़ील्ड से cybercrime.gov.in पर शिकायत करें।"]
        kn = [f"“ನಾನು {what_kn} ಬಗ್ಗೆ ದೂರು ನೀಡಬೇಕು. ನನ್ನ ಹಣ ಹೋಗಿಲ್ಲ.”",
              f"“ಇದನ್ನು {when} ರಂದು {c.sender_contact or 'ಅಪರಿಚಿತ ನಂಬರ್'} {CHANNELS.get(c.channel or '', 'ಸಂದೇಶ')} ಮೂಲಕ ಕಳುಹಿಸಿದರು.”",
              f"“ವಂಚಕರ UPI ID / ವೆಬ್‌ಸೈಟ್ {next((s['value'] for s in suspects if s['kind'] in ('upi', 'domain')), 'ನನ್ನ ವರದಿಯಲ್ಲಿದೆ')}.”",
              "1930 ಮುಖ್ಯವಾಗಿ ಹಣ ಕಳೆದುಕೊಂಡ ಪ್ರಕರಣಗಳನ್ನು ನೋಡುತ್ತದೆ. ಅವರು ನಿರಾಕರಿಸಿದರೆ, ಕೆಳಗಿನ ವಿವರಗಳೊಂದಿಗೆ cybercrime.gov.in ನಲ್ಲಿ ದೂರು ನೀಡಿ."]
        ta = [f"“நான் {what_ta} குறித்து புகார் அளிக்க வேண்டும். எனது பணம் இழக்கப்படவில்லை.”",
              f"“இது {when} அன்று {c.sender_contact or 'தெரியாத எண்'} மூலம் அனுப்பப்பட்டது.”",
              f"“மோசடி செய்பவரின் UPI ID / வலைத்தளம் {next((s['value'] for s in suspects if s['kind'] in ('upi', 'domain')), 'எனது அறிக்கையில் உள்ளது')} ஆகும்.”",
              "1930 பொதுவாகப் பணம் இழந்த வழக்குகளைக் கையாள்கிறது. அவர்கள் மறுத்தால், கீழே உள்ள விவரங்களுடன் cybercrime.gov.in இல் புகார் செய்க."]
        te = [f"“నేను {what_te} గురించి ఫిర్యాదు చేయాలనుకుంటున్నాను. నా డబ్బు పోలేదు.”",
              f"“ఇది {when} న {c.sender_contact or 'తెలియని నంబర్'} ద్వారా పంపబడింది.”",
              f"“మోసగాడి UPI ID / వెబ్‌సైట్ {next((s['value'] for s in suspects if s['kind'] in ('upi', 'domain')), 'నా రిపోర్టులో ఉంది')}.”",
              "1930 ప్రధానంగా డబ్బు పోయిన కేసులను చూస్తుంది. వారు నిరాకరిస్తే, క్రింది వివరాలతో cybercrime.gov.in లో ఫిర్యాదు చేయండి."]
        mr = [f"“मला {what_mr} बद्दल तक्रार करायची आहे. माझे पैसे गेलेले नाहीत.”",
              f"“हे {when} रोजी {c.sender_contact or 'अनोळखी नंबर'} ने पाठवले होते.”",
              f"“फसवणूक करणाऱ्याचा UPI ID / वेबसाइट {next((s['value'] for s in suspects if s['kind'] in ('upi', 'domain')), 'माझ्या अहवालात आहे')} आहे.”",
              "1930 प्रामुख्याने पैसे गेलेल्या प्रकरणांवर काम करते. त्यांनी नकार दिल्यास, खालील माहितीसह cybercrime.gov.in वर तक्रार नोंदवा."]
        bn = [f"“আমি {what_bn} সংক্রান্ত অভিযোগ জানাতে চাই। আমার টাকা যায়নি।”",
              f"“এটি {when}-এ {c.sender_contact or 'অজানা নম্বর'} পাঠিয়েছে।”",
              f"“প্রতারকের UPI ID / ওয়েবসাইট হলো {next((s['value'] for s in suspects if s['kind'] in ('upi', 'domain')), 'আমার রিপোর্টে আছে')}।”",
              "1930 মূলত টাকা খোয়া যাওয়ার ঘটনা দেখে। তারা পরামর্শ দিলে, নিচের বিবরণ দিয়ে cybercrime.gov.in-এ অভিযোগ করুন।"]
    return {"en": en, "hi": hi, "kn": kn, "ta": ta, "te": te, "mr": mr, "bn": bn}


def checklist(source: str, c: ComplaintIn, urgent: bool) -> list[dict]:
    steps = []
    if source == "screenshot":
        steps.append({"id": "verify", "urgent": True,
                      "en": "Open your own UPI app or bank statement and confirm no money arrived with that reference number. Don't hand over anything more.",
                      "hi": "अपना UPI ऐप या बैंक स्टेटमेंट खोलकर पक्का करें कि उस रेफ़रेंस नंबर से कोई पैसा नहीं आया। और कुछ भी न दें।",
                      "kn": "ನಿಮ್ಮ UPI ಆ್ಯಪ್ ಅಥವಾ ಬ್ಯಾಂಕ್ ಸ್ಟೇಟ್‌ಮೆಂಟ್ ತೆರೆದು ಆ ಉಲ್ಲೇಖ ಸಂಖ್ಯೆಯಿಂದ ಯಾವುದೇ ಹಣ ಬಂದಿಲ್ಲ ಎಂದು ಖಚಿತಪಡಿಸಿ. ಇನ್ನೇನೂ ಕೊಡಬೇಡಿ.",
                      "ta": "உங்கள் UPI ஆப் அல்லது வங்கி அறிக்கையைத் திறந்து அந்த குறிப்பு எண்ணில் எந்தப் பணமும் வரவில்லை என்பதை உறுதிப்படுத்தவும். வேறு எதுவும் கொடுக்க வேண்டாம்.",
                      "te": "మీ స్వంత UPI యాప్ లేదా బ్యాంక్ స్టేట్‌మెంట్‌ను తెరిచి, ఆ రిఫరెన్స్ నంబర్‌తో ఎలాంటి డబ్బు రాలేదని నిర్ధారించుకోండి. ఇంకా ఏమీ ఇవ్వవద్దు.",
                      "mr": "तुमचे स्वतःचे UPI ॲप किंवा बँक स्टेटमेंट उघडा आणि त्या संदर्भ क्रमांकावरून कोणतेही पैसे आले नसल्याची खात्री करा. अजून काहीही देऊ नका.",
                      "bn": "আপনার নিজের UPI অ্যাপ বা ব্যাঙ্ক স্টেটমেন্ট খুলে নিশ্চিত করুন যে ওই রেফারেন্স নম্বরে কোনো টাকা আসেনি। আর কিছু দেবেন না।"})
    if c.lost_money:
        steps.append({"id": "call", "urgent": urgent,
                      "en": "Call 1930 now. Money reported within the first hours can often be frozen before it is withdrawn.",
                      "hi": "अभी 1930 पर कॉल करें। पहले कुछ घंटों में शिकायत करने पर पैसे अक्सर निकाले जाने से पहले रोके जा सकते हैं।",
                      "kn": "ಈಗಲೇ 1930 ಗೆ ಕರೆ ಮಾಡಿ. ಮೊದಲ ಕೆಲವು ಗಂಟೆಗಳಲ್ಲಿ ದೂರು ನೀಡಿದರೆ ಹಣ ತೆಗೆಯುವ ಮೊದಲೇ ತಡೆಹಿಡಿಯಬಹುದು.",
                      "ta": "இப்போதே 1930 ஐ அழைக்கவும். முதல் சில மணிநேரங்களில் புகாரளித்தால் பணத்தை திரும்ப எடுக்கவிடாமல் பெரும்பாலும் முடக்கலாம்.",
                      "te": "ఇప్పుడే 1930కి కాల్ చేయండి. మొదటి కొన్ని గంటల్లో నివేదిస్తే విత్‌డ్రా కాకముందే డబ్బును తరచుగా నిలిపివేయవచ్చు.",
                      "mr": "आत्ताच 1930 वर कॉल करा. पहिल्या काही तासांत तक्रार केल्यास पैसे काढण्यापूर्वी ते रोखणे शक्य होते.",
                      "bn": "এখনই 1930 নম্বরে কল করুন। প্রথম কয়েক ঘণ্টার মধ্যে রিপোর্ট করলে টাকা তুলে নেওয়ার আগেই সাধারণত তা ফ্রিজ করা যায়।"})
        steps.append({"id": "bank", "urgent": urgent,
                      "en": "Call your bank's official helpline (number on your card/passbook) and ask them to block UPI, cards and net banking.",
                      "hi": "अपने बैंक की आधिकारिक हेल्पलाइन (कार्ड/पासबुक पर छपा नंबर) पर कॉल करके UPI, कार्ड और नेट बैंकिंग बंद करवाएँ।",
                      "kn": "ನಿಮ್ಮ ಬ್ಯಾಂಕ್‌ನ ಅಧಿಕೃತ ಸಹಾಯವಾಣಿಗೆ (ಕಾರ್ಡ್/ಪಾಸ್‌ಬುಕ್‌ನಲ್ಲಿರುವ ನಂಬರ್) ಕರೆ ಮಾಡಿ UPI, ಕಾರ್ಡ್ ಮತ್ತು ನೆಟ್ ಬ್ಯಾಂಕಿಂಗ್ ನಿರ್ಬಂಧಿಸಿ.",
                      "ta": "உங்கள் வங்கியின் அதிகாரப்பூர்வ உதவி எண்ணை (அட்டை/பாஸ்புக்கில் உள்ள எண்) அழைத்து UPI, அட்டைகள் மற்றும் நெட் பேங்கிங் ஆகியவற்றை முடக்கக் கோருங்கள்.",
                      "te": "మీ బ్యాంక్ అధికారిక హెల్ప్‌లైన్‌కు (కార్డ్/పాస్‌బుక్‌పై ఉన్న నంబర్) కాల్ చేసి UPI, కార్డులు మరియు నెట్ బ్యాంకింగ్‌ను బ్లాక్ చేయమని కోరండి.",
                      "mr": "तुमच्या बँकेच्या अधिकृत हेल्पलाइनवर (कार्ड/पासबुकवरील नंबर) कॉल करा आणि UPI, कार्ड्स आणि नेट बँकिंग ब्लॉक करण्यास सांगा.",
                      "bn": "আপনার ব্যাঙ্কের অফিসিয়াল হেল্পলাইনে (কার্ড/পাসবইয়ে থাকা নম্বর) কল করুন এবং UPI, কার্ড ও নেট ব্যাঙ্কিং ব্লক করতে বলুন।"})
    if source == "apk" and c.app_installed:
        steps.append({"id": "device", "urgent": True,
                      "en": "Turn on flight mode, uninstall the app (Settings → Apps), and change your UPI PIN and net-banking password from another phone.",
                      "hi": "फ़्लाइट मोड चालू करें, ऐप अनइंस्टॉल करें (Settings → Apps), और दूसरे फ़ोन से UPI PIN व नेट-बैंकिंग पासवर्ड बदलें।",
                      "kn": "ಫ್ಲೈಟ್ ಮೋಡ್ ಆನ್ ಮಾಡಿ, ಆ್ಯಪ್ ಅನ್‌ಇನ್‌ಸ್ಟಾಲ್ ಮಾಡಿ (Settings → Apps), ಮತ್ತು ಬೇರೆ ಫೋನ್‌ನಿಂದ UPI PIN ಹಾಗೂ ನೆಟ್-ಬ್ಯಾಂಕಿಂಗ್ ಪಾಸ್‌ವರ್ಡ್ ಬದಲಿಸಿ.",
                      "ta": "விமானப் பயன்முறையை இயக்கவும், ஆப்பை நிறுவல் நீக்கவும் (Settings → Apps), மற்றொரு போனிலிருந்து UPI PIN மற்றும் நெட்-பேங்கிங் கடவுச்சொல்லை மாற்றவும்.",
                      "te": "ఫ్లైట్ మోడ్‌ను ఆన్ చేయండి, యాప్‌ను అన్‌ఇన్‌స్టాల్ చేయండి (Settings → Apps), మరియు వేరే ఫోన్ నుండి మీ UPI PIN మరియు నెట్-బ్యాంకింగ్ పాస్‌వర్డ్‌ను మార్చండి.",
                      "mr": "फ्लाइट मोड चालू करा, ॲप अनइन्स्टॉल करा (Settings → Apps), आणि दुसऱ्या फोनवरून तुमचा UPI PIN आणि नेट-बँकिंग पासवर्ड बदला.",
                      "bn": "ফ্লাইট মোড চালু করুন, অ্যাপটি আনইনস্টল করুন (Settings → Apps), এবং অন্য ফোন থেকে আপনার UPI PIN ও নেট-ব্যাঙ্কিং পাসওয়ার্ড পরিবর্তন করুন।"})
    steps.append({"id": "portal", "urgent": False,
                  "en": "File the complaint on cybercrime.gov.in → 'Report Cyber Crime'. Copy each field from this page and attach the PDF.",
                  "hi": "cybercrime.gov.in → 'Report Cyber Crime' पर शिकायत दर्ज करें। इस पेज से हर फ़ील्ड कॉपी करें और PDF लगाएँ।",
                  "kn": "cybercrime.gov.in → 'Report Cyber Crime' ನಲ್ಲಿ ದೂರು ದಾಖಲಿಸಿ. ಈ ಪುಟದಿಂದ ಪ್ರತಿ ವಿವರ ಕಾಪಿ ಮಾಡಿ ಮತ್ತು PDF ಲಗತ್ತಿಸಿ.",
                  "ta": "cybercrime.gov.in → 'Report Cyber Crime' இல் புகார் பதிவு செய்யவும். இந்தப் பக்கத்திலிருந்து ஒவ்வொரு விவரத்தையும் நகலெடுத்து PDF ஐ இணைக்கவும்.",
                  "te": "cybercrime.gov.in → 'Report Cyber Crime'లో ఫిర్యాదు నమోదు చేయండి. ఈ పేజీ నుండి ప్రతి ఫీల్డ్‌ను కాపీ చేసి, PDFని జతచేయండి.",
                  "mr": "cybercrime.gov.in → 'Report Cyber Crime' वर तक्रार नोंदवा. या पृष्ठावरून प्रत्येक माहिती कॉपी करा आणि PDF जोडा.",
                  "bn": "cybercrime.gov.in → 'Report Cyber Crime'-এ অভিযোগ জমা দিন। এই পেজ থেকে প্রতিটি ফিল্ড কপি করুন এবং PDF সংযুক্ত করুন।"})
    if c.sender_contact:
        steps.append({"id": "chakshu", "urgent": False,
                      "en": "Report the sender's number on Chakshu (Sanchar Saathi) so it can be investigated and blocked.",
                      "hi": "भेजने वाले का नंबर चक्षु (संचार साथी) पर रिपोर्ट करें ताकि उसकी जाँच होकर उसे बंद किया जा सके।",
                      "kn": "ಕಳುಹಿಸಿದವರ ನಂಬರ್ ಅನ್ನು ಚಕ್ಷು (ಸಂಚಾರ ಸಾಥಿ) ನಲ್ಲಿ ವರದಿ ಮಾಡಿ, ಅದನ್ನು ತನಿಖೆ ಮಾಡಿ ನಿರ್ಬಂಧಿಸಬಹುದು.",
                      "ta": "அனுப்பியவரின் எண்ணை சக்ஷுவில் (சஞ்சார் சாதி) புகாரளிக்கவும், இதனால் அதை விசாரித்து முடக்க முடியும்.",
                      "te": "పంపినవారి నంబర్‌ను చక్షు (సంచార్ సాథీ)లో నివేదించండి, తద్వారా దానిపై విచారణ జరిపి బ్లాక్ చేయవచ్చు.",
                      "mr": "पाठवणाऱ्याचा नंबर चक्षू (संचार साथी) वर नोंदवा जेणेकरून त्याची चौकशी करून तो ब्लॉक करता येईल.",
                      "bn": "প্রেরকের নম্বর চক্ষু (সঞ্চার সাথী) পোর্টালে রিপোর্ট করুন যাতে এটি তদন্ত করে ব্লক করা যায়।"})
    steps.append({"id": "evidence", "urgent": False,
                  "en": "Keep screenshots of the chat, the QR/file and your bank SMS. Don't delete the chat.",
                  "hi": "चैट, QR/फ़ाइल और बैंक SMS के स्क्रीनशॉट रखें। चैट डिलीट न करें।",
                  "kn": "ಚಾಟ್, QR/ಫೈಲ್ ಮತ್ತು ಬ್ಯಾಂಕ್ SMS ನ ಸ್ಕ್ರೀನ್‌ಶಾಟ್ ಇಟ್ಟುಕೊಳ್ಳಿ. ಚಾಟ್ ಅಳಿಸಬೇಡಿ.",
                  "ta": "அரட்டை, QR/கோப்பு மற்றும் வங்கி SMS ஆகியவற்றின் ஸ்கிரீன்ஷாட்களை வைத்திருக்கவும். அரட்டையை நீக்க வேண்டாம்.",
                  "te": "చాట్, QR/ఫైల్ మరియు బ్యాంక్ SMS యొక్క స్క్రీన్‌షాట్‌లను ఉంచండి. చాట్‌ను తొలగించవద్దు.",
                  "mr": "चॅट, QR/फाइल आणि बँक SMS चे स्क्रीनशॉट ठेवा. चॅट हटवू नका.",
                  "bn": "চ্যাট, QR/ফাইল এবং ব্যাঙ্কের SMS-এর স্ক্রিনশট রাখুন। চ্যাট মুছবেন না।"})
    return steps


def portal_fields(source: str, scan: dict, c: ComplaintIn, suspects: list[dict], cat: dict, text: str) -> list[dict]:
    f = [
        {"key": "category", "label": "Category of complaint", "value": cat["category"]},
        {"key": "subcategory", "label": "Sub-category", "value": cat["subcategory"]},
        {"key": "incident_time", "label": "Approximate date & time of incident", "value": fmt_time(c.incident_time)},
        {"key": "platform", "label": "Where did the incident occur?", "value": CHANNELS.get(c.channel or "", "Not provided")},
    ]
    if c.lost_money:
        f += [
            {"key": "amount", "label": "Amount lost", "value": fmt_inr(c.amount)},
            {"key": "method", "label": "Payment method", "value": METHODS.get(c.payment_method or "", "Not provided")},
            {"key": "victim_bank", "label": "Your bank / wallet", "value": c.victim_bank or "Not provided"},
            {"key": "txn", "label": "Transaction ID / UTR", "value": ", ".join(c.transaction_ids) or "Not provided"},
            {"key": "paid_to", "label": "Beneficiary (money sent to)", "value": c.paid_to or next((s["value"] for s in suspects if s["kind"] == "upi"), "Not provided")},
        ]
    for s in suspects:
        if s["kind"] in ("upi", "domain", "url", "phone", "handle", "package", "telegram", "account", "utr_claimed", "amount_claimed"):
            f.append({"key": "suspect_" + s["kind"], "label": "Suspect — " + s["label"], "value": s["value"]})
    f.append({"key": "description", "label": "Description of the incident", "value": text})
    return f


def evidence_digest(obj: dict) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()


def build(ref: str, source: str, scan: dict, c: ComplaintIn) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    suspects = suspects_from_scan(source, scan, c)
    cat = suggest_category(source, scan, c)
    text = complaint_text(source, scan, c, suspects, ref)
    urgent = bool(c.lost_money and (c.incident_time is None or now - c.incident_time < dt.timedelta(hours=24)))
    scan_summary = {
        "kind": source, "score": scan["verdict"]["score"], "level": scan["verdict"]["level"],
        "headline": scan["verdict"]["headline"],
        "findings": [{"id": x["id"], "severity": x["severity"], "title": x["title"], "detail": x["detail"],
                      "evidence": x["evidence"][:4]} for x in scan["findings"][:10]],
    }
    if source == "screenshot":
        scan_summary["file"] = {k: scan["file"][k] for k in ("name", "size", "format", "width", "height", "sha256")}
        scan_summary["details"] = {k: scan["details"].get(k) for k in ("app", "status", "amount", "utr", "date", "payee")}
        scan_summary["annotated"] = scan.get("annotated")
    elif source == "apk":
        scan_summary["file"] = {k: scan["file"][k] for k in ("name", "size", "md5", "sha1", "sha256")}
        scan_summary["app"] = {k: scan["app"].get(k) for k in ("name", "package", "version_name", "target_sdk")}
        scan_summary["signing"] = {k: scan["signing"].get(k) for k in ("subject", "sha256", "not_before", "debug_cert")}
    elif source == "message":
        scan_summary["payload"] = scan["payload"]
        d = scan["details"]
        scan_summary["details"] = {"category": d.get("category"), "category_name": d.get("category_name"), "asks": d.get("asks"),
                                   "links": [{k: l.get(k) for k in ("url", "domain", "official", "level")} for l in d.get("links", [])],
                                   "upi_ids": d.get("upi_ids"), "phones": d.get("phones")}
    else:
        scan_summary["payload"] = scan["payload"]
        scan_summary["details"] = {k: v for k, v in scan["details"].items() if k != "params"}
    incident = c.model_dump(mode="json", exclude={"source", "sha256", "payload", "lang", "victim_name", "victim_mobile", "victim_email"})
    body = {
        "ref": ref, "created_at": now.isoformat(timespec="seconds"),
        "lang": c.lang, "urgent": urgent,
        "category": cat, "suspects": suspects, "incident": incident,
        "victim": {"name": c.victim_name, "mobile": c.victim_mobile, "email": c.victim_email},
        "scan": scan_summary,
        "portal_fields": portal_fields(source, scan, c, suspects, cat, text),
        "complaint_text": text,
        "call_script": call_script(source, scan, c, suspects),
        "checklist": checklist(source, c, urgent),
        "links": {"portal": PORTAL_URL, "helpline": HELPLINE, "chakshu": CHAKSHU_URL},
    }
    body["evidence_sha256"] = evidence_digest({"scan": {k: v for k, v in scan_summary.items() if k != "annotated"},
                                               "suspects": suspects, "incident": incident, "ref": ref})
    return body
