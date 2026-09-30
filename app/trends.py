"""Public scam trends: what people are checking and reporting, without exposing anyone.

Rules for the public list of reported UPI IDs / numbers / websites
  * reported by at least PUBLIC_MIN people from at least PUBLIC_MIN different networks (one person can't
    create a public accusation by opening many browsers), and
  * not disputed: fewer "this is genuine" answers than half the reports, and
  * not hidden or cleared by a moderator (APKXRAY_ADMIN_TOKEN). A moderator can also "approve" an entry, which
    publishes it regardless of disputes.
UPI IDs and phone numbers are partly masked on the public page; the exact-match lookup tells anyone whether the
ID/number *they* were given has been reported.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import threading
import time

from . import store
from .analyzer.rules import T
from .message.analyzer import CATEGORIES

PUBLIC_MIN = int(os.environ.get("APKXRAY_PUBLIC_MIN", "3"))
PUBLIC_KINDS = ("upi", "phone", "domain")

CATEGORY_NAMES: dict[str, dict] = {cid: v[0] for cid, v in CATEGORIES.items()}
CATEGORY_NAMES.update({
    "scam_message": T("Other scam messages", "अन्य ठगी मैसेज", "ಇತರ ವಂಚನೆ ಸಂದೇಶಗಳು"),
    "qr_receive_lure": T("'Scan to receive money' QR", "'पैसे पाने के लिए स्कैन करें' QR", "'ಹಣ ಪಡೆಯಲು ಸ್ಕ್ಯಾನ್ ಮಾಡಿ' QR"),
    "qr_impersonation": T("QR pretending to be a bank / company", "बैंक / कंपनी बनकर QR", "ಬ್ಯಾಂಕ್ / ಕಂಪನಿಯಂತೆ ನಟಿಸುವ QR"),
    "qr_autopay": T("Hidden AutoPay mandate in QR", "QR में छिपा AutoPay", "QR ನಲ್ಲಿ ಅಡಗಿದ AutoPay"),
    "phishing_link": T("Fake bank / phishing websites", "नकली बैंक / फ़िशिंग वेबसाइट", "ನಕಲಿ ಬ್ಯಾಂಕ್ / ಫಿಶಿಂಗ್ ವೆಬ್‌ಸೈಟ್"),
    "apk_link": T("Links that download an app (APK)", "ऐप (APK) डाउनलोड करने वाले लिंक", "ಆ್ಯಪ್ (APK) ಡೌನ್‌ಲೋಡ್ ಲಿಂಕ್‌ಗಳು"),
    "qr_other": T("Other risky QR codes", "अन्य ख़तरनाक QR", "ಇತರ ಅಪಾಯಕಾರಿ QR"),
    "fake_screenshot": T("Fake payment screenshots", "नकली पेमेंट स्क्रीनशॉट", "ನಕಲಿ ಪಾವತಿ ಸ್ಕ್ರೀನ್‌ಶಾಟ್"),
    "banking_trojan": T("Banking trojan apps", "बैंकिंग ट्रोजन ऐप", "ಬ್ಯಾಂಕಿಂಗ್ ಟ್ರೋಜನ್ ಆ್ಯಪ್‌ಗಳು"),
    "risky_app": T("Other risky apps", "अन्य ख़तरनाक ऐप", "ಇತರ ಅಪಾಯಕಾರಿ ಆ್ಯಪ್‌ಗಳು"),
})
KIND_NAMES = {"qr": T("QR codes & links", "QR कोड और लिंक", "QR ಕೋಡ್ ಮತ್ತು ಲಿಂಕ್"), "msg": T("Messages", "मैसेज", "ಸಂದೇಶಗಳು"),
              "shot": T("Payment screenshots", "पेमेंट स्क्रीनशॉट", "ಪಾವತಿ ಸ್ಕ್ರೀನ್‌ಶಾಟ್"), "apk": T("App files", "ऐप फ़ाइलें", "ಆ್ಯಪ್ ಫೈಲ್‌ಗಳು")}


def event_category(rep: dict) -> str | None:
    """Scam type of a checked item, only when it was judged risky."""
    if rep.get("verdict", {}).get("level") not in ("danger", "suspicious"):
        return None
    ids = {f["id"] for f in rep.get("findings", [])}
    kind = rep.get("kind")
    if kind == "msg":
        return rep["details"].get("category") or "scam_message"
    if kind == "qr":
        if ids & {"RECEIVE_MONEY_LURE", "COLLECT_REQUEST"}:
            return "qr_receive_lure"
        if "AUTOPAY_MANDATE" in ids:
            return "qr_autopay"
        if "APK_DOWNLOAD" in ids:
            return "apk_link"
        if ids & {"LOOKALIKE_DOMAIN", "PUNYCODE", "IP_ADDRESS_HOST", "USERINFO_TRICK", "BAIT_WORDS_IN_URL", "CHEAP_DOMAIN"}:
            return "phishing_link"
        if "IMPERSONATION" in ids:
            return "qr_impersonation"
        return "qr_other"
    if kind == "shot":
        return "fake_screenshot"
    if ids & {"BANKING_TROJAN_TRIAD", "SMS_OTP_THEFT", "BANK_APP_TARGET_LIST", "SCREEN_OVERLAY"}:
        return "banking_trojan"
    return "risky_app"


def record(rep: dict) -> None:
    try:
        store.event_add(rep.get("kind", "?"), rep.get("verdict", {}).get("level", "?"), event_category(rep))
    except Exception:
        pass  # counting must never break a check


def mask(kind: str, value: str) -> str:
    if kind == "upi" and "@" in value:
        local, handle = value.split("@", 1)
        keep = 3 if len(local) > 6 else 1
        return f"{local[:keep]}{'•' * min(5, max(3, len(local) - keep - 2))}{local[-2:] if len(local) > 6 else ''}@{handle}"
    if kind == "phone" and len(value) >= 8:
        return f"{value[:2]}{'•' * (len(value) - 4)}{value[-2:]}"
    if kind == "domain":
        return value.replace(".", "[.]")  # defanged: shown, but not clickable
    return value


def is_public(e: dict) -> bool:
    if e["status"] in ("hidden", "cleared"):
        return False
    if e["status"] == "approved":
        return True
    return e["reports"] >= PUBLIC_MIN and e["networks"] >= PUBLIC_MIN and e["disputes"] * 2 < e["reports"]


_cache: dict = {"at": 0.0, "data": None}
_cache_lock = threading.Lock()


def _day(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def build(now: float | None = None, use_cache: bool = True) -> dict:
    now = now or time.time()
    with _cache_lock:
        if use_cache and _cache["data"] and now - _cache["at"] < 30:
            return _cache["data"]
    today = dt.date.fromtimestamp(now)
    days = [(today - dt.timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
    this_week, last_week = set(days[7:]), set(days[:7])
    ev = store.events_since(days[0])
    daily = {d: {"day": d, "checks": 0, "threats": 0, "reports": 0} for d in days}
    by_kind = {k: {"kind": k, "name": KIND_NAMES[k], "checks": 0, "threats": 0} for k in KIND_NAMES}
    cats: dict[str, dict] = {}
    for day, kind, level, cat, n in ev:
        if day not in daily:
            continue
        daily[day]["checks"] += n
        risky = level in ("danger", "suspicious")
        if risky:
            daily[day]["threats"] += n
        if day in this_week and kind in by_kind:
            by_kind[kind]["checks"] += n
            by_kind[kind]["threats"] += n if risky else 0
        if cat:
            c = cats.setdefault(cat, {"category": cat, "name": CATEGORY_NAMES.get(cat, T(cat, cat, cat)), "count": 0, "prev": 0})
            c["count" if day in this_week else "prev"] += n
    for created, kind, value, reason in store.report_rows(time.mktime(dt.date.fromisoformat(days[0]).timetuple())):
        d = _day(created)
        if d in daily and reason != "not_scam":
            daily[d]["reports"] += 1
    types = sorted(cats.values(), key=lambda c: (-c["count"], -c["prev"]))
    for c in types:
        c["change"] = None if not c["prev"] else round(100 * (c["count"] - c["prev"]) / c["prev"])
        c["new"] = c["prev"] == 0 and c["count"] > 0
    rising = sorted([c for c in types if c["count"] >= 2 and (c["new"] or (c["change"] or 0) >= 25)],
                    key=lambda c: -(c["count"] - c["prev"]))[:3]

    entries = store.reported_values(PUBLIC_KINDS)
    public = [e for e in entries if is_public(e)]
    pending = [e for e in entries if not is_public(e) and e["status"] not in ("hidden", "cleared")]
    top = {}
    for k in PUBLIC_KINDS:
        rows = sorted([e for e in public if e["kind"] == k], key=lambda e: (-e["reports"], -(e["last"] or 0)))[:10]
        top[k] = [{"display": mask(k, e["value"]), "reports": e["reports"], "got_me": e["got_me"], "complaints": e["complaints"],
                   "disputes": e["disputes"], "first_seen": _day(e["first"]) if e["first"] else None,
                   "last_seen": _day(e["last"]) if e["last"] else None, "confirmed": e["status"] == "approved"} for e in rows]
    week = [daily[d] for d in days[7:]]
    prev = [daily[d] for d in days[:7]]
    data = {
        "generated": int(now),
        "public_min": PUBLIC_MIN,
        "totals": {
            "checks_7d": sum(x["checks"] for x in week), "checks_prev_7d": sum(x["checks"] for x in prev),
            "threats_7d": sum(x["threats"] for x in week), "threats_prev_7d": sum(x["threats"] for x in prev),
            "reports_7d": sum(x["reports"] for x in week), "reports_prev_7d": sum(x["reports"] for x in prev),
            "public_listed": len(public), "pending_review": len(pending),
            "lost_money_reports": sum(e["got_me"] for e in public),
        },
        "daily": [daily[d] for d in days],
        "by_kind": list(by_kind.values()),
        "types": types[:12],
        "rising": rising,
        "top": top,
        "includes_demo_data": any(e["demo"] for e in entries),
    }
    with _cache_lock:
        _cache.update(at=now, data=data)
    return data


def invalidate() -> None:
    with _cache_lock:
        _cache["data"] = None


UPI_LOOKUP = re.compile(r"^[a-z0-9.\-_]{2,64}@[a-z][a-z0-9]{1,31}$", re.I)


def lookup(q: str) -> dict:
    """Has the exact UPI ID / phone number / website someone was given been reported?"""
    from .complaints.builder import norm_phone
    from .qr.analyzer import _registrable
    q = (q or "").strip()
    if not q:
        raise ValueError("Type a UPI ID, phone number or website.")
    if UPI_LOOKUP.match(q):
        kind, value = "upi", q.lower()
    elif re.fullmatch(r"[+\d\s\-()]{8,20}", q) and len(norm_phone(q)) == 10:
        kind, value = "phone", norm_phone(q)
    else:
        host = re.sub(r"^[a-z]+://", "", q.lower()).split("/")[0].split("?")[0].split("@")[-1].split(":")[0]
        if not re.fullmatch(r"[a-z0-9\-.]+\.[a-z]{2,}", host):
            raise ValueError("That doesn't look like a UPI ID (name@bank), a 10-digit number or a website.")
        kind, value = "domain", _registrable(host)
    vc = store.vote_counts(kind, value)
    comp = store.indicator_count(kind, value)
    status = store.moderation_status(kind, value)
    reports = vc["total"] + comp
    return {"kind": kind, "value": value, "reports": 0 if status == "cleared" else reports, "got_me": vc["got_me"],
            "complaints": comp, "disputes": vc["disputes"], "status": status,
            "public": is_public({"status": status, "reports": reports, "networks": vc["networks"] + comp, "disputes": vc["disputes"]})}
