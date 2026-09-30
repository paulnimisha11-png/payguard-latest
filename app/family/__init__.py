"""Family guardian mode.

A guardian (e.g. a son or daughter) links a parent's phone. When the parent's phone gets a dangerous or
suspicious result — a QR code, link, message, payment screenshot or app — or the parent chooses to pay a
risky UPI ID anyway, every guardian gets an alert (in-app inbox, Web Push, and the Android app's notifications).

Accounts without passwords: every phone/browser registers as a *device* and keeps a random secret (only its
SHA-256 is stored). Requests prove the device with the header  X-PG-Device: <device_id>.<secret>.

Linking: the guardian creates a 6-digit code (valid 15 minutes, single use); the parent types it (or scans the
QR) on their own phone and confirms. Either side can unlink at any time.

Privacy: alerts carry the scam type, verdict and a masked identifier (e.g. "981•••45@ybl"), never the message
text or screenshot. Alerts are deleted after 30 days.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time

from .. import store
from ..analyzer.rules import T

INVITE_TTL = 15 * 60
ALERT_TTL_DAYS = 30
DEDUPE_SECONDS = 10 * 60
_db, _lock = store._db, store._lock

with _lock:
    _db.executescript("""
    CREATE TABLE IF NOT EXISTS fam_devices(id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, name TEXT, phone TEXT,
        platform TEXT, lang TEXT, created REAL, last_seen REAL);
    CREATE TABLE IF NOT EXISTS fam_invites(code TEXT PRIMARY KEY, guardian_id TEXT, created REAL, expires REAL, used INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS fam_links(guardian_id TEXT, protected_id TEXT, created REAL, PRIMARY KEY(guardian_id, protected_id));
    CREATE INDEX IF NOT EXISTS idx_fam_prot ON fam_links(protected_id);
    CREATE TABLE IF NOT EXISTS fam_alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, guardian_id TEXT, protected_id TEXT, created REAL,
        type TEXT, kind TEXT, level TEXT, category TEXT, target TEXT, body TEXT, dedupe TEXT, seen INTEGER DEFAULT 0);
    CREATE INDEX IF NOT EXISTS idx_fam_alerts ON fam_alerts(guardian_id, id);
    CREATE TABLE IF NOT EXISTS fam_push(endpoint TEXT PRIMARY KEY, device_id TEXT, sub TEXT, created REAL);
    CREATE TABLE IF NOT EXISTS fam_join_fail(ip TEXT, at REAL);
    """)
    _db.commit()


class FamilyError(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _clean_name(name: str | None, default: str) -> str:
    n = " ".join((name or "").split())[:40]
    return n or default


def _clean_phone(p: str | None) -> str | None:
    d = "".join(ch for ch in (p or "") if ch.isdigit())
    if len(d) == 12 and d.startswith("91"):
        d = d[2:]
    return d if len(d) == 10 and d[0] in "6789" else None


# ------------------------------------------------------------------ devices

def register(name: str | None, platform: str | None, lang: str | None) -> dict:
    did = secrets.token_urlsafe(16)
    secret = secrets.token_urlsafe(32)
    now = time.time()
    with _lock:
        _db.execute("INSERT INTO fam_devices VALUES (?,?,?,?,?,?,?,?)",
                    (did, _h(secret), _clean_name(name, ""), None, (platform or "web")[:16], (lang or "en")[:2], now, now))
        _db.commit()
    return {"device_id": did, "secret": secret, "token": f"{did}.{secret}"}


def authenticate(token: str | None) -> str | None:
    """Device id for a valid 'id.secret' token, else None."""
    if not token or "." not in token or len(token) > 200:
        return None
    did, secret = token.split(".", 1)
    with _lock:
        row = _db.execute("SELECT secret_hash FROM fam_devices WHERE id=?", (did,)).fetchone()
        if not row or not hmac.compare_digest(row[0], _h(secret)):
            return None
        _db.execute("UPDATE fam_devices SET last_seen=? WHERE id=?", (time.time(), did))
        _db.commit()
    return did


def update_device(did: str, name: str | None = None, phone: str | None = None, lang: str | None = None) -> None:
    with _lock:
        if name is not None:
            _db.execute("UPDATE fam_devices SET name=? WHERE id=?", (_clean_name(name, ""), did))
        if phone is not None:
            _db.execute("UPDATE fam_devices SET phone=? WHERE id=?", (_clean_phone(phone), did))
        if lang in ("en", "hi", "kn", "ta", "te", "mr", "bn"):
            _db.execute("UPDATE fam_devices SET lang=? WHERE id=?", (lang, did))
        _db.commit()


def _device(did: str) -> dict | None:
    with _lock:
        row = _db.execute("SELECT id, name, phone, platform, lang, created, last_seen FROM fam_devices WHERE id=?", (did,)).fetchone()
    return dict(zip(("id", "name", "phone", "platform", "lang", "created", "last_seen"), row)) if row else None


def delete_device(did: str) -> None:
    """Forget this phone completely: links, alerts, push subscriptions."""
    with _lock:
        _db.execute("DELETE FROM fam_links WHERE guardian_id=? OR protected_id=?", (did, did))
        _db.execute("DELETE FROM fam_alerts WHERE guardian_id=? OR protected_id=?", (did, did))
        _db.execute("DELETE FROM fam_push WHERE device_id=?", (did,))
        _db.execute("DELETE FROM fam_invites WHERE guardian_id=?", (did,))
        _db.execute("DELETE FROM fam_devices WHERE id=?", (did,))
        _db.commit()


def me(did: str) -> dict:
    d = _device(did) or {}
    with _lock:
        protecting = _db.execute("""SELECT d.id, d.name, d.phone, l.created, d.last_seen,
                (SELECT MAX(created) FROM fam_alerts a WHERE a.guardian_id=l.guardian_id AND a.protected_id=d.id)
                FROM fam_links l JOIN fam_devices d ON d.id=l.protected_id WHERE l.guardian_id=? ORDER BY l.created""", (did,)).fetchall()
        protected_by = _db.execute("""SELECT d.id, d.name, d.phone, l.created FROM fam_links l JOIN fam_devices d ON d.id=l.guardian_id
                WHERE l.protected_id=? ORDER BY l.created""", (did,)).fetchall()
        (unread,) = _db.execute("SELECT COUNT(*) FROM fam_alerts WHERE guardian_id=? AND seen=0", (did,)).fetchone()
        (push,) = _db.execute("SELECT COUNT(*) FROM fam_push WHERE device_id=?", (did,)).fetchone()
    return {
        "device": {"id": did, "name": d.get("name") or "", "phone": d.get("phone"), "lang": d.get("lang"), "push_enabled": bool(push)},
        "protecting": [{"id": i, "name": n or "Family member", "phone": p, "since": c, "last_seen": ls, "last_alert": la}
                       for i, n, p, c, ls, la in protecting],
        "protected_by": [{"id": i, "name": n or "Family member", "phone": p, "since": c} for i, n, p, c in protected_by],
        "unread": unread,
        "active_invite": active_invite(did),
    }


def active_invite(guardian_id: str) -> dict | None:
    now = time.time()
    with _lock:
        row = _db.execute(
            "SELECT code, created, expires FROM fam_invites WHERE guardian_id=? AND used=0 AND expires > ? ORDER BY created DESC LIMIT 1",
            (guardian_id, now)
        ).fetchone()
    if not row:
        return None
    code, created, expires = row
    return {"code": code, "expires_in": max(0, int(expires - now)), "expires_at": expires}


def create_invite(guardian_id: str, guardian_name: str | None = None) -> dict:
    if guardian_name is not None:
        update_device(guardian_id, name=guardian_name)
    now = time.time()
    with _lock:
        _db.execute("DELETE FROM fam_invites WHERE expires < ? OR used=1", (now,))
        for _ in range(20):
            code = f"{secrets.randbelow(10**6):06d}"
            if not _db.execute("SELECT 1 FROM fam_invites WHERE code=?", (code,)).fetchone():
                break
        _db.execute("INSERT INTO fam_invites VALUES (?,?,?,?,0)", (code, guardian_id, now, now + INVITE_TTL))
        _db.commit()
    return {"code": code, "expires_in": INVITE_TTL, "expires_at": now + INVITE_TTL}


def join(protected_id: str, code: str, name: str | None, ip: str) -> dict:
    now = time.time()
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    with _lock:
        _db.execute("DELETE FROM fam_join_fail WHERE at < ?", (now - 600,))
        (fails,) = _db.execute("SELECT COUNT(*) FROM fam_join_fail WHERE ip=?", (ip,)).fetchone()
        _db.commit()
    if fails >= 10:
        raise FamilyError(429, "Too many wrong codes. Wait 10 minutes and ask for a new code.")
    with _lock:
        row = _db.execute("SELECT guardian_id, expires, used FROM fam_invites WHERE code=?", (code,)).fetchone()
        if not row:
            _db.execute("INSERT INTO fam_join_fail VALUES (?,?)", (ip, now))
            _db.commit()
            raise FamilyError(404, f"Code '{code}' was not found. Please make sure you are using the active 6-digit code.")
        if row[2]:
            _db.execute("INSERT INTO fam_join_fail VALUES (?,?)", (ip, now))
            _db.commit()
            raise FamilyError(404, "This code has already been used. Each code works only once. Ask for a new code.")
        if row[1] < now:
            _db.execute("INSERT INTO fam_join_fail VALUES (?,?)", (ip, now))
            _db.commit()
            raise FamilyError(404, "This code has expired (valid for 15 minutes). Ask for a new code.")
        guardian_id = row[0]
        if guardian_id == protected_id:
            raise FamilyError(422, "Enter this code on the OTHER person's phone, not on the phone that created it.")
        _db.execute("UPDATE fam_invites SET used=1 WHERE code=?", (code,))
        _db.execute("INSERT OR IGNORE INTO fam_links VALUES (?,?,?)", (guardian_id, protected_id, now))
        _db.execute("DELETE FROM fam_join_fail WHERE ip=?", (ip,))
        _db.commit()
    if name:
        update_device(protected_id, name=name)
    g = _device(guardian_id) or {}
    p = _device(protected_id) or {}
    _notify(guardian_id, protected_id, "linked", None, None, None, None,
            {"en": f"{p.get('name') or 'Your family member'} is now protected",
             "hi": f"{p.get('name') or 'आपके परिजन'} अब सुरक्षित हैं",
             "kn": f"{p.get('name') or 'ನಿಮ್ಮ ಕುಟುಂಬದವರು'} ಈಗ ರಕ್ಷಿತರು",
             "ta": f"{p.get('name') or 'உங்கள் குடும்பத்தினர்'} இப்போது பாதுகாக்கப்பட்டுள்ளனர்",
             "te": f"{p.get('name') or 'మీ కుటుంబ సభ్యులు'} ఇప్పుడు సురక్షితంగా ఉన్నారు",
             "mr": f"{p.get('name') or 'तुमचे कुटुंबीय'} आता सुरक्षित आहेत",
             "bn": f"{p.get('name') or 'আপনার পরিবারের সদস্য'} এখন সুরক্ষিত"},
            {"en": "You'll get an alert here if they check something dangerous or try to pay a risky UPI ID.",
             "hi": "अगर वे कुछ ख़तरनाक जाँचते हैं या किसी ख़तरनाक UPI ID पर पैसे भेजने की कोशिश करते हैं, तो आपको यहाँ अलर्ट मिलेगा।",
             "kn": "ಅವರು ಅಪಾಯಕಾರಿ ಏನನ್ನಾದರೂ ಪರಿಶೀಲಿಸಿದರೆ ಅಥವಾ ಅಪಾಯಕಾರಿ UPI ID ಗೆ ಪಾವತಿಸಲು ಯತ್ನಿಸಿದರೆ ನಿಮಗೆ ಇಲ್ಲಿ ಎಚ್ಚರಿಕೆ ಬರುತ್ತದೆ.",
             "ta": "அவர்கள் ஏதேனும் ஆபத்தானதை சோதித்தாலோ அல்லது ஆபத்தான UPI IDக்கு பணம் செலுத்த முயன்றாலோ உங்களுக்கு இங்கே எச்சரிக்கை வரும்.",
             "te": "వారు ఏదైనా ప్రమాదకరమైనదాన్ని తనిఖీ చేసినా లేదా ప్రమాదకరమైన UPI IDకి చెల్లించడానికి ప్రయత్నించినా మీకు ఇక్కడ హెచ్చరిక వస్తుంది.",
             "mr": "त्यांनी काही धोकादायक तपासल्यास किंवा धोकादायक UPI ID वर पैसे पाठवण्याचा प्रयत्न केल्यास तुम्हाला येथे अलर्ट मिळेल.",
             "bn": "তারা কোনো বিপজ্জনক কিছু পরীক্ষা করলে বা ঝুঁকিপূর্ণ UPI ID-তে টাকা পাঠাতে চেষ্টা করলে আপনি এখানে সতর্কতা পাবেন।"},
            dedupe=None)
    return {"guardian": {"id": guardian_id, "name": g.get("name") or "Family member", "phone": g.get("phone")}}


def unlink(did: str, other_id: str) -> bool:
    with _lock:
        cur = _db.execute("DELETE FROM fam_links WHERE (guardian_id=? AND protected_id=?) OR (guardian_id=? AND protected_id=?)",
                          (did, other_id, other_id, did))
        _db.execute("DELETE FROM fam_alerts WHERE (guardian_id=? AND protected_id=?) OR (guardian_id=? AND protected_id=?)",
                    (did, other_id, other_id, did))
        _db.commit()
    return cur.rowcount > 0


def guardians_of(did: str) -> list[str]:
    with _lock:
        return [r[0] for r in _db.execute("SELECT guardian_id FROM fam_links WHERE protected_id=?", (did,)).fetchall()]


# ------------------------------------------------------------------ alerts

KIND_WORD = {
    "qr": {"en": "a QR code / link", "hi": "एक QR कोड / लिंक", "kn": "ಒಂದು QR ಕೋಡ್ / ಲಿಂಕ್",
           "ta": "ஒரு QR குறியீடு / இணைப்பு", "te": "ఒక QR కోడ్ / లింక్", "mr": "एक QR कोड / लिंक", "bn": "একটি QR কোড / লিঙ্ক"},
    "msg": {"en": "a message", "hi": "एक मैसेज", "kn": "ಒಂದು ಸಂದೇಶ",
            "ta": "ஒரு செய்தி", "te": "ఒక సందేశం", "mr": "एक संदेश", "bn": "একটি বার্তা"},
    "shot": {"en": "a payment screenshot", "hi": "एक पेमेंट स्क्रीनशॉट", "kn": "ಒಂದು ಪಾವತಿ ಸ್ಕ್ರೀನ್‌ಶಾಟ್",
             "ta": "ஒரு கட்டண ஸ்கிரீன்ஷாட்", "te": "ఒక చెల్లింపు స్క్రీನ್‌ಶಾಟ್", "mr": "एक पेमेंट स्क्रीनशॉट", "bn": "একটি পেমেন্ট স্ক্রিনশট"},
    "apk": {"en": "an app file", "hi": "एक ऐप फ़ाइल", "kn": "ಒಂದು ಆ್ಯಪ್ ಫೈಲ್",
            "ta": "ஒரு ஆப் கோப்பு", "te": "ఒక యాప్ ఫైల్", "mr": "एक ॲप फाइल", "bn": "একটি অ্যাপ ফাইল"},
}
LEVEL_WORD = {
    "danger": {"en": "dangerous", "hi": "ख़तरनाक", "kn": "ಅಪಾಯಕಾರಿ",
               "ta": "ஆபத்தானது", "te": "ప్రమాదకరమైనది", "mr": "धोकादायक", "bn": "বিপজ্জনক"},
    "suspicious": {"en": "suspicious", "hi": "संदिग्ध", "kn": "ಸಂಶಯಾಸ್ಪದ",
                   "ta": "சந்தேகத்திற்குரியது", "te": "అనుమానాస్పదమైనది", "mr": "संशयास्पद", "bn": "সন্দেহজনক"},
}


def _target(rep: dict) -> str | None:
    """A masked identifier the guardian can act on, never content."""
    from ..trends import mask
    d = rep.get("details") or {}
    kind = rep.get("kind")
    if kind == "qr":
        if d.get("payee_vpa"):
            return mask("upi", d["payee_vpa"].lower())
        if d.get("registered_domain") or d.get("host"):
            return mask("domain", (d.get("registered_domain") or d.get("host")).lower())
        if d.get("number"):
            return mask("phone", "".join(ch for ch in d["number"] if ch.isdigit())[-10:])
    if kind == "msg":
        if d.get("upi_ids"):
            return mask("upi", d["upi_ids"][0])
        bad = [l for l in d.get("links", []) if not l.get("official")]
        if bad:
            return mask("domain", bad[0]["domain"])
        if d.get("phones"):
            return mask("phone", d["phones"][0])
    if kind == "shot" and d.get("amount"):
        return f"₹{d['amount']:,.2f}"
    if kind == "apk":
        return (rep.get("app") or {}).get("name")
    return None


def _category_name(rep: dict) -> dict | None:
    from ..trends import CATEGORY_NAMES, event_category
    c = event_category(rep)
    return CATEGORY_NAMES.get(c) if c else None


def alert_for_scan(protected_id: str, rep: dict, event: str = "checked") -> int:
    """Create alerts for every guardian of this device. Returns how many were created."""
    level = (rep.get("verdict") or {}).get("level")
    if event == "checked" and level not in ("danger", "suspicious"):
        return 0
    guardians = guardians_of(protected_id)
    if not guardians:
        return 0
    p = _device(protected_id) or {}
    who = p.get("name") or None
    kind = rep.get("kind", "qr")
    target = _target(rep)
    cat = _category_name(rep)
    kw, lw = KIND_WORD.get(kind, KIND_WORD["qr"]), LEVEL_WORD.get(level, LEVEL_WORD["suspicious"])
    if event == "pay_anyway":
        title = {
            "en": f"⚠️ {who or 'Your family member'} is paying a risky UPI ID",
            "hi": f"⚠️ {who or 'आपके परिजन'} एक ख़तरनाक UPI ID पर पैसे भेज रहे हैं",
            "kn": f"⚠️ {who or 'ನಿಮ್ಮ ಕುಟುಂಬದವರು'} ಅಪಾಯಕಾರಿ UPI ID ಗೆ ಪಾವತಿಸುತ್ತಿದ್ದಾರೆ",
            "ta": f"⚠️ {who or 'உங்கள் குடும்பத்தினர்'} ஆபத்தான UPI IDக்கு பணம் செலுத்துகிறார்கள்",
            "te": f"⚠️ {who or 'మీ కుటుంబ సభ్యులు'} ప్రమాదకరమైన UPI IDకి చెల్లిస్తున్నారు",
            "mr": f"⚠️ {who or 'तुमचे कुटुंबीय'} एका धोकादायक UPI ID वर पैसे भरत आहेत",
            "bn": f"⚠️ {who or 'আপনার পরিবারের সদস্য'} একটি ঝুঁকিপূর্ণ UPI ID-তে টাকা পাঠাচ্ছেন",
        }
        body = {
            "en": "PayGuard warned them, but they chose to continue. Call them now" + (f": {target}" if target else "."),
            "hi": "PayGuard ने चेतावनी दी, फिर भी उन्होंने आगे बढ़ना चुना। उन्हें अभी कॉल करें" + (f": {target}" if target else "।"),
            "kn": "PayGuard ಎಚ್ಚರಿಸಿತು, ಆದರೂ ಅವರು ಮುಂದುವರಿದರು. ಈಗಲೇ ಅವರಿಗೆ ಕರೆ ಮಾಡಿ" + (f": {target}" if target else "."),
            "ta": "PayGuard எச்சரித்தது, ஆனாலும் அவர்கள் தொடர முடிவெடுத்தனர். உடனே அவர்களை அழைக்கவும்" + (f": {target}" if target else "."),
            "te": "PayGuard హెచ్చరించింది, కానీ వారు కొనసాగించారు. వెంటనే వారికి కాల్ చేయండి" + (f": {target}" if target else "."),
            "mr": "PayGuard ने सावध केले, तरीही त्यांनी पुढे जाणे निवडले. त्यांना आत्ताच कॉल करा" + (f": {target}" if target else "."),
            "bn": "PayGuard সতর্ক করেছিল, তাও তারা এগিয়ে যাওয়ার সিদ্ধান্ত নিয়েছে। এখনই তাদের কল করুন" + (f": {target}" if target else "."),
        }
    else:
        title = {
            "en": f"{who or 'Your family member'} checked {kw.get('en', kw['en'])} that looks {lw.get('en', lw['en'])}",
            "hi": f"{who or 'आपके परिजन'} ने {kw.get('hi', kw['en'])} जाँचा जो {lw.get('hi', lw['en'])} लगता है",
            "kn": f"{who or 'ನಿಮ್ಮ ಕುಟುಂಬದವರು'} {lw.get('kn', lw['en'])} ಎನಿಸುವ {kw.get('kn', kw['en'])} ಪರಿಶೀಲಿಸಿದರು",
            "ta": f"{who or 'உங்கள் குடும்பத்தினர்'} {lw.get('ta', lw['en'])} என்று தோன்றும் {kw.get('ta', kw['en'])} சோதித்தனர்",
            "te": f"{who or 'మీ కుటుంబ సభ్యులు'} {lw.get('te', lw['en'])} గా కనిపించే {kw.get('te', kw['en'])} తనిఖీ చేశారు",
            "mr": f"{who or 'तुमच्या कुटुंबियांनी'} {lw.get('mr', lw['en'])} वाटणारा {kw.get('mr', kw['en'])} तपासला",
            "bn": f"{who or 'আপনার পরিবারের সদস্য'} {lw.get('bn', lw['en'])} মনে হওয়া {kw.get('bn', kw['en'])} পরীক্ষা করেছেন",
        }
        hl = (rep.get("verdict") or {}).get("headline") or {}
        body = {l: " · ".join(x for x in [(cat.get(l) or cat.get('en')) if cat else None, target, (hl.get(l) or hl.get('en')) if isinstance(hl, dict) else None] if x) for l in ("en", "hi", "kn", "ta", "te", "mr", "bn")}
    dedupe = hashlib.sha256(f"{event}|{kind}|{rep.get('id')}".encode()).hexdigest()[:24]
    n = 0
    for g in guardians:
        n += _notify(g, protected_id, event, kind, level, (cat or {}).get("en"), target, title, body, dedupe=dedupe)
    return n


def _notify(guardian_id, protected_id, typ, kind, level, category, target, title, body, dedupe) -> int:
    now = time.time()
    with _lock:
        if dedupe and _db.execute("SELECT 1 FROM fam_alerts WHERE guardian_id=? AND protected_id=? AND dedupe=? AND created > ?",
                                  (guardian_id, protected_id, dedupe, now - DEDUPE_SECONDS)).fetchone():
            return 0
        cur = _db.execute("INSERT INTO fam_alerts(guardian_id, protected_id, created, type, kind, level, category, target, body, dedupe) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?)",
                          (guardian_id, protected_id, now, typ, kind, level, category, target,
                           json.dumps({"title": title, "body": body}, ensure_ascii=False), dedupe))
        _db.execute("DELETE FROM fam_alerts WHERE created < ?", (now - ALERT_TTL_DAYS * 86400,))
        _db.commit()
        alert_id = cur.lastrowid
    _push_async(guardian_id, {"id": alert_id, "title": title, "body": body, "type": typ, "level": level, "url": "/family"})
    return 1


def alerts(guardian_id: str, since_id: int = 0, limit: int = 50) -> list[dict]:
    with _lock:
        rows = _db.execute("""SELECT a.id, a.protected_id, d.name, d.phone, a.created, a.type, a.kind, a.level, a.category, a.target, a.body, a.seen
                FROM fam_alerts a LEFT JOIN fam_devices d ON d.id=a.protected_id
                WHERE a.guardian_id=? AND a.id > ? ORDER BY a.id DESC LIMIT ?""", (guardian_id, since_id, min(limit, 200))).fetchall()
    out = []
    for i, pid, name, phone, created, typ, kind, level, cat, target, body, seen in rows:
        b = json.loads(body)
        out.append({"id": i, "from": {"id": pid, "name": name or "Family member", "phone": phone}, "created": created, "type": typ,
                    "kind": kind, "level": level, "category": cat, "target": target, "title": b["title"], "body": b["body"], "seen": bool(seen)})
    return out


def mark_seen(guardian_id: str, up_to_id: int) -> None:
    with _lock:
        _db.execute("UPDATE fam_alerts SET seen=1 WHERE guardian_id=? AND id<=?", (guardian_id, up_to_id))
        _db.commit()


# ------------------------------------------------------------------ push

def push_subscribe(did: str, sub: dict) -> None:
    ep = sub.get("endpoint") or ""
    keys = sub.get("keys") or {}
    if not ep.startswith("https://") or not keys.get("p256dh") or not keys.get("auth") or len(ep) > 1000:
        raise FamilyError(422, "Invalid push subscription.")
    with _lock:
        _db.execute("INSERT OR REPLACE INTO fam_push VALUES (?,?,?,?)", (ep, did, json.dumps(sub), time.time()))
        _db.commit()


def push_unsubscribe(did: str, endpoint: str | None = None) -> None:
    with _lock:
        if endpoint:
            _db.execute("DELETE FROM fam_push WHERE device_id=? AND endpoint=?", (did, endpoint))
        else:
            _db.execute("DELETE FROM fam_push WHERE device_id=?", (did,))
        _db.commit()


PUSH_LOG: list[tuple[str, int]] = []   # (endpoint host, status) — last results, shown in /api/health for debugging


def _push_now(guardian_id: str, data: dict) -> None:
    from . import push
    with _lock:
        subs = _db.execute("SELECT endpoint, sub FROM fam_push WHERE device_id=?", (guardian_id,)).fetchall()
        lang = (_db.execute("SELECT lang FROM fam_devices WHERE id=?", (guardian_id,)).fetchone() or ["en"])[0] or "en"
    msg = {"title": data["title"].get(lang) or data["title"]["en"], "body": data["body"].get(lang) or data["body"]["en"],
           "url": data.get("url", "/family"), "tag": f"pg-{data.get('id')}", "level": data.get("level")}
    for ep, sub in subs:
        try:
            status = push.send(json.loads(sub), msg)
        except Exception:
            status = -1
        PUSH_LOG.append((ep.split("/")[2] if "//" in ep else ep[:30], status))
        del PUSH_LOG[:-20]
        if status in (404, 410):
            push_unsubscribe(guardian_id, ep)


def _push_async(guardian_id: str, data: dict) -> None:
    threading.Thread(target=_push_now, args=(guardian_id, data), daemon=True).start()
