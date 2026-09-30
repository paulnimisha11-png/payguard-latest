"""Accounts: sign-up, sign-in, sessions ("stay signed in until you sign out"), password reset, email confirmation,
login alerts and a per-user history of checks.

Security choices
- Passwords: scrypt (passwords.py). Emails are case-insensitive and unique.
- Sessions: a random 256-bit token in an HttpOnly, Secure, SameSite=Lax cookie. Only its SHA-256 is stored, so a
  database leak doesn't hand out sessions. 30-day lifetime, extended while you use the site (sliding), so people
  stay signed in until they sign out. Signing out deletes the session on the server.
- Brute force: failed sign-ins are limited per email and per IP; unknown emails get the same error and the same
  timing as wrong passwords; "forgot password" never reveals whether an email has an account.
- One-time tokens (email confirmation 24 h, password reset 1 h) are stored hashed and burn on use. A reset signs out
  every device.
"""
from __future__ import annotations

import hashlib
import re
import secrets

from . import emails, mailer
from .db import db, now
from .passwords import DUMMY_HASH, hash_password, needs_rehash, password_problem, verify_password

SESSION_DAYS = 30
COOKIE = "pg_session"
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[a-z]{2,24}$", re.I)
USER_COLS = "id, email, name, phone, lang, email_verified, login_alerts, created, last_login"


class AuthError(Exception):
    def __init__(self, status: int, msg: str, field: str | None = None):
        super().__init__(msg)
        self.status, self.msg, self.field = status, msg, field


def _h(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _user(row) -> dict | None:
    if not row:
        return None
    k = ["id", "email", "name", "phone", "lang", "email_verified", "login_alerts", "created", "last_login"]
    u = dict(zip(k, row))
    u["email_verified"] = bool(u["email_verified"])
    u["login_alerts"] = bool(u["login_alerts"])
    return u


def norm_email(email: str) -> str:
    e = (email or "").strip().lower()
    if not EMAIL_RE.match(e):
        raise AuthError(422, "Enter a valid email address.", "email")
    return e


def clean_name(name: str) -> str:
    n = " ".join((name or "").split())[:60]
    if not n:
        raise AuthError(422, "Enter your name.", "name")
    return n


# ------------------------------------------------------------------ rate limits (stored, so they survive restarts)

def _attempts(key: str, window: float) -> int:
    d = db()
    d.exec("DELETE FROM pg_login_attempts WHERE at < ?", now() - 3600)
    return d.one("SELECT COUNT(*) FROM pg_login_attempts WHERE key=? AND at > ?", key, now() - window)[0]


def _note_attempt(key: str) -> None:
    db().exec("INSERT INTO pg_login_attempts(key, at) VALUES (?, ?)", key, now())


def _clear_attempts(key: str) -> None:
    db().exec("DELETE FROM pg_login_attempts WHERE key=?", key)


def _limit(key: str, max_n: int, window: float, msg: str) -> None:
    if _attempts(key, window) >= max_n:
        raise AuthError(429, msg)


# ------------------------------------------------------------------ users

def signup(name: str, email: str, password: str, lang: str, ip: str, device: str, base_url: str) -> tuple[dict, str]:
    name, email = clean_name(name), norm_email(email)
    problem = password_problem(password, email)
    if problem:
        raise AuthError(422, problem, "password")
    _limit(f"signup:{ip}", 10, 3600, "Too many new accounts from this network. Try again in an hour.")
    _note_attempt(f"signup:{ip}")
    d = db()
    if d.one("SELECT 1 FROM pg_users WHERE email=?", email):
        raise AuthError(409, "An account with this email already exists. Sign in instead, or reset your password.", "email")
    uid = secrets.token_urlsafe(12)
    lang = lang if lang in ("en", "hi", "kn") else "en"
    d.exec("INSERT INTO pg_users(id, email, name, pw_hash, lang, created, last_login) VALUES (?,?,?,?,?,?,?)",
           uid, email, name, hash_password(password), lang, now(), now())
    token = new_session(uid, device, ip)
    verify = _one_time_token(uid, "verify", 24 * 3600)
    subj, html, text = emails.welcome(lang, name, f"{base_url}/api/auth/verify?token={verify}")
    mailer.send(email, subj, html, text)
    return get_user(uid), token


def login(email: str, password: str, ip: str, device: str, base_url: str) -> tuple[dict, str]:
    e = (email or "").strip().lower()
    _limit(f"ip:{ip}", 30, 900, "Too many sign-in attempts from this network. Wait 15 minutes.")
    _limit(f"email:{e}", 6, 900, "Too many wrong passwords for this account. Wait 15 minutes, or reset your password.")
    d = db()
    row = d.one("SELECT id, pw_hash FROM pg_users WHERE email=?", e) if EMAIL_RE.match(e) else None
    ok = verify_password(password or "", row[1] if row else DUMMY_HASH)
    if not row or not ok:
        _note_attempt(f"ip:{ip}")
        _note_attempt(f"email:{e}")
        raise AuthError(401, "Wrong email or password.")
    uid = row[0]
    _clear_attempts(f"email:{e}")
    if needs_rehash(row[1]):
        d.exec("UPDATE pg_users SET pw_hash=? WHERE id=?", hash_password(password), uid)
    d.exec("UPDATE pg_users SET last_login=? WHERE id=?", now(), uid)
    token = new_session(uid, device, ip)
    u = get_user(uid)
    if u["login_alerts"]:
        reset_token = _one_time_token(uid, "reset", 3600)
        subj, html, text = emails.login_alert(u["lang"], now(), device, mask_ip(ip), f"{base_url}/login?reset={reset_token}")
        mailer.send(u["email"], subj, html, text)
    return u, token


def resend_verification(uid: str, base_url: str) -> bool:
    """Sends a fresh confirmation link. Returns False if the email is already confirmed."""
    u = get_user(uid)
    if not u or u["email_verified"]:
        return False
    _limit(f"verify:{uid}", 3, 3600, "We've sent a few links already. Check your spam folder, or try again in an hour.")
    _note_attempt(f"verify:{uid}")
    verify = _one_time_token(uid, "verify", 24 * 3600)
    subj, html, text = emails.welcome(u["lang"], u["name"], f"{base_url}/api/auth/verify?token={verify}")
    mailer.send(u["email"], subj, html, text)
    return True


def get_user(uid: str) -> dict | None:
    return _user(db().one(f"SELECT {USER_COLS} FROM pg_users WHERE id=?", uid))


def update_user(uid: str, name: str | None = None, phone: str | None = None, lang: str | None = None,
                login_alerts: bool | None = None) -> dict:
    d = db()
    if name is not None:
        d.exec("UPDATE pg_users SET name=? WHERE id=?", clean_name(name), uid)
    if phone is not None:
        digits = re.sub(r"\D", "", phone)
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        if digits and not re.fullmatch(r"[6-9]\d{9}", digits):
            raise AuthError(422, "Enter a 10-digit Indian mobile number, or leave it empty.", "phone")
        d.exec("UPDATE pg_users SET phone=? WHERE id=?", digits or None, uid)
    if lang in ("en", "hi", "kn"):
        d.exec("UPDATE pg_users SET lang=? WHERE id=?", lang, uid)
    if login_alerts is not None:
        d.exec("UPDATE pg_users SET login_alerts=? WHERE id=?", 1 if login_alerts else 0, uid)
    return get_user(uid)


def change_password(uid: str, current: str, new: str, keep_session: str, base_url: str) -> None:
    row = db().one("SELECT pw_hash, email, lang FROM pg_users WHERE id=?", uid)
    if not row or not verify_password(current or "", row[0]):
        raise AuthError(401, "Your current password is wrong.", "current")
    problem = password_problem(new, row[1])
    if problem:
        raise AuthError(422, problem, "password")
    db().exec("UPDATE pg_users SET pw_hash=? WHERE id=?", hash_password(new), uid)
    db().exec("DELETE FROM pg_sessions WHERE user_id=? AND id<>?", uid, keep_session)
    t = _one_time_token(uid, "reset", 3600)
    subj, html, text = emails.password_changed(row[2], f"{base_url}/login?reset={t}")
    mailer.send(row[1], subj, html, text)


def delete_account(uid: str, password: str) -> None:
    row = db().one("SELECT pw_hash FROM pg_users WHERE id=?", uid)
    if not row or not verify_password(password or "", row[0]):
        raise AuthError(401, "Wrong password.", "password")
    d = db()
    for t in ("pg_sessions", "pg_tokens", "pg_history"):
        d.exec(f"DELETE FROM {t} WHERE user_id=?", uid)
    d.exec("DELETE FROM pg_users WHERE id=?", uid)


# ------------------------------------------------------------------ sessions

def new_session(uid: str, device: str, ip: str) -> str:
    token = secrets.token_urlsafe(32)
    t = now()
    db().exec("INSERT INTO pg_sessions(id, user_id, created, last_seen, expires, device, ip) VALUES (?,?,?,?,?,?,?)",
              _h(token), uid, t, t, t + SESSION_DAYS * 86400, device[:120], mask_ip(ip))
    return token


def session_user(token: str | None) -> tuple[dict, str, bool] | None:
    """(user, session_id, cookie_should_be_refreshed) for a valid session token."""
    if not token or len(token) > 100:
        return None
    sid = _h(token)
    d = db()
    row = d.one("SELECT user_id, last_seen, expires FROM pg_sessions WHERE id=?", sid)
    if not row:
        return None
    uid, last_seen, expires = row
    t = now()
    if expires < t:
        d.exec("DELETE FROM pg_sessions WHERE id=?", sid)
        return None
    refresh = False
    if t - last_seen > 3600:                       # sliding expiry: active users stay signed in
        new_exp = t + SESSION_DAYS * 86400
        refresh = new_exp - expires > 86400
        d.exec("UPDATE pg_sessions SET last_seen=?, expires=? WHERE id=?", t, max(expires, new_exp), sid)
    u = get_user(uid)
    return (u, sid, refresh) if u else None


def end_session(token: str | None) -> None:
    if token:
        db().exec("DELETE FROM pg_sessions WHERE id=?", _h(token))


def end_all_sessions(uid: str, except_sid: str | None = None) -> int:
    if except_sid:
        return db().exec("DELETE FROM pg_sessions WHERE user_id=? AND id<>?", uid, except_sid)
    return db().exec("DELETE FROM pg_sessions WHERE user_id=?", uid)


def list_sessions(uid: str, current_sid: str) -> list[dict]:
    rows = db().all("SELECT id, created, last_seen, device, ip FROM pg_sessions WHERE user_id=? AND expires>? ORDER BY last_seen DESC",
                    uid, now())
    return [{"id": r[0][:16], "created": r[1], "last_seen": r[2], "device": r[3], "network": r[4], "current": r[0] == current_sid}
            for r in rows]


def end_session_by_prefix(uid: str, prefix: str) -> bool:
    if not re.fullmatch(r"[0-9a-f]{16}", prefix or ""):
        return False
    return db().exec("DELETE FROM pg_sessions WHERE user_id=? AND id LIKE ?", uid, prefix + "%") > 0


# ------------------------------------------------------------------ one-time tokens (verify email, reset password)

def _one_time_token(uid: str, kind: str, ttl: float) -> str:
    token = secrets.token_urlsafe(32)
    d = db()
    d.exec("DELETE FROM pg_tokens WHERE expires < ?", now())
    d.exec("INSERT INTO pg_tokens(token_hash, user_id, kind, expires) VALUES (?,?,?,?)", _h(token), uid, kind, now() + ttl)
    return token


def _use_token(token: str, kind: str) -> str | None:
    if not token or len(token) > 100:
        return None
    d = db()
    row = d.one("SELECT user_id, expires, used FROM pg_tokens WHERE token_hash=? AND kind=?", _h(token), kind)
    if not row or row[2] or row[1] < now():
        return None
    if d.exec("UPDATE pg_tokens SET used=1 WHERE token_hash=? AND used=0", _h(token)) != 1:
        return None                                   # someone else used it at the same moment
    return row[0]


def verify_email(token: str) -> bool:
    uid = _use_token(token, "verify")
    if not uid:
        return False
    db().exec("UPDATE pg_users SET email_verified=1 WHERE id=?", uid)
    return True


def forgot_password(email: str, ip: str, base_url: str) -> None:
    """Always 'succeeds' from the outside, so nobody can learn which emails have accounts."""
    e = (email or "").strip().lower()
    if not EMAIL_RE.match(e):
        return
    if _attempts(f"forgot:{e}", 900) >= 3 or _attempts(f"forgotip:{ip}", 900) >= 10:
        return
    _note_attempt(f"forgot:{e}")
    _note_attempt(f"forgotip:{ip}")
    row = db().one("SELECT id, lang FROM pg_users WHERE email=?", e)
    if not row:
        return
    t = _one_time_token(row[0], "reset", 3600)
    subj, html, text = emails.reset(row[1], f"{base_url}/login?reset={t}")
    mailer.send(e, subj, html, text)


def reset_password(token: str, new: str, ip: str, device: str) -> tuple[dict, str]:
    d = db()
    row = d.one("SELECT user_id FROM pg_tokens WHERE token_hash=? AND kind='reset' AND used=0 AND expires>?", _h(token or ""), now())
    if not row:
        raise AuthError(400, "This reset link has expired or was already used. Ask for a new one.")
    u = get_user(row[0])
    problem = password_problem(new, u["email"] if u else "")
    if problem:
        raise AuthError(422, problem, "password")
    uid = _use_token(token, "reset")
    if not uid:
        raise AuthError(400, "This reset link has expired or was already used. Ask for a new one.")
    d.exec("UPDATE pg_users SET pw_hash=?, email_verified=1 WHERE id=?", hash_password(new), uid)  # they proved the inbox
    end_all_sessions(uid)
    _clear_attempts(f"email:{u['email']}")
    return get_user(uid), new_session(uid, device, ip)


# ------------------------------------------------------------------ history of checks

HISTORY_KEEP = 200


def record_check(uid: str, rep: dict, label: str | None) -> None:
    v = rep.get("verdict") or {}
    kind = rep.get("kind") or "apk"
    link = None
    if kind == "apk" and (rep.get("file") or {}).get("sha256"):
        link = "/r/" + rep["file"]["sha256"]
    elif kind == "shot" and rep.get("id"):
        link = "/s/" + rep["id"]
    title = (v.get("headline") or {}).get("en") if isinstance(v.get("headline"), dict) else v.get("headline")
    d = db()
    d.exec("INSERT INTO pg_history(user_id, created, kind, level, score, title, label, link) VALUES (?,?,?,?,?,?,?,?)",
           uid, now(), kind, v.get("level"), int(v.get("score") or 0), (title or "")[:160], (label or "")[:120] or None, link)
    cutoff = d.one("SELECT id FROM pg_history WHERE user_id=? ORDER BY id DESC LIMIT 1 OFFSET ?", uid, HISTORY_KEEP)
    if cutoff:
        d.exec("DELETE FROM pg_history WHERE user_id=? AND id<=?", uid, cutoff[0])


def history(uid: str, limit: int = 50) -> list[dict]:
    rows = db().all("SELECT id, created, kind, level, score, title, label, link FROM pg_history WHERE user_id=? ORDER BY id DESC LIMIT ?",
                    uid, max(1, min(limit, HISTORY_KEEP)))
    return [dict(zip(("id", "created", "kind", "level", "score", "title", "label", "link"), r)) for r in rows]


def clear_history(uid: str) -> None:
    db().exec("DELETE FROM pg_history WHERE user_id=?", uid)


def stats(uid: str) -> dict:
    rows = db().all("SELECT level, COUNT(*) FROM pg_history WHERE user_id=? GROUP BY level", uid)
    d = {k: n for k, n in rows}
    return {"checks": sum(d.values()), "threats": d.get("danger", 0) + d.get("suspicious", 0)}


# ------------------------------------------------------------------ helpers

def mask_ip(ip: str) -> str:
    ip = ip or "?"
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:3]) + ":…"
    parts = ip.split(".")
    return ".".join(parts[:2] + ["x", "x"]) if len(parts) == 4 else ip


def describe_device(ua: str) -> str:
    ua = ua or ""
    app = "PayGuard app" if "PayGuardApp" in ua else None
    browser = next((n for k, n in (("Edg/", "Edge"), ("SamsungBrowser", "Samsung Internet"), ("OPR/", "Opera"),
                                   ("Firefox/", "Firefox"), ("CriOS", "Chrome"), ("Chrome/", "Chrome"), ("Safari/", "Safari"))
                    if k in ua), "Browser")
    os_ = next((n for k, n in (("Android", "Android"), ("iPhone", "iPhone"), ("iPad", "iPad"), ("Windows", "Windows"),
                               ("Mac OS X", "Mac"), ("Linux", "Linux")) if k in ua), "Unknown device")
    return f"{app or browser} on {os_}"
