"""Accounts: who is signed in (Clerk does the signing in, see clerk.py), sessions and sign-in alerts, profile, and a
per-user history of checks.

Security choices
- Sign-up, passwords, Google sign-in, email verification and recovery are Clerk's job. PayGuard never sees a
  password; the old email + password endpoints are gone.
- A PayGuard account is linked to a Clerk user by clerk_user_id. The first time a Clerk user shows up, the account
  with the same *verified* email is linked (so people who signed up before Clerk keep their history); otherwise a
  new account is created. An unverified email never links.
- Every Clerk session we see is recorded (device, masked network): that is the "where you're signed in" list and
  what triggers the sign-in alert email. Ending a session here also revokes it at Clerk.
- One-time tokens (the "wasn't me" link in a sign-in alert, 1 h) are stored hashed and burn on use.
"""
from __future__ import annotations

import hashlib
import re
import secrets

from . import emails, mailer
from .db import db, now

SESSION_DAYS = 30                      # a device drops off the list after this long without a visit
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


# ------------------------------------------------------------------ users

def clerk_user(clerk_id: str, fetch) -> tuple[dict, bool] | None:
    """(PayGuard user, newly created?) for a Clerk user id. `fetch(clerk_id)` asks Clerk for the user's primary
    email; it is only called the first time we meet this Clerk user."""
    d = db()
    row = d.one(f"SELECT {USER_COLS} FROM pg_users WHERE clerk_user_id=?", clerk_id)
    if row:
        return _user(row), False
    info = fetch(clerk_id)
    if not info or not info.get("verified"):
        return None                                   # never link on an email nobody proved they own
    email = norm_email(info["email"])
    old = d.one("SELECT id FROM pg_users WHERE email=?", email)
    if old:                                           # an account from before Clerk: same person, keep everything
        if d.exec("UPDATE pg_users SET clerk_user_id=?, email_verified=1 WHERE id=? AND clerk_user_id IS NULL",
                  clerk_id, old[0]) != 1:
            return None                               # that email already belongs to another Clerk user
        return get_user(old[0]), False
    uid = secrets.token_urlsafe(12)
    name = " ".join((info.get("name") or "").split())[:60] or email.split("@")[0][:60]
    try:
        d.exec("INSERT INTO pg_users(id, email, name, pw_hash, email_verified, created, last_login, clerk_user_id) "
               "VALUES (?,?,?,'',1,?,?,?)", uid, email, name, now(), now(), clerk_id)
    except Exception:                                 # two first requests at the same moment: the other one won
        row = d.one(f"SELECT {USER_COLS} FROM pg_users WHERE clerk_user_id=?", clerk_id)
        return (_user(row), False) if row else None
    return get_user(uid), True


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


def delete_account(uid: str) -> str | None:
    """Removes the profile, history and sessions. Returns the Clerk user id that was linked, if any."""
    d = db()
    row = d.one("SELECT clerk_user_id FROM pg_users WHERE id=?", uid)
    for t in ("pg_sessions", "pg_tokens", "pg_history"):
        d.exec(f"DELETE FROM {t} WHERE user_id=?", uid)
    d.exec("DELETE FROM pg_users WHERE id=?", uid)
    return row[0] if row else None


# ------------------------------------------------------------------ sessions

def clerk_session(u: dict, clerk_sid: str, device: str, ip: str, base_url: str, alert: bool = True) -> str | None:
    """Our record of one Clerk session; returns its id here, or None if it was signed out from the account page
    (Clerk's token can outlive that by up to a minute). A session we haven't seen before is a new sign-in: it is
    added to the device list and, unless alerts are off, the owner gets the sign-in email."""
    sid, d, t = _h(clerk_sid), db(), now()
    row = d.one("SELECT last_seen, expires FROM pg_sessions WHERE id=?", sid)
    if row:
        if row[1] <= 0:
            return None
        if t - row[0] > 3600:
            d.exec("UPDATE pg_sessions SET last_seen=?, expires=? WHERE id=?", t, t + SESSION_DAYS * 86400, sid)
        return sid
    try:
        d.exec("INSERT INTO pg_sessions(id, user_id, created, last_seen, expires, device, ip, clerk_sid) VALUES (?,?,?,?,?,?,?,?)",
               sid, u["id"], t, t, t + SESSION_DAYS * 86400, device[:120], mask_ip(ip), clerk_sid)
    except Exception:                                 # a parallel request recorded it first
        return sid
    d.exec("UPDATE pg_users SET last_login=? WHERE id=?", t, u["id"])
    if alert and u["login_alerts"]:
        reset_token = _one_time_token(u["id"], "reset", 3600)
        subj, html, text = emails.login_alert(u["lang"], t, device, mask_ip(ip), f"{base_url}/login?reset={reset_token}")
        mailer.send(u["email"], subj, html, text)
    return sid


def _end(where: str, *params) -> list[str]:
    """Marks sessions as signed out and returns their Clerk session ids so the caller can revoke them at Clerk."""
    d = db()
    rows = d.all(f"SELECT clerk_sid FROM pg_sessions WHERE {where} AND expires>0 AND clerk_sid IS NOT NULL", *params)
    d.exec(f"UPDATE pg_sessions SET expires=0 WHERE {where}", *params)
    return [r[0] for r in rows]


def end_session(sid: str) -> list[str]:
    return _end("id=?", sid)


def end_all_sessions(uid: str) -> list[str]:
    return _end("user_id=?", uid)


def list_sessions(uid: str, current_sid: str) -> list[dict]:
    rows = db().all("SELECT id, created, last_seen, device, ip FROM pg_sessions WHERE user_id=? AND expires>? "
                    "AND clerk_sid IS NOT NULL ORDER BY last_seen DESC", uid, now())
    return [{"id": r[0][:16], "created": r[1], "last_seen": r[2], "device": r[3], "network": r[4], "current": r[0] == current_sid}
            for r in rows]


def end_session_by_prefix(uid: str, prefix: str) -> list[str] | None:
    if not re.fullmatch(r"[0-9a-f]{16}", prefix or ""):
        return None
    if not db().one("SELECT 1 FROM pg_sessions WHERE user_id=? AND id LIKE ? AND expires>0", uid, prefix + "%"):
        return None
    return _end("user_id=? AND id LIKE ?", uid, prefix + "%")


# ------------------------------------------------------------------ one-time tokens (the "wasn't me" link)

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


def lock_account(token: str) -> list[str] | None:
    """The "wasn't me" link in a sign-in alert: signs the account out everywhere. Returns the Clerk sessions to
    revoke, or None if the link is used up or expired."""
    uid = _use_token(token, "reset")
    if not uid:
        return None
    return end_all_sessions(uid)


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
