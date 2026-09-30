"""/api/auth/* and /api/me/* endpoints. Signing in itself happens at Clerk (see clerk.py)."""
from __future__ import annotations

import logging
from typing import Callable

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from . import clerk
from . import service as S
from .db import db
from .mailer import provider

router = APIRouter()
log = logging.getLogger("payguard.auth")
_client_ip: Callable[[Request], str] = lambda r: r.client.host if r.client else "?"


def init(client_ip: Callable[[Request], str]) -> None:
    global _client_ip
    _client_ip = client_ip


# ------------------------------------------------------------------ helpers

def _origin(request: Request) -> str:
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    return f"{proto}://{host}"


def base_url(request: Request) -> str:
    return clerk.public_origin() or _origin(request)


def _same_site(request: Request) -> None:
    """Blocks cross-site form posts (CSRF): state-changing calls must be JSON and, when the browser says where they
    come from, come from this site. (Clerk's session token can also arrive as a cookie, so this still matters.)"""
    ctype = request.headers.get("content-type", "")
    if request.method in ("POST", "PATCH", "PUT") and "application/json" not in ctype:
        raise HTTPException(415, "Send JSON.")
    origin = request.headers.get("origin")
    if origin:
        host = request.headers.get("x-forwarded-host") or request.headers.get("host") or ""
        if origin.split("://", 1)[-1].rstrip("/") != host:
            raise HTTPException(403, "Cross-site request blocked.")


def _run(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except S.AuthError as e:
        raise HTTPException(e.status, {"error": e.msg, "field": e.field} if e.field else e.msg)


def current(request: Request) -> tuple[dict, str, bool] | None:
    """The signed-in user for this request as (user, session id, newly created account), or None. Safe to call from
    any endpoint. The Clerk session token must have been issued for this site (its `azp` claim)."""
    try:
        ids = clerk.verify(request, clerk.authorized_parties(_origin(request)))
        if not ids:
            return None
        found = S.clerk_user(ids[0], clerk.fetch_user)
        if not found:
            return None
        u, created = found
        ua = S.describe_device(request.headers.get("user-agent", ""))
        sid = S.clerk_session(u, ids[1], ua, _client_ip(request), base_url(request), alert=not created)
        return (u, sid, created) if sid else None
    except Exception as e:                             # Clerk unreachable, database hiccup: treat as signed out
        log.warning("sign-in check failed: %s", type(e).__name__)
        return None


def need_user(request: Request) -> tuple[dict, str, bool]:
    cur = current(request)
    if not cur:
        raise HTTPException(401, "Please sign in.")
    return cur


def _public(u: dict) -> dict:
    return {k: u[k] for k in ("id", "email", "name", "phone", "lang", "email_verified", "login_alerts", "created", "last_login")}


def _revoke(clerk_sids: list[str]) -> None:
    for sid in clerk_sids:
        clerk.revoke_session(sid)


# ------------------------------------------------------------------ sign in (Clerk) / out

@router.get("/api/auth/config")
async def config():
    """What the browser needs to start ClerkJS. The publishable key is public by design; the secret key never leaves
    the server."""
    return {"enabled": clerk.enabled(), "publishable_key": clerk.publishable_key() if clerk.enabled() else None}


@router.post("/api/auth/signup")
@router.post("/api/auth/login")
@router.post("/api/auth/forgot")
@router.post("/api/auth/reset")
@router.post("/api/auth/password")
async def moved():
    """The old email + password endpoints. Nothing can sign in, sign up or set a password here any more."""
    raise HTTPException(410, "Sign-in has moved. Open /login to sign in with Google or your email.")


@router.get("/api/auth/verify")
async def verify():
    return RedirectResponse("/login", status_code=303)      # old confirmation links: Clerk confirms emails now


@router.post("/api/auth/logout")
async def logout(request: Request):
    _same_site(request)
    cur = current(request)
    if cur:
        _revoke(S.end_session(cur[1]))
    return {"ok": True}


@router.post("/api/auth/logout-all")
async def logout_all(request: Request):
    _same_site(request)
    u, _, _ = need_user(request)
    sids = S.end_all_sessions(u["id"])
    _revoke(sids)
    return {"ended": len(sids)}


class LockIn(BaseModel):
    token: str


@router.post("/api/auth/lockout")
async def lockout(request: Request, body: LockIn):
    """The one-click "wasn't me" link from a sign-in alert email: signs the account out on every device."""
    _same_site(request)
    sids = S.lock_account(body.token)
    if sids is None:
        raise HTTPException(400, "This link has expired or was already used.")
    _revoke(sids)
    return {"ended": len(sids)}


@router.get("/api/auth/me")
async def me(request: Request, response: Response):
    response.headers["Cache-Control"] = "no-store"
    cur = current(request)
    if not cur:
        return {"user": None}
    return {"user": _public(cur[0]), "stats": S.stats(cur[0]["id"])}


class ProfileIn(BaseModel):
    name: str | None = None
    phone: str | None = None
    lang: str | None = None
    login_alerts: bool | None = None


@router.patch("/api/auth/me")
async def update_me(request: Request, body: ProfileIn):
    _same_site(request)
    u, _, _ = need_user(request)
    return {"user": _public(_run(S.update_user, u["id"], body.name, body.phone, body.lang, body.login_alerts))}


class DeleteIn(BaseModel):
    confirm: str


@router.post("/api/auth/delete")
async def delete_me(request: Request, body: DeleteIn):
    """Needs a valid Clerk session and the word DELETE typed by the user. Removes the PayGuard profile, history and
    sessions, then deletes the sign-in identity at Clerk through its Backend API."""
    _same_site(request)
    u, _, _ = need_user(request)
    if body.confirm.strip() != "DELETE":
        raise HTTPException(422, {"error": "Type DELETE to confirm.", "field": "confirm"})
    clerk_id = S.delete_account(u["id"])
    return {"deleted": True, "clerk_deleted": bool(clerk_id) and clerk.delete_user(clerk_id)}


@router.post("/api/auth/verify/resend")
async def resend_verify(request: Request):
    _same_site(request)
    need_user(request)
    return {"sent": False}                                  # Clerk only lets verified emails in


# ------------------------------------------------------------------ devices and history

@router.get("/api/auth/sessions")
async def sessions(request: Request):
    u, sid, _ = need_user(request)
    return {"sessions": S.list_sessions(u["id"], sid)}


@router.delete("/api/auth/sessions/{sid_prefix}")
async def end_session(request: Request, sid_prefix: str):
    _same_site(request)
    u, _, _ = need_user(request)
    sids = S.end_session_by_prefix(u["id"], sid_prefix)
    if sids is None:
        raise HTTPException(404, "No such session.")
    _revoke(sids)
    return {"ok": True}


@router.get("/api/me/history")
async def my_history(request: Request, limit: int = 50):
    u, _, _ = need_user(request)
    return {"history": S.history(u["id"], limit), "stats": S.stats(u["id"])}


@router.delete("/api/me/history")
async def clear_history(request: Request):
    _same_site(request)
    u, _, _ = need_user(request)
    S.clear_history(u["id"])
    return {"ok": True}


def health() -> dict:
    return {"accounts_db": db().kind, "accounts_db_ok": db().ping(), "email": provider(), "sign_in": "clerk" if clerk.enabled() else "off"}
