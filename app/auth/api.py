"""/api/auth/* and /api/me/* endpoints."""
from __future__ import annotations

import os
from typing import Callable

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from . import service as S
from .db import db
from .mailer import provider

router = APIRouter()
_client_ip: Callable[[Request], str] = lambda r: r.client.host if r.client else "?"


def init(client_ip: Callable[[Request], str]) -> None:
    global _client_ip
    _client_ip = client_ip


# ------------------------------------------------------------------ helpers

def base_url(request: Request) -> str:
    env = os.environ.get("PUBLIC_URL", "").rstrip("/")
    if env:
        return env
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    return f"{proto}://{host}"


def _secure(request: Request) -> bool:
    return (request.headers.get("x-forwarded-proto") or request.url.scheme) == "https"


def _set_cookie(resp: Response, request: Request, token: str) -> None:
    resp.set_cookie(S.COOKIE, token, max_age=S.SESSION_DAYS * 86400, httponly=True, secure=_secure(request),
                    samesite="lax", path="/")


def _clear_cookie(resp: Response, request: Request) -> None:
    resp.delete_cookie(S.COOKIE, path="/", secure=_secure(request), httponly=True, samesite="lax")


def _same_site(request: Request) -> None:
    """Blocks cross-site form posts (CSRF) on top of SameSite=Lax cookies: state-changing calls must be JSON and,
    when the browser says where they come from, come from this site."""
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
    """The signed-in user for this request, or None. Safe to call from any endpoint."""
    try:
        return S.session_user(request.cookies.get(S.COOKIE))
    except Exception:
        return None


def need_user(request: Request) -> tuple[dict, str, bool]:
    cur = current(request)
    if not cur:
        raise HTTPException(401, "Please sign in.")
    return cur


def _public(u: dict) -> dict:
    return {k: u[k] for k in ("id", "email", "name", "phone", "lang", "email_verified", "login_alerts", "created", "last_login")}


# ------------------------------------------------------------------ sign up / in / out

class SignupIn(BaseModel):
    name: str
    email: str
    password: str
    lang: str = "en"


class LoginIn(BaseModel):
    email: str
    password: str


@router.post("/api/auth/signup", status_code=201)
async def signup(request: Request, body: SignupIn, response: Response):
    _same_site(request)
    ua = S.describe_device(request.headers.get("user-agent", ""))
    user, token = _run(S.signup, body.name, body.email, body.password, body.lang, _client_ip(request), ua, base_url(request))
    _set_cookie(response, request, token)
    return {"user": _public(user)}


@router.post("/api/auth/login")
async def login(request: Request, body: LoginIn, response: Response):
    _same_site(request)
    ua = S.describe_device(request.headers.get("user-agent", ""))
    user, token = _run(S.login, body.email, body.password, _client_ip(request), ua, base_url(request))
    _set_cookie(response, request, token)
    return {"user": _public(user)}


@router.post("/api/auth/logout")
async def logout(request: Request, response: Response):
    _same_site(request)
    S.end_session(request.cookies.get(S.COOKIE))
    _clear_cookie(response, request)
    return {"ok": True}


@router.post("/api/auth/logout-all")
async def logout_all(request: Request, response: Response):
    _same_site(request)
    u, sid, _ = need_user(request)
    n = S.end_all_sessions(u["id"])
    _clear_cookie(response, request)
    return {"ended": n}


@router.get("/api/auth/me")
async def me(request: Request, response: Response):
    cur = current(request)
    if not cur:
        response.headers["Cache-Control"] = "no-store"
        return {"user": None}
    u, sid, refresh = cur
    if refresh:
        _set_cookie(response, request, request.cookies[S.COOKIE])   # extend the cookie too (sliding sign-in)
    response.headers["Cache-Control"] = "no-store"
    return {"user": _public(u), "stats": S.stats(u["id"])}


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
    password: str


@router.post("/api/auth/delete")
async def delete_me(request: Request, body: DeleteIn, response: Response):
    _same_site(request)
    u, _, _ = need_user(request)
    _run(S.delete_account, u["id"], body.password)
    _clear_cookie(response, request)
    return {"deleted": True}


# ------------------------------------------------------------------ passwords and email

class PasswordIn(BaseModel):
    current: str
    new: str


@router.post("/api/auth/password")
async def change_password(request: Request, body: PasswordIn):
    _same_site(request)
    u, sid, _ = need_user(request)
    _run(S.change_password, u["id"], body.current, body.new, sid, base_url(request))
    return {"ok": True}


class ForgotIn(BaseModel):
    email: str


@router.post("/api/auth/forgot")
async def forgot(request: Request, body: ForgotIn):
    _same_site(request)
    S.forgot_password(body.email, _client_ip(request), base_url(request))
    return {"ok": True, "message": "If that email has a PayGuard account, a reset link is on its way."}


class ResetIn(BaseModel):
    token: str
    password: str


@router.post("/api/auth/reset")
async def reset(request: Request, body: ResetIn, response: Response):
    _same_site(request)
    ua = S.describe_device(request.headers.get("user-agent", ""))
    user, token = _run(S.reset_password, body.token, body.password, _client_ip(request), ua)
    _set_cookie(response, request, token)
    return {"user": _public(user)}


@router.get("/api/auth/verify")
async def verify(token: str = ""):
    ok = S.verify_email(token)
    return RedirectResponse(f"/app?verified={'1' if ok else '0'}", status_code=303)


@router.post("/api/auth/verify/resend")
async def resend_verify(request: Request):
    _same_site(request)
    u, _, _ = need_user(request)
    return {"sent": _run(S.resend_verification, u["id"], base_url(request))}


# ------------------------------------------------------------------ devices and history

@router.get("/api/auth/sessions")
async def sessions(request: Request):
    u, sid, _ = need_user(request)
    return {"sessions": S.list_sessions(u["id"], sid)}


@router.delete("/api/auth/sessions/{sid_prefix}")
async def end_session(request: Request, sid_prefix: str):
    _same_site(request)
    u, _, _ = need_user(request)
    if not S.end_session_by_prefix(u["id"], sid_prefix):
        raise HTTPException(404, "No such session.")
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
    return {"accounts_db": db().kind, "accounts_db_ok": db().ping(), "email": provider()}
