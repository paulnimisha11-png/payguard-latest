"""Clerk (https://clerk.com) does the signing in: Google, email + password or code, verification and recovery.

The browser gets a short-lived session token from ClerkJS and sends it with every API call (Authorization: Bearer,
or Clerk's own __session cookie). Here it is verified with Clerk's official SDK.

Environment
  CLERK_PUBLISHABLE_KEY  pk_test_… / pk_live_…; public, handed to the browser by /api/auth/config
  CLERK_SECRET_KEY       sk_…; server only. Used for Clerk's Backend API (look up a user's email, end sessions,
                         delete a user) and to fetch the signing keys when CLERK_JWT_KEY is not set
  CLERK_JWT_KEY          optional: the instance's PEM public key, so tokens are verified without a network call
  PUBLIC_URL             this site's address. A session token is only accepted if it was issued for it (its `azp`
                         claim), so a token a user got on some other site can't be replayed here. Unset (local
                         development only), the address the request came to is used instead.
  CLERK_AUTHORIZED_PARTIES  optional, comma-separated extra origins to accept, e.g. http://localhost:8000 when
                         PUBLIC_URL points at the deployed site but you are testing on your laptop
Without the first two, accounts are switched off and every scanner still works.
"""
from __future__ import annotations

import logging
import os
from urllib.parse import urlsplit

log = logging.getLogger("payguard.auth")


def publishable_key() -> str:
    return os.environ.get("CLERK_PUBLISHABLE_KEY", "").strip()


def _secret_key() -> str:
    return os.environ.get("CLERK_SECRET_KEY", "").strip()


def _jwt_key() -> str | None:
    # hosting dashboards often store a PEM on one line with literal "\n"
    return os.environ.get("CLERK_JWT_KEY", "").strip().replace("\\n", "\n") or None


def enabled() -> bool:
    return bool(publishable_key() and _secret_key())


def _origin(url: str) -> str:
    """scheme://host[:port] of a URL ("https://x.example/app/" -> "https://x.example"), or "" if it isn't one."""
    u = urlsplit(url.strip())
    return f"{u.scheme}://{u.netloc}" if u.scheme in ("http", "https") and u.netloc else ""


def public_origin() -> str:
    return _origin(os.environ.get("PUBLIC_URL", ""))


def authorized_parties(request_origin: str) -> list[str]:
    """The origins a session token may have been issued for."""
    extra = [_origin(p) for p in os.environ.get("CLERK_AUTHORIZED_PARTIES", "").split(",")]
    return [public_origin() or request_origin] + [p for p in extra if p]


def verify(request, authorized_parties: list[str]) -> tuple[str, str] | None:
    """(clerk user id, clerk session id) when the request carries a valid Clerk session token made for this site."""
    if not enabled():
        return None
    from clerk_backend_api.security import authenticate_request
    from clerk_backend_api.security.types import AuthenticateRequestOptions
    state = authenticate_request(request, AuthenticateRequestOptions(
        secret_key=_secret_key(), jwt_key=_jwt_key(), authorized_parties=authorized_parties,
        accepts_token=["session_token"]))
    if not state.is_signed_in or not state.payload:
        reason = getattr(state.reason, "name", "")
        if reason not in ("SESSION_TOKEN_MISSING", "TOKEN_EXPIRED", "TOKEN_INVALID"):   # configuration, not a stale tab
            log.warning("Clerk session refused: %s (accepted origins: %s)", reason, ", ".join(authorized_parties))
        return None
    sub, sid = state.payload.get("sub"), state.payload.get("sid")
    return (sub, sid) if sub and sid else None


def _api():
    from clerk_backend_api import Clerk
    return Clerk(bearer_auth=_secret_key())


def fetch_user(clerk_user_id: str) -> dict | None:
    """{"email", "verified", "name"} for a Clerk user: their primary email address and whether Clerk verified it."""
    with _api() as c:
        u = c.users.get(user_id=clerk_user_id)
    addrs = u.email_addresses or []
    e = next((a for a in addrs if a.id == u.primary_email_address_id), addrs[0] if addrs else None)
    if not e:
        return None
    status = getattr(e.verification, "status", None)
    name = " ".join(p for p in (u.first_name, u.last_name) if isinstance(p, str) and p)
    return {"email": e.email_address, "verified": getattr(status, "value", status) == "verified", "name": name}


def revoke_session(clerk_sid: str) -> bool:
    try:
        with _api() as c:
            c.sessions.revoke(session_id=clerk_sid)
        return True
    except Exception as e:                 # already ended, or Clerk unreachable: our own record still blocks it
        log.warning("could not end Clerk session: %s", type(e).__name__)
        return False


def delete_user(clerk_user_id: str) -> bool:
    try:
        with _api() as c:
            c.users.delete(user_id=clerk_user_id)
        return True
    except Exception as e:
        log.error("could not delete Clerk user: %s", type(e).__name__)
        return False
