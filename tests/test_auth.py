"""Accounts with Clerk sign-in: session tokens are verified by Clerk's SDK, Clerk users are linked to PayGuard
accounts (old ones by verified email), sign-in alerts, devices, history, deletion, and the old password endpoints
are gone. Runs on SQLite by default; set DATABASE_URL=postgresql://... to run the same tests on Postgres.

No network: the tests sign their own session tokens with a throwaway RSA key and give the server the public half
as CLERK_JWT_KEY (Clerk's "networkless" verification), and Clerk's Backend API calls are replaced by fakes."""
import os
import re
import time
import uuid

os.environ["PAYGUARD_MAIL_SYNC"] = "1"   # send emails immediately so the tests can read them

import jwt  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.auth import clerk, mailer  # noqa: E402
from app.main import app  # noqa: E402

UA = {"user-agent": "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36"}
SITE = "http://testserver"
SCAM = "upi://pay?pa=9876501234@ybl&pn=SBI%20Refund%20Dept&am=4999.00&tn=Scan%20to%20receive%20your%20refund"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE = _KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
PUBLIC = _KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

CLERK_USERS: dict[str, dict] = {}        # what "Clerk" knows: clerk user id -> {"email", "verified", "name"}
REVOKED: list[str] = []
DELETED: list[str] = []


@pytest.fixture(autouse=True)
def fake_clerk(monkeypatch):
    monkeypatch.setenv("CLERK_PUBLISHABLE_KEY", "pk_test_dGVzdC5jbGVyay5hY2NvdW50cy5kZXYk")   # test.clerk.accounts.dev$
    monkeypatch.setenv("CLERK_SECRET_KEY", "sk_test_not-a-real-key")
    monkeypatch.setenv("CLERK_JWT_KEY", PUBLIC.replace("\n", "\\n"))    # one line, as hosting dashboards store it
    monkeypatch.delenv("PUBLIC_URL", raising=False)
    monkeypatch.setattr(clerk, "fetch_user", lambda cid: CLERK_USERS.get(cid))
    monkeypatch.setattr(clerk, "revoke_session", lambda sid: REVOKED.append(sid) or True)
    monkeypatch.setattr(clerk, "delete_user", lambda cid: DELETED.append(cid) or True)


def email():
    return f"user{uuid.uuid4().hex[:10]}@example.com"


def clerk_signup(addr, name="", verified=True):
    cid = "user_" + uuid.uuid4().hex[:24]
    CLERK_USERS[cid] = {"email": addr, "verified": verified, "name": name}
    return cid


def token(cid, sid=None, azp=SITE, ttl=60, key=PRIVATE):
    t = int(time.time())
    return jwt.encode({"sub": cid, "sid": sid or "sess_" + uuid.uuid4().hex[:24], "azp": azp, "iss": "https://test.clerk.accounts.dev",
                       "iat": t - 5, "nbf": t - 5, "exp": t + ttl}, key, algorithm="RS256", headers={"kid": "ins_test"})


def client(tok=None):
    # a private-network client address, so X-Forwarded-For is honoured (lets tests pick an IP)
    h = dict(UA)
    if tok:
        h["Authorization"] = "Bearer " + tok
    return TestClient(app, client=("127.0.0.1", 50000), headers=h)


def signed_in(addr=None, name="Asha", **kw):
    """A browser signed in through Clerk: (client, clerk user id, clerk session id, email)."""
    addr = addr or email()
    cid, sid = clerk_signup(addr, name, **kw), "sess_" + uuid.uuid4().hex[:24]
    return client(token(cid, sid)), cid, sid, addr


def mails_to(addr):
    return [m for m in mailer.OUTBOX if m["to"] == addr]


def legacy_account(addr, name="Old Timer"):
    """An account made with the old email + password sign-up, with one saved check."""
    from app.auth.db import db, now
    uid = "legacy" + uuid.uuid4().hex[:8]
    db().exec("INSERT INTO pg_users(id, email, name, pw_hash, lang, created, last_login) VALUES (?,?,?,?,?,?,?)",
              uid, addr, name, "scrypt$x$y", "hi", now() - 86400, now() - 3600)
    db().exec("INSERT INTO pg_history(user_id, created, kind, level, score, title) VALUES (?,?,?,?,?,?)",
              uid, now() - 3600, "qr", "danger", 90, "Old scam check")
    return uid


def test_clerk_session_signs_in_and_creates_the_account():
    c, cid, sid, e = signed_in(name="Asha Rao")
    with c:
        u = c.get("/api/auth/me").json()
        assert u["user"]["email"] == e and u["user"]["name"] == "Asha Rao" and u["user"]["email_verified"] is True
        assert u["stats"] == {"checks": 0, "threats": 0}
        assert set(u["user"]) == {"id", "email", "name", "phone", "lang", "email_verified", "login_alerts", "created", "last_login"}
        assert c.get("/api/auth/me").json()["user"]["id"] == u["user"]["id"]          # same account on the next request
        assert mails_to(e) == []                                                       # no "new sign-in" alert for signing up
    # Clerk's own __session cookie works too (what the browser sends when no header is set)
    with client() as ck:
        ck.cookies.set("__session", token(cid, sid))
        assert ck.get("/api/auth/me").json()["user"]["email"] == e
    with client() as anon:
        assert anon.get("/api/auth/me").json() == {"user": None}


def test_bad_tokens_are_signed_out():
    e = email()
    cid = clerk_signup(e)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    for bad in (token(cid, key=other),                       # not signed by our Clerk instance
                token(cid, ttl=-60),                         # expired
                token(cid, azp="https://evil.example"),      # issued for another site
                "not-a-token", "pg_session_value"):
        with client(bad) as c:
            assert c.get("/api/auth/me").json()["user"] is None, bad[:20]
            assert c.get("/api/me/history").status_code == 401
    with client(token(clerk_signup(email(), verified=False))) as c:      # an email nobody proved they own
        assert c.get("/api/auth/me").json()["user"] is None


def test_existing_account_is_linked_by_verified_email_and_keeps_history():
    e = email()
    uid = legacy_account(e)
    with client(token(clerk_signup(e.upper(), "Someone Else", verified=False))) as c:    # unverified: no way in
        assert c.get("/api/auth/me").json()["user"] is None
    cid = clerk_signup("  " + e.upper() + " ", "Google Name")                           # same email, other spelling
    with client(token(cid)) as c:
        u = c.get("/api/auth/me").json()
        assert u["user"]["id"] == uid and u["user"]["name"] == "Old Timer" and u["user"]["lang"] == "hi"
        assert u["user"]["email_verified"] is True and u["stats"] == {"checks": 1, "threats": 1}
        assert c.get("/api/me/history").json()["history"][0]["title"] == "Old scam check"
    with client(token(clerk_signup(e))) as c:            # a second Clerk user can't take over a linked account
        assert c.get("/api/auth/me").json()["user"] is None
    del CLERK_USERS[cid]                                  # linked for good: Clerk isn't asked again
    with client(token(cid)) as c:
        assert c.get("/api/auth/me").json()["user"]["id"] == uid


def test_old_password_sign_in_is_gone():
    e = email()
    legacy_account(e)
    with client() as c:
        for path, body in (("/api/auth/login", {"email": e, "password": "anything-at-all"}),
                           ("/api/auth/signup", {"name": "X", "email": email(), "password": "Tr1cky-scam-guard"}),
                           ("/api/auth/forgot", {"email": e}),
                           ("/api/auth/reset", {"token": "x", "password": "New-strong-pass-42"}),
                           ("/api/auth/password", {"current": "a", "new": "New-strong-pass-42"})):
            r = c.post(path, json=body)
            assert r.status_code == 410 and "set-cookie" not in r.headers, path
        assert c.get("/api/auth/me").json()["user"] is None
        c.cookies.set("pg_session", "an-old-session-cookie")               # old cookies mean nothing now
        assert c.get("/api/auth/me").json()["user"] is None
        assert c.get("/api/auth/verify?token=x", follow_redirects=False).headers["location"] == "/login"


def test_new_sign_in_sends_alert_with_lockout_link():
    e = email()
    cid = clerk_signup(e)
    s1, s2, s3 = ("sess_" + uuid.uuid4().hex[:24] for _ in range(3))
    with client(token(cid, s1)) as first, client(token(cid, s2)) as second:
        assert first.get("/api/auth/me").json()["user"]                    # account created: no alert
        assert mails_to(e) == []
        assert second.get("/api/auth/me").json()["user"]                   # a new session on another device
        assert second.get("/api/auth/me").json()["user"]
        alerts = mails_to(e)
        assert len(alerts) == 1 and "sign-in" in alerts[0]["subject"].lower()              # once per session
        assert "Chrome on Android" in alerts[0]["text"] and "127.0.x.x" in alerts[0]["text"]
        link = re.search(r"/login\?reset=([\w\-]+)", alerts[0]["text"]).group(1)
        # "wasn't me": one click signs the account out everywhere, here and at Clerk
        with client() as stranger:
            assert stranger.post("/api/auth/lockout", json={"token": "nope"}).status_code == 400
            assert stranger.post("/api/auth/lockout", json={"token": link}).json() == {"ended": 2}
            assert stranger.post("/api/auth/lockout", json={"token": link}).status_code == 400   # single use
        assert {s1, s2} <= set(REVOKED)
        assert first.get("/api/auth/me").json()["user"] is None and second.get("/api/auth/me").json()["user"] is None
        # alerts can be turned off
        with client(token(cid, s3)) as third:
            assert third.get("/api/auth/me").json()["user"] and len(mails_to(e)) == 2
            assert third.patch("/api/auth/me", json={"login_alerts": False}).json()["user"]["login_alerts"] is False
        with client(token(cid)) as fourth:
            assert fourth.get("/api/auth/me").json()["user"]
            assert len(mails_to(e)) == 2


def test_profile_validation():
    c, *_ = signed_in()
    with c:
        assert c.patch("/api/auth/me", json={"phone": "12345"}).status_code == 422
        u = c.patch("/api/auth/me", json={"phone": "+91 98450 12345", "name": "Deepa", "lang": "kn"}).json()["user"]
        assert u["phone"] == "9845012345" and u["name"] == "Deepa" and u["lang"] == "kn"
    with client() as anon:
        assert anon.patch("/api/auth/me", json={"name": "X"}).status_code == 401


def test_csrf_protection():
    c, *_ = signed_in()
    with c:
        # a cross-site HTML form can't post JSON, and a cross-origin fetch carries a foreign Origin
        assert c.post("/api/auth/logout", data={"a": "1"}).status_code == 415
        # the classic CSRF trick: a JSON body sent as text/plain from another site's form
        assert c.post("/api/auth/logout", content='{"a": 1}', headers={"content-type": "text/plain"}).status_code == 415
        assert c.patch("/api/auth/me", json={"name": "Hacked"}, headers={"origin": "https://evil.example"}).status_code == 403
        assert c.post("/api/auth/delete", json={"confirm": "DELETE"}, headers={"origin": "https://evil.example"}).status_code == 403
        assert c.get("/api/auth/me").json()["user"]["name"] == "Asha"


def test_history_sessions_and_sign_out():
    e = email()
    cid = clerk_signup(e)
    s1, s2 = "sess_" + uuid.uuid4().hex[:24], "sess_" + uuid.uuid4().hex[:24]
    with client(token(cid, s1)) as c, client(token(cid, s2)) as phone2:
        c.post("/api/qr/text", json={"text": SCAM})
        c.post("/api/message", json={"text": "Mom, I reached college safely."})
        h = c.get("/api/me/history").json()
        assert [x["kind"] for x in h["history"]] == ["msg", "qr"] and h["stats"] == {"checks": 2, "threats": 1}
        assert h["history"][1]["level"] == "danger" and "•" in (h["history"][1]["label"] or "")
        assert "9876501234" not in str(h)                                   # masked, never the raw UPI ID
        with client() as anon:
            assert anon.post("/api/qr/text", json={"text": SCAM}).json()["verdict"]["level"] == "danger"   # anonymous checks still work
        assert len(c.get("/api/me/history").json()["history"]) == 2
        assert phone2.get("/api/auth/me").json()["user"]
        ss = c.get("/api/auth/sessions").json()["sessions"]
        assert len(ss) == 2 and sum(s["current"] for s in ss) == 1
        other = next(s for s in ss if not s["current"])
        assert c.delete(f"/api/auth/sessions/{other['id']}").status_code == 200
        assert s2 in REVOKED                                                 # ended at Clerk too
        assert phone2.get("/api/auth/me").json()["user"] is None             # and refused here right away
        assert c.delete(f"/api/auth/sessions/{other['id']}").status_code == 404
        assert len(c.get("/api/auth/sessions").json()["sessions"]) == 1
        c.delete("/api/me/history")
        assert c.get("/api/me/history").json()["history"] == []
        assert c.post("/api/auth/logout", json={}).status_code == 200
        assert s1 in REVOKED and c.get("/api/auth/me").json()["user"] is None   # the old token can't be replayed
    with client(token(cid)) as again, client(token(cid)) as tablet:
        assert again.get("/api/auth/me").json()["user"] and tablet.get("/api/auth/me").json()["user"]
        assert again.post("/api/auth/logout-all", json={}).json() == {"ended": 2}
        assert again.get("/api/auth/me").json()["user"] is None and tablet.get("/api/auth/me").json()["user"] is None


def test_delete_account_needs_session_and_confirmation():
    c, cid, sid, e = signed_in()
    with c:
        c.post("/api/qr/text", json={"text": SCAM})
        uid = c.get("/api/auth/me").json()["user"]["id"]
        with client() as anon:
            assert anon.post("/api/auth/delete", json={"confirm": "DELETE"}).status_code == 401
        assert c.post("/api/auth/delete", json={}).status_code == 422
        assert c.post("/api/auth/delete", json={"confirm": "yes"}).status_code == 422
        assert cid not in DELETED and c.get("/api/auth/me").json()["user"]
        assert c.post("/api/auth/delete", json={"confirm": "DELETE"}).json() == {"deleted": True, "clerk_deleted": True}
        assert cid in DELETED                                                 # removed at Clerk through its Backend API
        del CLERK_USERS[cid]
        assert c.get("/api/auth/me").json()["user"] is None
    from app.auth.db import db
    for table, col in (("pg_users", "id"), ("pg_history", "user_id"), ("pg_sessions", "user_id")):
        assert db().one(f"SELECT COUNT(*) FROM {table} WHERE {col}=?", uid)[0] == 0


def test_accounts_off_without_clerk_keys(monkeypatch):
    c, cid, sid, e = signed_in()
    with c:
        assert c.get("/api/auth/config").json() == {"enabled": True, "publishable_key": "pk_test_dGVzdC5jbGVyay5hY2NvdW50cy5kZXYk"}
        assert "sk_test" not in c.get("/api/auth/config").text and c.get("/api/health").json()["sign_in"] == "clerk"
        monkeypatch.delenv("CLERK_SECRET_KEY")
        assert c.get("/api/auth/config").json() == {"enabled": False, "publishable_key": None}
        assert c.get("/api/auth/me").json()["user"] is None
        assert c.post("/api/qr/text", json={"text": SCAM}).json()["verdict"]["level"] == "danger"   # scanners don't care


def test_tokens_only_count_for_this_site(monkeypatch):
    cid = clerk_signup(email())
    local, deployed = token(cid), token(cid, azp="https://payguard.example")
    monkeypatch.setenv("PUBLIC_URL", "https://payguard.example/app")      # a path is ignored: tokens name an origin
    with client(deployed) as c, client(local) as dev:
        assert c.get("/api/auth/me").json()["user"]
        # with PUBLIC_URL set the request's own Host is not trusted any more, not even a forged one
        assert dev.get("/api/auth/me").json()["user"] is None
        evil = token(cid, azp="https://evil.example")
        assert c.get("/api/auth/me", headers={"authorization": "Bearer " + evil, "x-forwarded-host": "evil.example",
                                               "x-forwarded-proto": "https"}).json()["user"] is None
        monkeypatch.setenv("CLERK_AUTHORIZED_PARTIES", "http://localhost:8000, http://testserver/")
        assert dev.get("/api/auth/me").json()["user"] and c.get("/api/auth/me").json()["user"]


def test_env_file_with_multiline_pem(tmp_path, monkeypatch):
    from app import load_env
    f = tmp_path / ".env"
    f.write_text("# local settings\nPG_T_PUB=pk_test_abc\nexport PG_T_QUOTED=\"two words\"\nPG_T_PEM=" + PUBLIC + "PG_T_URL=https://x.example\nPG_T_KEEP=file\n")
    monkeypatch.setenv("PG_T_KEEP", "already set")
    names = load_env(str(f))
    try:
        assert names == ["PG_T_PUB", "PG_T_QUOTED", "PG_T_PEM", "PG_T_URL"]
        assert os.environ["PG_T_PEM"] == PUBLIC.strip() and os.environ["PG_T_URL"] == "https://x.example"
        assert os.environ["PG_T_QUOTED"] == "two words" and os.environ["PG_T_KEEP"] == "already set"
        assert load_env(str(tmp_path / "missing.env")) == [] and load_env("") == []
    finally:
        for n in names:
            os.environ.pop(n, None)


def test_pages_and_health():
    with client() as c:
        assert "landing" in c.get("/").text.lower() or c.get("/").status_code == 200
        assert c.get("/app").status_code == 200 and c.get("/login").status_code == 200 and c.get("/account").status_code == 200
        assert 'id="clerk-box"' in c.get("/login").text and 'type="password"' not in c.get("/login").text
        assert 'id="panel-msg"' in c.get("/?check=upi://pay?pa=a@ybl").text          # old deep links still open the app
        h = c.get("/api/health").json()
        assert h["accounts_db_ok"] is True and h["email"] in ("console", "brevo", "resend", "smtp")


@pytest.mark.skipif(not os.environ.get("DATABASE_URL"), reason="set DATABASE_URL to also test Postgres")
def test_running_on_postgres():
    from app.auth.db import db
    assert db().kind == "postgres"
