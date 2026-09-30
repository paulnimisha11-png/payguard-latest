"""Accounts: sign-up, stay signed in, sign-out, login alerts by email, password reset, history, abuse protection.
Runs on SQLite by default; set DATABASE_URL=postgresql://... to run the same tests on Postgres."""
import os
import re
import uuid

os.environ["PAYGUARD_MAIL_SYNC"] = "1"   # send emails immediately so the tests can read them

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.auth import mailer  # noqa: E402
from app.main import app  # noqa: E402

PW = "Tr1cky-scam-guard"
UA = {"user-agent": "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36"}


@pytest.fixture(autouse=True)
def fresh_rate_limits():
    # rate limits are stored in the database; a shared Postgres keeps them between runs
    from app.auth.db import db
    db().exec("DELETE FROM pg_login_attempts")


def email():
    return f"user{uuid.uuid4().hex[:10]}@example.com"


def client():
    # a private-network client address, so X-Forwarded-For is honoured (lets tests pick an IP)
    return TestClient(app, client=("127.0.0.1", 50000), headers=UA)


def mails_to(addr):
    return [m for m in mailer.OUTBOX if m["to"] == addr]


def link(mail, path):
    m = re.search(r"(https?://[^\s\"]+" + re.escape(path) + r"[^\s\"<]+)", mail["text"])
    return m.group(1) if m else None


def test_signup_stays_signed_in_and_logout():
    e = email()
    with client() as c:
        r = c.post("/api/auth/signup", json={"name": "Asha", "email": e.upper(), "password": PW, "lang": "hi"})
        assert r.status_code == 201, r.text
        assert r.json()["user"]["email"] == e and r.json()["user"]["lang"] == "hi"
        ck = r.headers["set-cookie"]
        assert "pg_session=" in ck and "HttpOnly" in ck and "Max-Age=2592000" in ck and "samesite=lax" in ck.lower()
        assert c.get("/api/auth/me").json()["user"]["name"] == "Asha"
        assert c.post("/api/auth/verify/resend", json={}).json()["sent"] is True       # a fresh link on request
        # welcome email with a working confirmation link
        w = mails_to(e)[-1]
        assert "PayGuard" in w["subject"] and PW not in w["text"]
        verify = link(w, "/api/auth/verify?token=")
        v = c.get(verify.split("testserver")[-1] if "testserver" in verify else verify, follow_redirects=False)
        assert v.status_code == 303 and v.headers["location"] == "/app?verified=1"
        assert c.get("/api/auth/me").json()["user"]["email_verified"] is True
        assert c.post("/api/auth/verify/resend", json={}).json()["sent"] is False      # nothing to confirm any more
        assert c.get(verify.split("testserver")[-1], follow_redirects=False).headers["location"] == "/app?verified=0"  # single use
        # a brand-new browser (no cookie) is signed out; signing out ends the server session
        with client() as other:
            assert other.get("/api/auth/me").json()["user"] is None
        token = c.cookies.get("pg_session")
        assert c.post("/api/auth/logout", json={}).status_code == 200
        assert c.get("/api/auth/me").json()["user"] is None
        c.cookies.set("pg_session", token)        # an old cookie can't be replayed after sign-out
        assert c.get("/api/auth/me").json()["user"] is None


def test_login_sends_alert_and_rejects_wrong_password():
    e = email()
    with client() as c:
        c.post("/api/auth/signup", json={"name": "Ravi", "email": e, "password": PW})
        c.post("/api/auth/logout", json={})
        n = len(mails_to(e))
        bad = c.post("/api/auth/login", json={"email": e, "password": "nope-nope-nope"})
        assert bad.status_code == 401 and bad.json()["error"] == "Wrong email or password."
        unknown = c.post("/api/auth/login", json={"email": "ghost" + e, "password": PW})
        assert unknown.status_code == 401 and unknown.json()["error"] == bad.json()["error"]   # no account enumeration
        ok = c.post("/api/auth/login", json={"email": e, "password": PW})
        assert ok.status_code == 200 and ok.json()["user"]["email"] == e
        alert = mails_to(e)[n:][-1]
        assert "sign-in" in alert["subject"].lower()
        assert "Chrome on Android" in alert["text"] and "127.0.x.x" in alert["text"]
        assert "/login?reset=" in alert["text"]
        # alerts can be turned off
        c.patch("/api/auth/me", json={"login_alerts": False})
        c.post("/api/auth/logout", json={})
        m = len(mails_to(e))
        c.post("/api/auth/login", json={"email": e, "password": PW})
        assert len(mails_to(e)) == m


def test_brute_force_is_limited():
    e = email()
    with client() as c:
        c.post("/api/auth/signup", json={"name": "B", "email": e, "password": PW})
        c.post("/api/auth/logout", json={})
        codes = [c.post("/api/auth/login", json={"email": e, "password": f"wrong-{i}-xx"},
                        headers={"x-forwarded-for": "10.9.8.7"}).status_code for i in range(7)]
        assert codes[:6] == [401] * 6 and codes[6] == 429
        # even the right password is refused while locked
        assert c.post("/api/auth/login", json={"email": e, "password": PW}).status_code == 429


def test_forgot_and_reset_password_signs_out_everywhere():
    e = email()
    with client() as a, client() as b:
        a.post("/api/auth/signup", json={"name": "C", "email": e, "password": PW})
        b.post("/api/auth/login", json={"email": e, "password": PW})
        assert b.get("/api/auth/me").json()["user"]
        r = a.post("/api/auth/forgot", json={"email": e})
        same = a.post("/api/auth/forgot", json={"email": "nobody-" + e})
        assert r.json()["message"] == same.json()["message"]
        reset_mail = [m for m in mails_to(e) if "reset" in m["subject"].lower()][-1]
        token = re.search(r"/login\?reset=([\w\-]+)", reset_mail["text"]).group(1)
        assert a.post("/api/auth/reset", json={"token": token, "password": "short"}).status_code == 422
        ok = a.post("/api/auth/reset", json={"token": token, "password": "New-strong-pass-42"})
        assert ok.status_code == 200
        assert b.get("/api/auth/me").json()["user"] is None          # other device signed out
        assert a.get("/api/auth/me").json()["user"]["email"] == e      # this device signed in with the new password
        assert a.post("/api/auth/reset", json={"token": token, "password": "Another-pass-43"}).status_code == 400  # single use
        a.post("/api/auth/logout", json={})
        assert a.post("/api/auth/login", json={"email": e, "password": PW}).status_code == 401
        assert a.post("/api/auth/login", json={"email": e, "password": "New-strong-pass-42"}).status_code == 200


def test_validation_and_duplicates():
    e = email()
    with client() as c:
        assert c.post("/api/auth/signup", json={"name": "D", "email": "not-an-email", "password": PW}).json()["field"] == "email"
        weak = c.post("/api/auth/signup", json={"name": "D", "email": e, "password": "password123"})
        assert weak.status_code == 422 and weak.json()["field"] == "password"
        assert c.post("/api/auth/signup", json={"name": "D", "email": e, "password": PW}).status_code == 201
        assert c.post("/api/auth/signup", json={"name": "D", "email": e.upper(), "password": PW}).status_code == 409
        assert c.patch("/api/auth/me", json={"phone": "12345"}).status_code == 422
        assert c.patch("/api/auth/me", json={"phone": "+91 98450 12345", "name": "Deepa"}).json()["user"]["phone"] == "9845012345"


def test_csrf_protection():
    with client() as c:
        # a cross-site HTML form can't post JSON, and a cross-origin fetch carries a foreign Origin
        assert c.post("/api/auth/login", data={"email": "a@b.co", "password": "x"}).status_code in (415, 422)
        # the classic CSRF trick: a JSON body sent as text/plain from another site's form
        sneaky = c.post("/api/auth/logout", content='{"a": 1}', headers={"content-type": "text/plain"})
        assert sneaky.status_code == 415
        assert c.post("/api/auth/login", json={"email": "a@b.co", "password": "x"},
                      headers={"origin": "https://evil.example"}).status_code == 403


def test_history_sessions_password_change_and_delete():
    e = email()
    scam = "upi://pay?pa=9876501234@ybl&pn=SBI%20Refund%20Dept&am=4999.00&tn=Scan%20to%20receive%20your%20refund"
    with client() as c, client() as phone2:
        c.post("/api/auth/signup", json={"name": "E", "email": e, "password": PW})
        c.post("/api/qr/text", json={"text": scam})
        c.post("/api/message", json={"text": "Mom, I reached college safely."})
        h = c.get("/api/me/history").json()
        assert [x["kind"] for x in h["history"]] == ["msg", "qr"] and h["stats"] == {"checks": 2, "threats": 1}
        assert h["history"][1]["level"] == "danger" and "•" in (h["history"][1]["label"] or "")
        assert "9876501234" not in str(h)                                   # masked, never the raw UPI ID
        with client() as anon:
            anon.post("/api/qr/text", json={"text": scam})                    # anonymous checks still work
        phone2.post("/api/auth/login", json={"email": e, "password": PW})
        ss = c.get("/api/auth/sessions").json()["sessions"]
        assert len(ss) == 2 and sum(s["current"] for s in ss) == 1
        other = next(s for s in ss if not s["current"])
        assert c.delete(f"/api/auth/sessions/{other['id']}").status_code == 200
        assert phone2.get("/api/auth/me").json()["user"] is None
        assert c.post("/api/auth/password", json={"current": "wrong", "new": "Fresh-pass-77"}).status_code == 401
        assert c.post("/api/auth/password", json={"current": PW, "new": "Fresh-pass-77"}).status_code == 200
        assert any("changed" in m["subject"].lower() for m in mails_to(e))
        assert c.get("/api/auth/me").json()["user"]                           # this device stays signed in
        c.delete("/api/me/history")
        assert c.get("/api/me/history").json()["history"] == []
        assert c.post("/api/auth/delete", json={"password": "nope"}).status_code == 401
        assert c.post("/api/auth/delete", json={"password": "Fresh-pass-77"}).status_code == 200
        assert c.get("/api/auth/me").json()["user"] is None
        assert c.post("/api/auth/login", json={"email": e, "password": "Fresh-pass-77"}).status_code == 401


def test_pages_and_health():
    with client() as c:
        assert "landing" in c.get("/").text.lower() or c.get("/").status_code == 200
        assert c.get("/app").status_code == 200 and c.get("/login").status_code == 200 and c.get("/account").status_code == 200
        assert 'id="panel-msg"' in c.get("/?check=upi://pay?pa=a@ybl").text          # old deep links still open the app
        h = c.get("/api/health").json()
        assert h["accounts_db_ok"] is True and h["email"] in ("console", "brevo", "resend", "smtp")


@pytest.mark.skipif(not os.environ.get("DATABASE_URL"), reason="set DATABASE_URL to also test Postgres")
def test_running_on_postgres():
    from app.auth.db import db
    assert db().kind == "postgres"
