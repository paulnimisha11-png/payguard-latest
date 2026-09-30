"""Layered SMS pipeline: extraction -> rules -> URLs -> sender -> Scam Memory -> threat intel -> risk engine -> Gemini.

Gemini and Google Safe Browsing are replaced by httpx.MockTransport handlers: no network, no real keys."""
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app import reasoning
from app.main import app
from app.message import ai as sms_ai
from app.message import threatintel
from app.message.sender import classify
from app.message.urlcheck import check_url, typosquat_of
from app.message.urlextract import extract_urls

SCAM = "Dear customer your SBI account will be blocked today. Update KYC at http://sbi-kyc-update.xyz/login and share the OTP you receive."
BANK_ALERT = "Your A/c XX1234 is debited for Rs 500.00 on 30-09-26 by UPI ref 426512345678. Not you? Call 1800 1234 (toll free). -SBI"
OTP = "123456 is your OTP for login to Axis Mobile. Do not share it with anyone. -Axis Bank"
FRIEND = "Hi! Dinner at 8 tonight? I'll book the table at the usual place."
# nothing a rule catches for sure: no link, no OTP request, no fee -> the AI's semantic reading matters here
AMBIGUOUS = "Hello sir, this is Priya from the customer desk. Your recent request needs a quick verification, please reply when free so we can complete it."


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("SAFE_BROWSING_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_KEY", raising=False)
    monkeypatch.setenv("GEMINI_SMS_TIMEOUT", "2")
    yield
    reasoning._transport = None
    threatintel._transport = None


def gemini_reply(obj, seen=None):
    def h(req: httpx.Request):
        if seen is not None:
            seen.append(json.loads(req.content))
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": json.dumps(obj)}]}}]})
    return h


def ask(c, text, **kw):
    r = c.post("/api/message", json={"text": text, **kw})
    assert r.status_code == 200, r.text
    return r.json()


def ids(r):
    return {f["id"] for f in r["risk"]["factors"]}


# ------------------------------------------------------------------ URL extraction (regex + urllib, nothing fetched)

def test_extracts_multiple_urls_with_parts_and_dedupes():
    urls = extract_urls("Pay at https://Pay.example.co.in/a/b?x=1&y=2, see www.test.com. Again: https://pay.example.co.in/a/b?x=1&y=2 and bit.ly/3xYz")
    assert [u["host"] for u in urls] == ["pay.example.co.in", "www.test.com", "bit.ly"]
    u = urls[0]
    assert u["registered_domain"] == "example.co.in" and u["subdomain"] == "pay" and u["path"] == "/a/b"
    assert u["params"] == [{"name": "x", "value": "1"}, {"name": "y", "value": "2"}] and u["scheme"] == "https"


def test_extracts_obfuscated_ip_and_unicode_links():
    got = {u["host"]: u for u in extract_urls("go hxxps://evil-site[.]top/x or 192.168.4.4/login or http://3232235777/ or https://раура1.com/ o​k")}
    assert got["evil-site.top"]["obfuscation"] == ["defanged"]
    assert got["192.168.4.4"]["is_ip"] and got["3232235777"]["is_ip"]
    assert any(h.startswith("xn--") and u["idn"] for h, u in got.items())
    assert extract_urls("Version 1.2.3, pi is 3.14, e.g. this. Rs.500 only") == []
    assert extract_urls("(see bit.ly/abc).")[0]["raw"] == "bit.ly/abc"


def test_no_url():
    assert extract_urls(FRIEND) == []


# ------------------------------------------------------------------ URL heuristics (each is a hint, not proof)

@pytest.mark.parametrize("url,expect", [
    ("http://hdfcbnak.com/login", "TYPOSQUAT_DOMAIN"),
    ("https://amaz0n-gifts.in/claim", "TYPOSQUAT_DOMAIN"),
    ("http://3232235777/pay", "DISGUISED_IP"),
    ("http://pay-now.site:8080/x", "UNUSUAL_PORT"),
    ("https://good.example.com/r?url=https%3A%2F%2Fevil.top%2Fx", "REDIRECT_LINK"),
    ("https://x.example.com/%2e%2e%2f%2e%2e/login", "ENCODED_LINK"),
    ("https://files.example.com/update.exe", "EXECUTABLE_LINK"),
    ("https://secure-kyc-update-verify-account-now.com/", "LONG_DOMAIN"),
])
def test_url_heuristics(url, expect):
    c = check_url(extract_urls(url)[0])
    assert expect in {s["id"] for s in c["extra"]}


def test_official_links_get_no_heuristic_hits():
    for u in ("https://www.onlinesbi.sbi/", "https://www.hdfcbank.com/", "https://www.amazon.in/"):
        c = check_url(extract_urls(u)[0])
        assert c["official"] and not c["extra"]
    assert typosquat_of("hdfcbank.com") is None


# ------------------------------------------------------------------ sender

def test_sender_classification():
    assert classify("VM-SBIINB-S") | {} == classify("VM-SBIINB-S") and classify("VM-SBIINB-S")["org"] == "sbi"
    assert classify("+91 98450 12345")["type"] == "mobile" and classify("+447911123456")["type"] == "international"
    assert classify("SBI-Alert")["type"] == "other_name" and classify(None)["type"] == "unknown"


# ------------------------------------------------------------------ end to end through the API (no AI configured)

def test_legitimate_messages_stay_minimal_and_skip_the_ai():
    with TestClient(app) as c:
        for text, snd in ((BANK_ALERT, "VM-SBIINB-S"), (OTP, "AX-AXISBK"), (FRIEND, "9845012345")):
            r = ask(c, text, sender=snd)
            assert r["risk"]["level"] == "MINIMAL", (text, r["risk"]["factors"])
            assert r["risk"]["layers"]["ai"]["status"] in ("skipped", "disabled")
            assert "not a probability" in r["risk"]["score_note"].lower()


def test_obvious_scam_is_high_decided_without_ai(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    calls = []
    reasoning._transport = httpx.MockTransport(gemini_reply({"risk_level": "LOW", "reason": "x"}, calls))
    with TestClient(app) as c:
        r = ask(c, SCAM, sender="+919876543210")
    assert r["risk"]["level"] == "HIGH" and r["verdict"]["level"] == "danger"
    assert {"ASKS_FOR_CODE", "DANGEROUS_LINK", "ORG_FROM_PERSONAL_NUMBER"} <= ids(r)
    assert r["risk"]["layers"]["ai"]["status"] == "skipped" and calls == []           # no tokens spent
    assert any("OTP" in a for a in r["risk"]["safe_actions"])
    assert r["details"]["links"][0]["host"] == "sbi-kyc-update.xyz"
    assert r["details"]["sender"]["type"] == "mobile"


def test_shortened_and_ip_links_raise_but_do_not_decide():
    with TestClient(app) as c:
        r = ask(c, "hey look at this bit.ly/3xYz12")
        assert "SHORT_LINK" in ids(r) and r["risk"]["level"] in ("MINIMAL", "LOW")
        r = ask(c, "Your parcel is waiting, confirm address at 192.168.4.4/confirm", sender="+447911123456")
        assert r["risk"]["level"] in ("MEDIUM", "HIGH") and "FOREIGN_SENDER" in ids(r)


def test_multiple_urls_all_checked():
    with TestClient(app) as c:
        r = ask(c, "Links: https://www.amazon.in/orders and hxxp://amaz0n-refund[.]top/claim and bit.ly/zz9")
    hosts = [l["host"] for l in r["details"]["links"]]
    assert hosts == ["www.amazon.in", "amaz0n-refund.top", "bit.ly"]
    assert r["details"]["links"][0]["official"] and "OBFUSCATED_LINK" in ids(r)


# ------------------------------------------------------------------ Gemini: only when ambiguous, masked, capped, cached

def test_ambiguous_message_asks_gemini_with_masked_text_and_caps_its_weight(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    seen = []
    reasoning._transport = httpx.MockTransport(gemini_reply(
        {"risk_level": "HIGH", "impersonation": True, "impersonated_entity": "company support", "credential_request": False,
         "payment_request": False, "social_engineering": True, "tactics": ["authority", "urgency"], "reason": "Unsolicited 'verification' from an unnamed desk."}, seen))
    text = AMBIGUOUS + " Call 9876543210 or pay at priya.help@ybl, ref 998877665544."
    with TestClient(app) as c:
        r = ask(c, text)
    assert r["risk"]["layers"]["ai"]["status"] == "ok" and r["ai"]["risk_level"] == "HIGH"
    assert "AI_SEMANTIC" in ids(r)
    assert r["risk"]["score"] <= max(50, r["risk"]["deterministic_score"] + 25)
    if r["risk"]["deterministic_level"] in ("MINIMAL", "LOW"):
        assert r["risk"]["level"] != "HIGH"                                          # AI alone can't make it HIGH
    sent = json.dumps(seen[0])
    assert "9876543210" not in sent and "priya.help@ybl" not in sent and "998877665544" not in sent
    assert "<PHONE>" in sent and "<UPI_ID>" in sent and "<NUMBER>" in sent
    assert "test-key-not-real" not in json.dumps(r)


def test_gemini_low_never_lowers_the_score(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    reasoning._transport = httpx.MockTransport(gemini_reply({"risk_level": "LOW", "impersonation": False, "credential_request": False,
                                                             "payment_request": False, "social_engineering": False, "reason": "Looks fine."}))
    with TestClient(app) as c:
        r = ask(c, "Your electricity will be disconnected tonight, pay the pending bill at http://bescom-bill.top/pay", sender="+919812345678")
    assert r["risk"]["score"] >= r["risk"]["deterministic_score"] and r["risk"]["level"] in ("MEDIUM", "HIGH")


def test_duplicate_sms_uses_the_cache(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    calls = []
    reasoning._transport = httpx.MockTransport(gemini_reply({"risk_level": "MEDIUM", "impersonation": True, "credential_request": False,
                                                             "payment_request": False, "social_engineering": True, "reason": "Vague request."}, calls))
    text = AMBIGUOUS + " Visit help-desk-services.online for details."
    with TestClient(app) as c:
        a, b = ask(c, text), ask(c, text)
    assert len(calls) == 1
    assert a["ai"]["cached"] is False and b["ai"]["cached"] is True and b["risk"]["score"] == a["risk"]["score"]


@pytest.mark.parametrize("failure", ["503", "timeout", "garbage"])
def test_gemini_failure_falls_back_to_deterministic(monkeypatch, failure):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")

    def h(req):
        if failure == "timeout":
            raise httpx.ReadTimeout("slow", request=req)
        if failure == "503":
            return httpx.Response(503, json={"error": {"message": "high demand"}})
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "not json"}]}}]})
    reasoning._transport = httpx.MockTransport(h)
    with TestClient(app) as c:
        r = ask(c, AMBIGUOUS + " Details: support-center-help.site/verify " + failure)
    lay = r["risk"]["layers"]["ai"]
    assert lay["status"] in ("error", "timeout") and "deterministic" in lay["detail"]
    assert "ai" not in r and r["risk"]["score"] == r["risk"]["deterministic_score"]


def test_ai_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    calls = []
    reasoning._transport = httpx.MockTransport(gemini_reply({"risk_level": "HIGH", "reason": "x"}, calls))
    with TestClient(app) as c:
        r = ask(c, AMBIGUOUS, use_ai=False)
    assert r["risk"]["layers"]["ai"]["status"] == "skipped" and calls == []


def test_redaction_keeps_amounts_and_replaces_links():
    links = [{"url": "http://sbi-kyc.top/a?id=9876543210", "host": "sbi-kyc.top"}]
    out = sms_ai.redact("Pay ₹4999 at http://sbi-kyc.top/a?id=9876543210 or call +91 98765 43210, OTP 482913, mail a.b@x.com", links)
    assert "₹4999" in out and "<LINK:sbi-kyc.top>" in out and "<PHONE>" in out and "<NUMBER>" in out and "<EMAIL>" in out
    assert "98765" not in out and "482913" not in out


# ------------------------------------------------------------------ threat intelligence (optional; failures don't matter)

def test_safe_browsing_match_makes_it_high(monkeypatch):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-sb-key")
    sent = []

    def h(req):
        body = json.loads(req.content)
        sent.append(body)
        url = body["threatInfo"]["threatEntries"][0]["url"]
        return httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING", "threat": {"url": url}}]})
    threatintel._transport = httpx.MockTransport(h)
    with TestClient(app) as c:
        r = ask(c, "Hi, the photos from the trip are here: http://trip-photos-share.example.org/album")
    assert "THREAT_INTEL_MATCH" in ids(r) and r["risk"]["level"] == "HIGH"
    assert r["risk"]["layers"]["threat_intel"]["status"] == "ok"
    assert "trip" not in json.dumps(sent[0]["client"]) and "photos from the trip" not in json.dumps(sent)   # only the URL is sent


@pytest.mark.parametrize("failure", ["500", "timeout"])
def test_safe_browsing_failure_is_reported_not_fatal(monkeypatch, failure):
    monkeypatch.setenv("SAFE_BROWSING_API_KEY", "test-sb-key")

    def h(req):
        if failure == "timeout":
            raise httpx.ConnectTimeout("down", request=req)
        return httpx.Response(500, json={})
    threatintel._transport = httpx.MockTransport(h)
    with TestClient(app) as c:
        r = ask(c, f"Update KYC now at http://kyc-{failure}-update.top/x or your account will be blocked", sender="+919812345670")
    assert r["risk"]["layers"]["threat_intel"]["status"] in ("error", "timeout")
    assert "own checks" in r["risk"]["layers"]["threat_intel"]["detail"]
    assert r["risk"]["level"] in ("MEDIUM", "HIGH")


def test_threat_intel_disabled_without_key():
    with TestClient(app) as c:
        r = ask(c, "see http://random-site-example.top/x")
    assert r["risk"]["layers"]["threat_intel"]["status"] == "disabled"


# ------------------------------------------------------------------ Scam Memory

def test_scam_memory_finds_reported_domain_and_sender():
    text = "Your electricity connection will be cut tonight. Pay pending bill: http://power-bill-clear.top/pay"
    with TestClient(app) as c:
        for i in range(3):
            assert c.post("/api/reports", json={"kind": "msg", "payload": text, "reason": "fake", "voter": f"mem-{i}"}).status_code == 200
        r = ask(c, "Dear user, bill overdue. Clear now at http://power-bill-clear.top/pay2", sender="+919812300000")
    mem = r["sms"]["memory"]
    assert any(m["value"] == "power-bill-clear.top" and m["reports"] >= 3 for m in mem["matches"])
    assert "SCAM_MEMORY" in ids(r) and r["risk"]["level"] == "HIGH"
    assert "reported" in r["risk"]["layers"]["memory"]["detail"]
