import json
import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from app import store
from app.family import push
from app.main import app

SCAM_QR = "upi://pay?pa=9876501234@ybl&pn=SBI%20Refund%20Dept&am=4999.00&tn=Scan%20to%20receive%20your%20refund"
SAFE_QR = "upi://pay?pa=sharmastores@okaxis&pn=Sharma%20Stores"


@pytest.fixture(autouse=True)
def _reset_family_state():
    with store._lock:
        store._db.execute("DELETE FROM fam_join_fail")
        store._db.commit()
    yield
    with store._lock:
        store._db.execute("DELETE FROM fam_join_fail")
        store._db.commit()


def _device(c, name):
    r = c.post("/api/family/device", json={"name": name, "platform": "web", "lang": "en"})
    assert r.status_code == 201
    return {"x-pg-device": r.json()["token"]}


def _link(c, guardian, parent, parent_name="Papa"):
    inv = c.post("/api/family/invite", json={"name": "Rahul"}, headers=guardian).json()
    assert len(inv["code"]) == 6 and "/family?join=" in inv["join_url"]
    j = c.post("/api/family/join", json={"code": inv["code"], "name": parent_name}, headers=parent)
    assert j.status_code == 200, j.text
    assert j.json()["guardian"]["name"] == "Rahul"
    return inv["code"]


def test_full_family_flow():
    with TestClient(app) as c:
        g, p = _device(c, "Rahul"), _device(c, "")
        code = _link(c, g, p)
        # code is single-use
        assert c.post("/api/family/join", json={"code": code}, headers=_device(c, "x")).status_code == 404
        me_g, me_p = c.get("/api/family/me", headers=g).json(), c.get("/api/family/me", headers=p).json()
        assert me_g["protecting"][0]["name"] == "Papa" and me_p["protected_by"][0]["name"] == "Rahul"

        # parent checks a safe QR: no alert. A scam QR: alert. Same scam again within 10 min: no duplicate.
        c.post("/api/qr/text", json={"text": SAFE_QR}, headers=p)
        r = c.post("/api/qr/text", json={"text": SCAM_QR}, headers=p).json()
        assert r["family_alerted"] == 1
        assert c.post("/api/qr/text", json={"text": SCAM_QR}, headers=p).json()["family_alerted"] == 0
        # scam message
        c.post("/api/message", json={"text": "Your SBI account will be blocked today. Share the OTP sent to you to stop it."}, headers=p)
        al = c.get("/api/family/alerts", headers=g).json()
        types = [a["type"] for a in al["alerts"]]
        assert types.count("checked") == 2 and "linked" in types
        a = next(a for a in al["alerts"] if a["kind"] == "qr")
        assert a["from"]["name"] == "Papa" and a["level"] == "danger"
        assert a["target"] and "•" in a["target"] and "9876501234" not in json.dumps(al)  # masked
        assert "OTP sent to you" not in json.dumps(al)                                     # never the message text
        assert al["unread"] >= 3

        # parent insists on paying: urgent alert
        ev = c.post("/api/family/event", json={"type": "pay_anyway", "kind": "qr", "payload": SCAM_QR}, headers=p).json()
        assert ev["alerted"] == 1
        top = c.get("/api/family/alerts", headers=g).json()["alerts"][0]
        assert top["type"] == "pay_anyway" and "risky UPI" in top["title"]["en"]
        # a safe QR can't be used to raise a false alarm
        assert c.post("/api/family/event", json={"type": "pay_anyway", "kind": "qr", "payload": SAFE_QR}, headers=p).json()["alerted"] == 0

        # mark seen
        c.post("/api/family/alerts/seen", json={"up_to_id": top["id"]}, headers=g)
        assert c.get("/api/family/me", headers=g).json()["unread"] == 0

        # the parent's own phone gets no alerts; unlinking stops everything
        assert c.get("/api/family/alerts", headers=p).json()["alerts"] == []
        assert c.delete(f"/api/family/link/{me_p['device']['id']}", headers=g).status_code == 200
        assert c.post("/api/qr/text", json={"text": SCAM_QR + "&x=1"}, headers=p).json()["family_alerted"] == 0
        assert c.get("/api/family/me", headers=p).json()["protected_by"] == []


def test_auth_and_code_rules():
    with TestClient(app) as c:
        assert c.get("/api/family/me").status_code == 401
        assert c.get("/api/family/me", headers={"x-pg-device": "abc.def"}).status_code == 401
        g = _device(c, "G")
        inv = c.post("/api/family/invite", json={}, headers=g).json()
        assert c.post("/api/family/join", json={"code": inv["code"]}, headers=g).status_code == 422   # own code
        other = _device(c, "O")
        for _ in range(10):
            c.post("/api/family/join", json={"code": "000000"}, headers=other, )
        assert c.post("/api/family/join", json={"code": inv["code"]}, headers=other).status_code == 429  # brute force stopped
        assert c.patch("/api/family/device", json={"phone": "12345"}, headers=g).status_code == 422
        assert c.patch("/api/family/device", json={"phone": "+91 98450 12345"}, headers=g).json()["device"]["phone"] == "9845012345"
        # forget this phone
        assert c.delete("/api/family/device", headers=g).status_code == 200
        assert c.get("/api/family/me", headers=g).status_code == 401


def test_web_push_encryption_roundtrip_and_vapid():
    ua = ec.generate_private_key(ec.SECP256R1())
    p256dh = push.b64u(ua.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))
    auth = push.b64u(b"0123456789abcdef")
    body = push.encrypt(b'{"title":"hi"}', p256dh, auth)
    assert push.decrypt(body, ua, auth) == b'{"title":"hi"}'
    hdr = push.vapid_header("https://fcm.googleapis.com/fcm/send/abc")
    jwt = hdr.split("t=")[1].split(",")[0]
    head, claims, sig = jwt.split(".")
    assert json.loads(push.unb64u(claims))["aud"] == "https://fcm.googleapis.com" and len(push.unb64u(sig)) == 64
    assert len(push.unb64u(push.public_key())) == 65


def test_push_subscription_endpoint():
    with TestClient(app) as c:
        g = _device(c, "G")
        assert c.get("/api/family/push-key").json()["key"]
        bad = c.post("/api/family/push", json={"subscription": {"endpoint": "http://x"}}, headers=g)
        assert bad.status_code == 422
        ua = ec.generate_private_key(ec.SECP256R1())
        sub = {"endpoint": "https://push.example.invalid/sub/1",
               "keys": {"p256dh": push.b64u(ua.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)),
                        "auth": push.b64u(b"0123456789abcdef")}}
        assert c.post("/api/family/push", json={"subscription": sub}, headers=g).status_code == 200
        assert c.get("/api/family/me", headers=g).json()["device"]["push_enabled"]
        assert c.post("/api/family/test", headers=g).status_code == 200
