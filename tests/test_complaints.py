import os
from fastapi.testclient import TestClient
from app.main import app

S = os.path.join(os.path.dirname(__file__), "..", "samples")
UPI = "upi://pay?pa=9876501234@ybl&pn=SBI%20Refund%20Dept&am=4999.00&tn=Scan%20to%20receive%20your%20refund"


def make(c, **kw):
    body = {"source": "qr", "payload": UPI, "lang": "en", "lost_money": True, "amount": 4999,
            "incident_time": "2026-09-26T21:40:00+05:30", "transaction_ids": ["426912345678"],
            "payment_method": "upi", "victim_bank": "SBI", "channel": "whatsapp", "sender_contact": "+91 98765 11111"}
    body.update(kw)
    return c.post("/api/complaints", json=body)


def test_qr_complaint_full_cycle():
    with TestClient(app) as c:
        r = make(c)
        assert r.status_code == 201, r.text
        b = r.json()
        ref, tok = b["ref"], b["token"]
        fields = {f["key"]: f["value"] for f in b["portal_fields"]}
        assert fields["subcategory"] == "UPI Related Frauds"
        assert fields["txn"] == "426912345678" and fields["paid_to"] == "9876501234@ybl"
        assert len(fields["description"]) >= 200 and "9876501234@ybl" in fields["description"]
        assert all(b["call_script"][l] for l in ("en", "hi", "kn", "ta", "te", "mr", "bn"))
        assert b["checklist"][0]["id"] == "call"
        # evidence was recomputed on the server
        assert b["scan"]["level"] == "danger" and b["scan"]["details"]["payee_vpa"] == "9876501234@ybl"
        pdf = c.get(f"/api/complaints/{ref}/pdf", params={"token": tok})
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
        assert c.get(f"/api/complaints/{ref}", params={"token": "wrong"}).status_code == 404
        assert c.get(f"/api/complaints/{ref}/pdf").status_code == 404
        # the next person scanning the same QR is warned
        q = c.post("/api/qr/text", json={"text": UPI}).json()
        assert q["findings"][0]["id"] in ("REPORTED_BY_USERS", "RECEIVE_MONEY_LURE")
        assert any(f["id"] == "REPORTED_BY_USERS" for f in q["findings"]) and q["community"]["reports"] >= 1
        assert c.get("/api/indicators", params={"kind": "phone", "value": "9876511111"}).json()["reports"] >= 1
        # delete wipes victim data
        assert c.delete(f"/api/complaints/{ref}", params={"token": tok}).status_code == 200
        assert c.get(f"/api/complaints/{ref}", params={"token": tok}).status_code == 404


def test_attempt_only_and_apk():
    with TestClient(app) as c:
        with open(os.path.join(S, "Courier_Delivery_Update.apk"), "rb") as fh:
            sha = c.post("/api/scan", files={"file": ("Courier_Delivery_Update.apk", fh)}).json()["file"]["sha256"]
        r = c.post("/api/complaints", json={"source": "apk", "sha256": sha, "app_installed": True, "channel": "whatsapp"})
        assert r.status_code == 201, r.text
        b = r.json()
        assert not b["incident"]["lost_money"] and b["checklist"][0]["id"] == "device"
        assert any(s["kind"] == "package" for s in b["suspects"])
        assert c.get(f"/api/complaints/{b['ref']}/pdf", params={"token": b["token"]}).content.startswith(b"%PDF")


def test_validation_messages():
    with TestClient(app) as c:
        r = make(c, transaction_ids=["12"])
        assert r.status_code == 422 and "Transaction ID" in r.json()["error"]
        assert make(c, paid_to="not a upi@@").status_code == 422
        assert make(c, incident_time="2099-01-01T00:00:00+05:30").status_code == 422
        assert c.post("/api/complaints", json={"source": "apk", "sha256": "0" * 64}).status_code == 404
        assert c.get("/api/complaints/../../etc", params={"token": "x"}).status_code in (400, 404)
