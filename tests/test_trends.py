import uuid

from fastapi.testclient import TestClient

from app import store, trends
from app.main import app


def _vote(c, payload, voter, reason="fake", ip="203.0.113.10"):
    return c.post("/api/reports", json={"kind": "qr", "payload": payload, "reason": reason, "voter": voter},
                  headers={"x-forwarded-for": ip})


def test_public_listing_needs_several_networks_and_is_masked():
    vpa = f"rf{uuid.uuid4().hex[:8]}@ybl"
    qr = f"upi://pay?pa={vpa}&pn=Refund%20Desk&am=4999&tn=refund"
    with TestClient(app, client=("127.0.0.1", 5000)) as c:
        # three fake "people" from ONE network: counted as reports, but not listed publicly
        for i in range(3):
            assert _vote(c, qr, f"same-net-{i}", ip="198.51.100.7").status_code == 200
        assert trends.lookup(vpa)["reports"] == 3 and not trends.lookup(vpa)["public"]
        # two more networks -> public
        _vote(c, qr, "n2", ip="192.0.2.20")
        _vote(c, qr, "n3", ip="203.0.113.99")
        t = c.get("/api/trends").json()
        shown = [e["display"] for e in t["top"]["upi"]]
        assert any(s.endswith("@ybl") and "•" in s for s in shown), shown
        assert vpa not in str(t)  # never the full UPI ID on the public page
        lk = c.get("/api/lookup", params={"q": vpa}).json()
        assert lk["public"] and lk["reports"] == 5 and lk["kind"] == "upi"


def test_disputes_and_moderation():
    vpa = f"shop{uuid.uuid4().hex[:8]}@okaxis"
    qr = f"upi://pay?pa={vpa}&pn=Kirana%20Store"
    with TestClient(app, client=("127.0.0.1", 5000)) as c:
        for i in range(3):
            _vote(c, qr, f"grudge-{i}", ip=f"10.{i}.0.1")
        assert trends.lookup(vpa)["reports"] == 3
        # customers who know the shop say it's genuine
        for i in range(2):
            r = _vote(c, qr, f"customer-{i}", reason="not_scam", ip=f"172.16.{i}.5")
            assert r.status_code == 200 and r.json()["disputes"] == i + 1
        lk = trends.lookup(vpa)
        assert lk["disputes"] == 2 and not lk["public"]
        scan = c.post("/api/qr/text", json={"text": qr}).json()
        rep = next(f for f in scan["findings"] if f["id"] == "REPORTED_BY_USERS")
        assert rep["severity"] == "info" and scan["verdict"]["level"] == "low"
        # a moderator clears it completely
        store.moderate("upi", vpa, "cleared")
        assert c.post("/api/qr/text", json={"text": qr}).json()["community"]["reports"] == 0
        # admin API needs the token
        assert c.get("/api/admin/review").status_code == 403


def test_single_report_only_asks_for_care():
    vpa = f"one{uuid.uuid4().hex[:8]}@okaxis"
    qr = f"upi://pay?pa={vpa}&pn=Tea%20Stall"
    with TestClient(app, client=("127.0.0.1", 5000)) as c:
        _vote(c, qr, "lonely")
        scan = c.post("/api/qr/text", json={"text": qr}).json()
        f = next(f for f in scan["findings"] if f["id"] == "REPORTED_BY_USERS")
        assert f["severity"] == "medium" and scan["verdict"]["level"] in ("low", "caution")


def test_trends_counts_checks_and_scam_types():
    with TestClient(app, client=("127.0.0.1", 5000)) as c:
        before = trends.build(use_cache=False)
        c.post("/api/message", json={"text": "Dear Consumer, your electricity power will be disconnected tonight. Call officer 9876543210 immediately"})
        c.post("/api/qr/text", json={"text": "upi://pay?pa=9876501234@ybl&pn=SBI%20Refund&am=4999&tn=Scan%20to%20receive%20refund"})
        c.post("/api/message", json={"text": "Mom, I reached college safely."})
        after = trends.build(use_cache=False)
        assert after["totals"]["checks_7d"] == before["totals"]["checks_7d"] + 3
        assert after["totals"]["threats_7d"] == before["totals"]["threats_7d"] + 2
        cats = {t["category"]: t["count"] for t in after["types"]}
        assert cats.get("electricity", 0) >= 1 and cats.get("qr_receive_lure", 0) >= 1
        assert len(after["daily"]) == 14
        for bad in ("", "hello", "12"):
            assert c.get("/api/lookup", params={"q": bad}).status_code == 422
        assert c.get("/api/lookup", params={"q": "+91 98765 43210"}).json()["kind"] == "phone"
        assert c.get("/api/lookup", params={"q": "https://sbi-kyc.xyz/login"}).json()["value"] == "sbi-kyc.xyz"


def test_mask():
    assert trends.mask("upi", "9876501234@ybl") == "987•••••34@ybl"
    assert trends.mask("phone", "9876543210") == "98••••••10"
    assert trends.mask("domain", "sbi-kyc.xyz") == "sbi-kyc[.]xyz"
