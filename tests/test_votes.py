import uuid
from fastapi.testclient import TestClient
from app.main import app


def shop_qr():
    # a fresh, clean merchant QR per test run so earlier votes don't leak in
    vpa = f"shop{uuid.uuid4().hex[:8]}@okaxis"
    return f"upi://pay?pa={vpa}&pn=Sri%20Stationery&cu=INR"


def test_one_tap_reports_raise_the_warning():
    qr = shop_qr()
    with TestClient(app) as c:
        first = c.post("/api/qr/text", json={"text": qr}).json()
        assert first["verdict"]["level"] == "low"
        assert first["community"]["can_report"] and first["community"]["reports"] == 0

        for i, reason in enumerate(["fake", "got_me", "fake"]):
            r = c.post("/api/reports", json={"kind": "qr", "payload": qr, "reason": reason, "voter": f"phone-{i}"})
            assert r.status_code == 200, r.text
            assert r.json()["recorded"] and r.json()["reports"] == i + 1

        # same phone again -> not double counted
        again = c.post("/api/reports", json={"kind": "qr", "payload": qr, "reason": "fake", "voter": "phone-0"}).json()
        assert again["already"] and again["reports"] == 3
        assert again["got_me"] == 1 and again["fake"] == 2

        after = c.post("/api/qr/text", json={"text": qr}).json()
        assert after["community"]["reports"] == 3
        assert any(f["id"] == "REPORTED_BY_USERS" for f in after["findings"])
        assert after["verdict"]["level"] == "danger"


def test_report_validation():
    with TestClient(app) as c:
        assert c.post("/api/reports", json={"kind": "qr", "payload": "x", "reason": "maybe"}).status_code == 422
        assert c.post("/api/reports", json={"kind": "nope", "payload": "x"}).status_code == 422
        # official bank websites can't be reported
        r = c.post("/api/reports", json={"kind": "qr", "payload": "https://www.onlinesbi.sbi/", "reason": "fake", "voter": "v"})
        assert r.status_code == 422
        # unknown APK / screenshot ids
        assert c.post("/api/reports", json={"kind": "apk", "id": "0" * 64, "reason": "fake"}).status_code in (404, 422)


def test_qr_render_png():
    with TestClient(app) as c:
        r = c.get("/api/qr/render.png", params={"data": shop_qr()})
        assert r.status_code == 200 and r.content.startswith(b"\x89PNG")
        assert c.get("/api/qr/render.png", params={"data": "x" * 2000}).status_code in (400, 413, 422)
