import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.screenshot.analyzer import HAS_OCR, analyze_screenshot

D = os.path.join(os.path.dirname(__file__), "..", "samples", "screenshots")
read = lambda n: open(os.path.join(D, n), "rb").read()
ids = lambda r: {f["id"] for f in r["findings"]}
needs_ocr = pytest.mark.skipif(not HAS_OCR, reason="tesseract not installed")


def test_photoshop_metadata_is_caught_without_ocr():
    r = analyze_screenshot(read("fake_photoshop.jpg"), "x.jpg")
    assert "EDITOR_SOFTWARE" in ids(r) and r["verdict"]["level"] == "danger"


@needs_ocr
@pytest.mark.parametrize("name", ["genuine_receipt.png", "genuine_whatsapp_forwarded.jpg"])
def test_genuine_receipts_are_clean(name):
    r = analyze_screenshot(read(name), name)
    assert r["verdict"]["level"] == "low", [(f["id"], f["evidence"]) for f in r["findings"]]
    d = r["details"]
    assert d["amount"] == 2450 and d["utr"] == "626921345678" and d["status"] == "completed"
    assert "VERIFY_IN_BANK" in ids(r)  # always tells the user a screenshot isn't proof


@needs_ocr
@pytest.mark.parametrize("name,expect", [
    ("fake_edited_amount.png", "PATCHED_BACKGROUND"),
    ("fake_pending.png", "NOT_COMPLETED"),
    ("fake_redrawn_digits.png", "GLYPH_INCONSISTENT"),
])
def test_fakes_are_caught(name, expect):
    r = analyze_screenshot(read(name), name)
    assert expect in ids(r)
    assert r["verdict"]["level"] in ("danger", "suspicious")


@needs_ocr
def test_expected_amount_and_reuse_and_complaint():
    with TestClient(app) as c:
        r = c.post("/api/screenshot", files={"file": ("g.png", read("genuine_receipt.png"))}, data={"expected_amount": "3000"}).json()
        assert "EXPECTED_AMOUNT_MISMATCH" in ids(r)
        # forwarded copy of the same genuine receipt is NOT treated as reuse
        r2 = c.post("/api/screenshot", files={"file": ("g.jpg", read("genuine_whatsapp_forwarded.jpg"))}).json()
        assert "UTR_REUSED" not in ids(r2)
        # an edited copy with the same reference number IS
        r3 = c.post("/api/screenshot", files={"file": ("e.png", read("fake_edited_amount.png"))}).json()
        assert "UTR_REUSED" in ids(r3)
        assert c.get(f"/api/screenshot/{r3['id']}").status_code == 200
        cp = c.post("/api/complaints", json={"source": "screenshot", "sha256": r3["id"], "lost_money": True, "amount": 24500,
                                             "channel": "in_person", "sender_contact": "9876500000"})
        assert cp.status_code == 201, cp.text
        b = cp.json()
        assert b["category"]["subcategory"].startswith("Fake payment proof") and b["checklist"][0]["id"] == "verify"
        assert c.get(f"/api/complaints/{b['ref']}/pdf", params={"token": b["token"]}).content.startswith(b"%PDF")


def test_bad_inputs():
    with TestClient(app) as c:
        assert c.post("/api/screenshot", files={"file": ("x.png", b"not an image")}).status_code == 422
        assert c.post("/api/screenshot", files={"file": ("x.png", read("genuine_receipt.png"))}, data={"expected_amount": "abc"}).status_code == 422
        assert c.get("/api/screenshot/" + "0" * 64).status_code == 404


def test_android_support_endpoints():
    with TestClient(app) as c:
        png = c.get("/api/app/connect.png")
        assert png.status_code == 200 and png.content.startswith(b"\x89PNG")
        assert png.headers["x-payguard-server"].startswith("http")
        h = c.get("/api/health").json()
        assert h["service"] == "payguard" and "android_apk" in h
        page = c.get("/?check=upi%3A%2F%2Fpay%3Fpa%3Da%40ybl")
        assert page.status_code == 200


def test_parse_bank_sms_formats():
    from app.screenshot.analyzer import parse_bank_sms
    a = parse_bank_sms("Rs.10.00 credited to HDFC Bank A/c XX8808 on 26-09-26 by VPA x@ybl (UPI Ref No 741859388059).")
    assert a == {"amount": 10.0, "utr": "741859388059", "direction": "credit", "raw_len": a["raw_len"]}
    b = parse_bank_sms("Dear Customer, INR 2,450.00 credited to your A/c XX4821 on 26/09/26. UPI Ref: 626921345678 -SBI")
    assert b["amount"] == 2450.0 and b["utr"] == "626921345678"
    c = parse_bank_sms("Sent Rs.500 from Kotak Bank AC X1234 to shop@okaxis on 26-09-26. UPI Ref 612345678901")
    assert c["direction"] == "debit" and c["amount"] == 500.0


@needs_ocr
def test_bank_sms_is_decisive():
    ok = analyze_screenshot(read("genuine_receipt.png"), "g.png",
                            bank_sms="Rs.2,450.00 credited to A/c XX4821. UPI Ref No 626921345678")
    assert "BANK_MATCH" in ids(ok) and ok["verdict"]["level"] == "low"
    bad = analyze_screenshot(read("genuine_receipt.png"), "g.png",
                             bank_sms="Rs.245.00 credited to A/c XX4821. UPI Ref No 626921345678")
    assert "BANK_AMOUNT_MISMATCH" in ids(bad) and bad["verdict"]["level"] == "danger"
    other = analyze_screenshot(read("genuine_receipt.png"), "g.png",
                               bank_sms="Rs.2,450.00 credited to A/c XX4821. UPI Ref No 626921999999")
    assert "BANK_DIFFERENT_PAYMENT" in ids(other)


@needs_ocr
def test_promo_and_masked_account_are_not_amounts():
    # "up to ₹10,000" banners and masked account numbers must never be read as the payment amount
    from app.screenshot.analyzer import _extract
    lines = [{"text": "Paid to", "words": [], "h": 20, "cy": 10, "box": (0, 0, 10, 10)},
             {"text": "₹10", "words": [{"text": "₹10", "box": (0, 20, 30, 50), "h": 30}], "h": 30, "cy": 35, "box": (0, 20, 30, 50)},
             {"text": "XXXXXXXXXX8808 ₹10", "words": [{"text": "XXXXXXXXXX8808", "box": (0, 60, 90, 80), "h": 20},
                                                      {"text": "₹10", "box": (100, 60, 130, 80), "h": 20}], "h": 20, "cy": 70, "box": (0, 60, 130, 80)},
             {"text": "Enjoy payments up to ₹10,000.", "words": [{"text": "₹10,000.", "box": (0, 90, 60, 110), "h": 20}], "h": 20, "cy": 100, "box": (0, 90, 60, 110)}]
    ex = _extract(lines)
    assert ex["amount"]["value"] == 10 and ex["amounts_all"] == [10.0]


def test_similar_receipt_matching(tmp_path, monkeypatch):
    from app import store
    store.shot_put({"id": "a" * 64, "details": {"utr": "741859388059", "amount": 10.0,
                    "fingerprint": {"utr": "741859388059", "txn": "T2609261828141973833879", "date": "06:28 pm on 26 Sept 2026", "amount": 10.0}},
                    "file": {"phash": "0" * 256}, "kind": "shot", "verdict": {}, "findings": []})
    hit = store.similar_receipts({"utr": "741859388079", "txn": "T2609261828141973835127", "date": "06:28 pm on 26 Sept 2026", "amount": 100.0}, "b" * 64)
    assert hit and "₹10.00" in hit["evidence"][0]
    # same amount = the same payment, not an edit
    assert store.similar_receipts({"utr": "741859388079", "txn": "T2609261828141973835127", "date": "x", "amount": 10.0}, "b" * 64) is None
    # a different minute is a different payment
    assert store.similar_receipts({"utr": "741859388079", "txn": "T2609261930141973835127", "date": "y", "amount": 100.0}, "b" * 64) is None
