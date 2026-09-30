"""Payment screenshot verification: VERIFIED / SUSPICIOUS / UNVERIFIED, extracted fields, checks performed.

Rules under test:
- a clean screenshot is UNVERIFIED (never VERIFIED): PayGuard has no bank/UPI records, and its own SQLite history is
  never treated as proof that a payment happened;
- tampering or inconsistencies => SUSPICIOUS, with the reason;
- VERIFIED only when a trusted transaction source (verify.TRUSTED_SOURCES) confirms the payment.
Synthetic receipts only (no real person's data), drawn with the bundled Poppins font."""
import io
import os

import pytest
import qrcode
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw, ImageFont

from app.main import app
from app.screenshot import verify as V
from app.screenshot.analyzer import HAS_OCR, analyze_screenshot

HERE = os.path.dirname(__file__)
SAMPLES = os.path.join(HERE, "..", "samples", "screenshots")
FONT_DIR = os.path.join(HERE, "fonts")
HAVE_FONT = os.path.exists(os.path.join(FONT_DIR, "Poppins-Regular.ttf"))
needs_ocr = pytest.mark.skipif(not (HAS_OCR and HAVE_FONT), reason="needs an OCR engine and tests/fonts")


def sample(name):
    with open(os.path.join(SAMPLES, name), "rb") as f:
        return f.read()


def font(size, medium=False):
    return ImageFont.truetype(os.path.join(FONT_DIR, "Poppins-Medium.ttf" if medium else "Poppins-Regular.ttf"), size)


def receipt(amount="1,250", vpa="asha.stores@okaxis", utr="741859300059", date="26 Sept 2026", qr=None):
    """A light-mode UPI receipt; `qr` = a upi:// payload drawn onto the image (e.g. a 'pay again' code)."""
    W, H = 1080, 2000
    im = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(im)
    ink, dim = (20, 20, 20), (110, 110, 110)
    d.rectangle((0, 0, W, 260), fill=(20, 110, 40))
    d.text((200, 120), "Payment Successful", font=font(52, True), fill="white")
    d.text((70, 330), "Paid to", font=font(40), fill=dim)
    d.text((70, 390), "ASHA STORES", font=font(48, True), fill=ink)
    d.text((70, 460), vpa, font=font(38), fill=dim)
    d.text((70, 560), f"₹{amount}", font=font(84, True), fill=ink)
    d.text((70, 720), "UPI Transaction ID", font=font(34), fill=dim)
    d.text((70, 770), utr, font=font(42), fill=ink)
    d.text((70, 860), "Debited from XXXXXXXX4821", font=font(38), fill=ink)
    d.text((70, 940), f"06:28 pm on {date}", font=font(38), fill=ink)
    if qr:
        code = qrcode.make(qr, box_size=9, border=3).convert("RGB")
        im.paste(code, (W - code.width - 60, 1100))
        d.text((70, 1150), "Scan to pay again", font=font(36), fill=dim)
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue()


def ids(r):
    return {f["id"] for f in r["findings"]}


def checks(r):
    return {c["id"]: c for c in r["verification"]["checks"]}


# --- units -----------------------------------------------------------------------------------------------------------

def test_upi_ids_are_read_from_text_and_emails_are_ignored():
    text = "Paid to Asha asha.stores @ okaxis support@phonepe.com 98450 12345@ybl"
    assert V.upi_ids(text)[0] == "asha.stores@okaxis"
    assert "support@phonepe.com" not in V.upi_ids(text)


def test_impossible_dates():
    assert V.impossible_dates("on 31 Feb 2026") == ["31 Feb 2026"]
    assert V.impossible_dates("date 30/02/2026") == ["30/02/2026"]
    assert V.impossible_dates("on 29 Feb 2024, 12/31/2026, 26 Sept 2026") == []      # leap day and m/d order are fine


# --- sample screenshots (the demo set) --------------------------------------------------------------------------------

@needs_ocr
@pytest.mark.parametrize("name", ["genuine_receipt.png", "genuine_whatsapp_forwarded.jpg"])
def test_genuine_samples_are_unverified_never_verified(name):
    r = analyze_screenshot(sample(name), name)
    v = r["verification"]
    assert v["status"] == "UNVERIFIED", v["reason"]
    assert v["trusted_source_connected"] is False
    assert "cannot" in v["reason"] and v["fields"]["amount"] and v["fields"]["transaction_id"]
    assert v["fields"]["upi_id"] == "sharma.stationery@okaxis"
    assert checks(r)["trusted_source"]["status"] == "skipped"
    assert all(c["status"] != "fail" for c in v["checks"])


@needs_ocr
@pytest.mark.parametrize("name", ["fake_edited_amount.png", "fake_pending.png", "fake_photoshop.jpg", "fake_redrawn_digits.png"])
def test_fake_samples_are_suspicious_with_reasons(name):
    r = analyze_screenshot(sample(name), name)
    v = r["verification"]
    assert v["status"] == "SUSPICIOUS"
    assert v["issues"] and any(i["category"] in ("tampering", "inconsistency") for i in v["issues"])
    assert any(c["status"] == "fail" for c in v["checks"])
    assert "not treat this screenshot as proof" in v["reason"]


def test_fake_pending_status_check_fails():
    r = analyze_screenshot(sample("fake_pending.png"), "p.png")
    if not r["verification"]["fields"]["status"]:
        pytest.skip("no OCR")
    assert checks(r)["status"]["status"] == "fail"


# --- synthetic receipts: new consistency checks ---------------------------------------------------------------------

@needs_ocr
def test_clean_synthetic_receipt_is_unverified_and_fields_are_extracted():
    r = analyze_screenshot(receipt(), "r.png")
    v = r["verification"]
    assert v["status"] == "UNVERIFIED", v["issues"]
    f = v["fields"]
    assert f["amount"] == 1250 and f["transaction_id"] == "741859300059" and f["upi_id"] == "asha.stores@okaxis"
    assert f["status"] and f["date_time"]
    assert checks(r)["qr"]["status"] == "skipped"


@needs_ocr
def test_qr_matching_the_receipt_passes():
    r = analyze_screenshot(receipt(qr="upi://pay?pa=asha.stores@okaxis&pn=ASHA%20STORES&am=1250&cu=INR"), "r.png")
    assert r["verification"]["fields"]["qr"][0]["payee_vpa"] == "asha.stores@okaxis"
    assert checks(r)["qr"]["status"] == "pass"
    assert r["verification"]["status"] == "UNVERIFIED"


@needs_ocr
def test_qr_with_another_payee_and_amount_is_suspicious():
    r = analyze_screenshot(receipt(qr="upi://pay?pa=quickcash77@ybl&pn=Quick%20Cash&am=9999&cu=INR"), "r.png")
    assert {"QR_PAYEE_MISMATCH", "QR_AMOUNT_MISMATCH"} <= ids(r)
    assert checks(r)["qr"]["status"] == "fail"
    assert r["verification"]["status"] == "SUSPICIOUS"


@needs_ocr
def test_malformed_qr_on_receipt_is_suspicious():
    r = analyze_screenshot(receipt(qr="upi:\\pay?pa=asha.stores@okaxis&am=1250"), "r.png")
    assert "QR_UPI_INVALID" in ids(r) and r["verification"]["status"] == "SUSPICIOUS"


@needs_ocr
def test_impossible_date_is_suspicious():
    r = analyze_screenshot(receipt(date="31 Feb 2026"), "r.png")
    assert "IMPOSSIBLE_DATE" in ids(r)
    assert checks(r)["datetime"]["status"] == "fail" and r["verification"]["status"] == "SUSPICIOUS"


@needs_ocr
def test_expected_amount_mismatch_is_suspicious():
    r = analyze_screenshot(receipt(), "r.png", expected_amount=12500)
    assert checks(r)["amount"]["status"] == "fail" and r["verification"]["status"] == "SUSPICIOUS"


# --- trusted sources: the only way to VERIFIED ------------------------------------------------------------------------

@needs_ocr
def test_verified_only_with_a_trusted_source(monkeypatch):
    img = receipt()
    assert analyze_screenshot(img, "r.png")["verification"]["status"] == "UNVERIFIED"
    seen = {}

    def bank(fields):                                     # stands in for a real, authenticated bank/PSP integration
        seen.update(fields)
        return {"confirmed": fields["transaction_id"] == "741859300059", "source": "Test bank", "detail": "credit found"}

    monkeypatch.setattr(V, "TRUSTED_SOURCES", [bank])
    v = analyze_screenshot(img, "r.png")["verification"]
    assert v["status"] == "VERIFIED" and "Test bank" in v["reason"] and seen["amount"] == 1250
    assert {c["id"]: c for c in v["checks"]}["trusted_source"]["status"] == "pass"

    monkeypatch.setattr(V, "TRUSTED_SOURCES", [lambda f: {"confirmed": False, "source": "Test bank", "detail": "no such credit"}])
    v = analyze_screenshot(img, "r.png")["verification"]
    assert v["status"] == "SUSPICIOUS" and "no such credit" in v["reason"]


@needs_ocr
def test_trusted_source_never_overrides_tampering(monkeypatch):
    monkeypatch.setattr(V, "TRUSTED_SOURCES", [lambda f: {"confirmed": True, "source": "Test bank", "detail": "ok"}])
    assert analyze_screenshot(sample("fake_edited_amount.png"), "f.png")["verification"]["status"] == "SUSPICIOUS"


def test_a_failing_trusted_source_is_ignored(monkeypatch):
    def broken(_):
        raise TimeoutError
    monkeypatch.setattr(V, "TRUSTED_SOURCES", [broken])
    v = analyze_screenshot(sample("genuine_receipt.png"), "g.png")["verification"]
    assert v["status"] != "VERIFIED"


# --- API: upload -> analysis -> result, and PayGuard history --------------------------------------------------------

@needs_ocr
def test_api_returns_verification_and_history_is_not_proof():
    img = receipt(utr="603322118877")
    with TestClient(app) as c:
        r1 = c.post("/api/screenshot", files={"file": ("r.png", img, "image/png")}).json()
        v1 = r1["verification"]
        assert v1["status"] == "UNVERIFIED" and v1["fields"]["transaction_id"] == "603322118877"
        assert {x["id"] for x in v1["checks"]} >= {"metadata", "pixels", "ocr", "fields", "amount", "upi_id", "reference",
                                                   "datetime", "qr", "history", "bank_sms", "trusted_source"}
        assert all(x["name"] and x["status"] in ("pass", "fail", "warn", "skipped") for x in v1["checks"])
        # the same receipt checked again: PayGuard's own record of it must NOT upgrade it to VERIFIED
        again = c.post("/api/screenshot", files={"file": ("r.png", img, "image/png")}).json()["verification"]
        assert again["status"] == "UNVERIFIED"
        # a different receipt re-using that reference number with another amount: SUSPICIOUS via history
        other = c.post("/api/screenshot", files={"file": ("r2.png", receipt(amount="9,800", utr="603322118877"), "image/png")}).json()
        assert other["verification"]["status"] == "SUSPICIOUS"
        assert {x["id"]: x for x in other["verification"]["checks"]}["history"]["status"] == "fail"
        # the stored report keeps the verification block
        stored = c.get(f"/api/screenshot/{r1['id']}").json()
        assert stored["verification"]["status"] == "UNVERIFIED"
