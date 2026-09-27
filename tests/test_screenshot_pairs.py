"""Regression tests for two real-world misses:
1. an edit that erases a digit from the right-aligned amount beside the payee ("₹10" -> "₹ 0") went unnoticed;
2. when an edited copy was checked first, the genuine receipt checked afterwards was blamed as the "edited copy".
Uses a synthetic dark-mode receipt (no real person's data)."""
import io
import os

import pytest
from PIL import Image, ImageDraw, ImageFont

from app.screenshot.analyzer import HAS_OCR, analyze_screenshot

GF = "/usr/share/fonts/truetype/google-fonts/"
pytestmark = pytest.mark.skipif(not (HAS_OCR and os.path.exists(GF + "Poppins-Regular.ttf")), reason="needs OCR + fonts")

BG, CARD, INK, DIM = (18, 18, 18), (30, 30, 30), (235, 235, 235), (150, 150, 150)


def F(name, size):
    return ImageFont.truetype(GF + name, size)


def receipt(top="10", debit="10", utr="741859300059", txn="T2609261828141973800079", erase_top_digit=False):
    W, H = 1080, 2000
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    d.rectangle((0, 0, W, 260), fill=(20, 110, 40))
    d.text((60, 40), "1:25", font=F("Poppins-Medium.ttf", 40), fill="white")
    d.text((200, 140), "Transaction Successful", font=F("Poppins-Medium.ttf", 48), fill="white")
    d.text((200, 200), "06:28 pm on 26 Sept 2026", font=F("Poppins-Regular.ttf", 36), fill=(220, 240, 220))
    d.rounded_rectangle((30, 300, W - 30, 1150), radius=30, fill=CARD)
    d.text((70, 340), "Paid to", font=F("Poppins-Medium.ttf", 44), fill=INK)
    d.ellipse((70, 440, 180, 550), fill=(40, 160, 230))
    d.text((230, 450), "ASHA_STORES", font=F("Poppins-Regular.ttf", 46), fill=INK)
    d.text((230, 515), "asha.stores@okaxis", font=F("Poppins-Regular.ttf", 38), fill=DIM)
    big = F("Poppins-Medium.ttf", 50)
    tw = d.textlength(f"₹{top}", font=big)
    d.text((W - 80 - tw, 450), f"₹{top}", font=big, fill=INK)
    if erase_top_digit:
        # paint over the first digit only, leaving "₹ 0"
        x_digit = W - 80 - tw + d.textlength("₹", font=big)
        d.rectangle((x_digit, 445, x_digit + d.textlength(top[0], font=big), 520), fill=CARD)
    d.text((70, 640), "Transfer Details", font=F("Poppins-Regular.ttf", 42), fill=INK)
    d.text((70, 720), "PhonePe Transaction ID", font=F("Poppins-Regular.ttf", 34), fill=DIM)
    d.text((70, 770), txn, font=F("Poppins-Regular.ttf", 42), fill=INK)
    d.text((70, 860), "Debited from", font=F("Poppins-Regular.ttf", 34), fill=DIM)
    d.text((230, 920), "XXXXXXXXXX4821", font=F("Poppins-Regular.ttf", 44), fill=INK)
    tw2 = d.textlength(f"₹{debit}", font=big)
    d.text((W - 80 - tw2, 915), f"₹{debit}", font=big, fill=INK)
    d.text((230, 1000), f"UTR: {utr}", font=F("Poppins-Regular.ttf", 40), fill=DIM)
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue()


def ids(r):
    return {f["id"] for f in r["findings"]}


def test_clean_synthetic_receipt_is_low():
    r = analyze_screenshot(receipt(), "genuine.png")
    assert r["verdict"]["level"] == "low", r["findings"]
    assert r["details"]["amount"] == 10


def test_erased_digit_beside_payee_is_caught():
    r = analyze_screenshot(receipt(erase_top_digit=True), "edited.png")
    assert "AMOUNT_ERASED" in ids(r) or "AMOUNT_MISMATCH" in ids(r), r["findings"]
    assert r["verdict"]["level"] == "danger"


def test_different_amounts_on_one_receipt_is_critical():
    r = analyze_screenshot(receipt(top="100", debit="10"), "edited.png")
    assert "AMOUNT_MISMATCH" in ids(r), r["findings"]
    assert r["verdict"]["level"] == "danger"


def _lookups(other_score):
    def seen(utr, sha, ph, amount):
        return None

    def similar(fp, sha):
        return {"evidence": ["Other receipt: ₹100.00"], "other_score": other_score, "other_amount": 100.0}
    return seen, similar


def test_genuine_is_not_blamed_when_the_edited_copy_was_checked_first():
    seen, similar = _lookups(other_score=100)          # the other version showed its own signs of editing
    r = analyze_screenshot(receipt(), "genuine.png", seen_lookup=seen, similar_lookup=similar)
    assert r["verdict"]["level"] == "low"
    assert "ORIGINAL_OF_EDITED" in ids(r) and "EDITED_COPY" not in ids(r)


def test_edited_copy_is_blamed_when_the_genuine_was_checked_first():
    seen, similar = _lookups(other_score=0)
    r = analyze_screenshot(receipt(erase_top_digit=True), "edited.png", seen_lookup=seen, similar_lookup=similar)
    assert r["verdict"]["level"] == "danger" and "EDITED_COPY" in ids(r)


def test_two_clean_versions_are_suspicious_not_danger():
    seen, similar = _lookups(other_score=0)
    r = analyze_screenshot(receipt(), "a.png", seen_lookup=seen, similar_lookup=similar)
    assert "TWO_VERSIONS" in ids(r) and r["verdict"]["level"] == "suspicious"
