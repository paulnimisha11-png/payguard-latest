"""Payment screenshot verification: the extra checks and the final VERIFIED / SUSPICIOUS / UNVERIFIED result.

Called from analyze_screenshot():
  extra_findings(...)  - more consistency checks on the OCR result (UPI ID format, QR / UPI code on the image
                         compared with the receipt, impossible dates). They are ordinary findings, scored like the rest.
  summarize(rep, ...)  - builds rep["verification"]: extracted fields, issues, every check performed, the status and why.

What a screenshot can and cannot prove: pixels and text can show that an image is inconsistent or edited
(-> SUSPICIOUS), but a clean screenshot only shows that it *looks* right. Only the payment network or the receiver's own
bank can confirm that money moved. PayGuard's own database (reused reference numbers, earlier copies of the same receipt)
can reveal fakes, but is never evidence that a payment happened. So:
  VERIFIED   only when a trusted transaction source confirms the payment (see TRUSTED_SOURCES - none is connected);
  SUSPICIOUS when tampering or inconsistency indicators were found;
  UNVERIFIED otherwise: internally consistent, but not independently confirmed.
"""
from __future__ import annotations

import datetime as dt
import re

from ..analyzer.rules import T
from ..qr.analyzer import VPA_RE, analyze_payload, decode_qr_image

# A trusted source is a callable(fields: dict) -> {"confirmed": bool, "source": str, "detail": str} | None backed by a
# real, authenticated record of the transaction (e.g. a bank / payment-gateway API for the receiver's own account).
# None is connected: PayGuard does not have access to bank or UPI records, and nothing here pretends otherwise.
TRUSTED_SOURCES: list = []

TAMPERING = {"EDITOR_SOFTWARE", "EDIT_HISTORY", "GLYPH_INCONSISTENT", "PATCHED_BACKGROUND", "TEXT_STYLE_MISMATCH",
             "ELA_OUTLIER", "AMOUNT_ERASED", "EDITED_COPY"}
INCONSISTENT = {"NOT_COMPLETED", "TXN_TIME_MISMATCH", "FUTURE_DATE", "IMPOSSIBLE_DATE", "AMOUNT_MISMATCH",
                "EXPECTED_AMOUNT_MISMATCH", "UTR_REUSED", "TWO_VERSIONS", "BANK_DIFFERENT_PAYMENT", "BANK_AMOUNT_MISMATCH",
                "NO_UTR", "NOT_A_RECEIPT", "UPI_ID_INVALID", "QR_UPI_INVALID", "QR_AMOUNT_MISMATCH", "QR_PAYEE_MISMATCH"}
SERIOUS = ("medium", "high", "critical")

# check id -> (name, finding ids it covers)
CHECKS = [
    ("metadata", "File metadata (editing software, edit history)", {"EDITOR_SOFTWARE", "EDIT_HISTORY", "CAMERA_PHOTO", "CROPPED"}),
    ("pixels", "Pixel forensics (patched background, mixed fonts, re-drawn digits, compression anomalies)",
     {"PATCHED_BACKGROUND", "TEXT_STYLE_MISMATCH", "ELA_OUTLIER", "GLYPH_INCONSISTENT", "AMOUNT_ERASED"}),
    ("ocr", "Text could be read (OCR)", {"TEXT_UNREADABLE", "LOW_RESOLUTION"}),
    ("fields", "Required fields present (amount, status, reference, date, payee)", {"NO_UTR", "NOT_A_RECEIPT"}),
    ("status", "Payment status is completed", {"NOT_COMPLETED"}),
    ("amount", "Amounts agree (on the receipt, with the expected amount)", {"AMOUNT_MISMATCH", "EXPECTED_AMOUNT_MISMATCH"}),
    ("upi_id", "UPI ID format (name@bank)", {"UPI_ID_INVALID"}),
    ("reference", "Transaction reference format (12-digit UTR)", {"NO_UTR"}),
    ("datetime", "Date and time are possible (not in the future, match the transaction ID)",
     {"FUTURE_DATE", "IMPOSSIBLE_DATE", "TXN_TIME_MISMATCH", "OLD_PAYMENT"}),
    ("qr", "QR / UPI code on the image matches the receipt", {"QR_UPI_INVALID", "QR_AMOUNT_MISMATCH", "QR_PAYEE_MISMATCH"}),
    ("history", "PayGuard history (reused reference numbers, edited copies of earlier receipts)",
     {"UTR_REUSED", "EDITED_COPY", "TWO_VERSIONS", "ORIGINAL_OF_EDITED"}),
    ("bank_sms", "Your bank SMS (if pasted) matches", {"BANK_DIFFERENT_PAYMENT", "BANK_AMOUNT_MISMATCH", "BANK_MATCH", "BANK_SMS_DEBIT"}),
]

_VPA_TEXT = re.compile(r"([A-Za-z0-9][A-Za-z0-9.\-_]{1,255})\s?@\s?([A-Za-z][A-Za-z0-9]{1,63})\b")
_DATE_TXT = re.compile(r"\b(\d{1,2})\s*(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?,?\s*((?:19|20)\d{2})\b", re.I)
_DATE_NUM = re.compile(r"\b(\d{1,2})[/\-.](\d{1,2})[/\-.]((?:19|20)?\d{2})\b")
_MON = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}


def _finding(id_, sev, pts, title, detail, evidence):
    return {"id": id_, "severity": sev, "points": pts, "title": title, "detail": detail, "evidence": [e for e in evidence if e]}


def upi_ids(text: str) -> list[str]:
    """UPI IDs printed on the receipt (OCR sometimes puts a space around the @). Emails are excluded."""
    out = []
    for m in _VPA_TEXT.finditer(text or ""):
        v = f"{m.group(1)}@{m.group(2)}".lower()
        if re.search(r"\.(com|in|org|net|co)$", v) or v in out:
            continue
        out.append(v)
    return out


def impossible_dates(text: str) -> list[str]:
    """Date-like text that no calendar has (31 Feb, 00 Mar, month 13...). analyze_screenshot skips these silently."""
    bad = []
    for m in _DATE_TXT.finditer(text or ""):
        try:
            dt.date(int(m.group(3)), _MON[m.group(2)[:3].lower()], int(m.group(1)))
        except ValueError:
            bad.append(m.group(0))
    for m in _DATE_NUM.finditer(text or ""):
        d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
        y = y + 2000 if y < 100 else y
        try:
            dt.date(y, mo, d)
        except ValueError:
            if not (mo <= 31 and d <= 12):                 # could be month/day order
                bad.append(m.group(0))
            else:
                try:
                    dt.date(y, d, mo)
                except ValueError:
                    bad.append(m.group(0))
    return bad


def qr_payloads(data: bytes) -> list[dict]:
    """UPI payment codes found on the screenshot, parsed with PayGuard's existing QR / UPI parser."""
    try:
        codes = decode_qr_image(data)
    except Exception:
        return []
    out = []
    for c in codes[:3]:
        try:
            d = analyze_payload(c)["details"]
        except Exception:
            continue
        if d.get("type") == "upi":
            out.append({"payload": c[:300], "payee_vpa": (d.get("payee_vpa") or "").lower(), "payee_name": d.get("payee_name") or "",
                        "amount": d.get("amount"), "valid": (d.get("upi_format") or {}).get("valid", True),
                        "problems": (d.get("upi_format") or {}).get("problems", [])})
    return out


def qr_regions(img) -> list[tuple[int, int, int, int]]:
    """Bounding boxes (x0, y0, x1, y1) of QR codes on the image, so OCR noise read from QR modules can be ignored."""
    try:
        import cv2
        import numpy as np
        g = np.asarray(img.convert("L") if hasattr(img, "convert") else img)
        det = cv2.QRCodeDetector()
        ok, pts = det.detectMulti(g)
        if not ok or pts is None:                          # detectMulti misses a single code that detect() finds
            ok, p1 = det.detect(g)
            if not ok or p1 is None:
                return []
            pts = np.asarray(p1).reshape(1, -1, 2)
        out = []
        for p in pts:
            xs, ys = p[:, 0], p[:, 1]
            pad = 0.08 * max(xs.max() - xs.min(), ys.max() - ys.min())
            out.append((int(xs.min() - pad), int(ys.min() - pad), int(xs.max() + pad), int(ys.max() + pad)))
        return out
    except Exception:
        return []


def drop_qr_text(lines: list[dict], img) -> list[dict]:
    """OCR sometimes 'reads' digits in a QR code's squares (e.g. '03'); those are not receipt text."""
    boxes = qr_regions(img)
    if not boxes:
        return lines

    def inside(b):
        cx, cy = (b[0] + b[2]) / 2, (b[1] + b[3]) / 2
        return any(x0 <= cx <= x1 and y0 <= cy <= y1 for x0, y0, x1, y1 in boxes)
    return [ln for ln in lines if not inside(ln["box"])]


def _norm_name(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def extra_findings(ex: dict, data: bytes, text_read: bool) -> tuple[list[dict], dict]:
    """New consistency checks. Returns (findings, extra extracted fields)."""
    F: list[dict] = []
    text = ex.get("text") or ""
    ids = upi_ids(text) if text_read else []
    extra = {"upi_id": ids[0] if ids else None, "upi_ids_all": ids, "qr": qr_payloads(data)}

    bad_ids = [v for v in ids if not VPA_RE.match(v)]
    if bad_ids:
        F.append(_finding("UPI_ID_INVALID", "medium", 15,
                          T("The UPI ID on the receipt is not a valid UPI ID", "रसीद पर UPI ID सही नहीं है", "ರಸೀದಿಯಲ್ಲಿರುವ UPI ID ಸರಿಯಾಗಿಲ್ಲ"),
                          T("Real payment apps print the payee's UPI ID exactly (like name@bank). This one breaks that format, which happens when text is typed in by hand.",
                            "असली पेमेंट ऐप UPI ID बिल्कुल सही छापते हैं (जैसे name@bank)। यह उस रूप में नहीं है, जो हाथ से टाइप करने पर होता है।",
                            "ನಿಜವಾದ ಪಾವತಿ ಆ್ಯಪ್‌ಗಳು UPI ID ಅನ್ನು ನಿಖರವಾಗಿ ಮುದ್ರಿಸುತ್ತವೆ (name@bank). ಇದು ಆ ರೂಪದಲ್ಲಿಲ್ಲ, ಕೈಯಿಂದ ಟೈಪ್ ಮಾಡಿದಾಗ ಹೀಗಾಗುತ್ತದೆ."),
                          [f"UPI ID read: {v}" for v in bad_ids[:3]]))

    bad_dates = impossible_dates(text) if text_read else []
    if bad_dates:
        F.append(_finding("IMPOSSIBLE_DATE", "critical", 45,
                          T("The date on the receipt doesn't exist", "रसीद पर लिखी तारीख़ असल में होती ही नहीं", "ರಸೀದಿಯಲ್ಲಿರುವ ದಿನಾಂಕ ಅಸ್ತಿತ್ವದಲ್ಲೇ ಇಲ್ಲ"),
                          T("A payment app always prints a real calendar date. A date like 31 February only appears when a receipt is edited or made up.",
                            "पेमेंट ऐप हमेशा असली तारीख़ छापता है। 31 फ़रवरी जैसी तारीख़ तभी दिखती है जब रसीद एडिट की गई हो या बनाई गई हो।",
                            "ಪಾವತಿ ಆ್ಯಪ್ ಯಾವಾಗಲೂ ನಿಜವಾದ ದಿನಾಂಕ ಮುದ್ರಿಸುತ್ತದೆ. 31 ಫೆಬ್ರವರಿಯಂತಹ ದಿನಾಂಕ ರಸೀದಿ ಎಡಿಟ್ ಅಥವಾ ಕಲ್ಪಿತವಾದಾಗ ಮಾತ್ರ ಕಾಣುತ್ತದೆ."),
                          [f"Date read: “{d}”" for d in bad_dates[:3]]))

    for q in extra["qr"]:
        if not q["valid"]:
            F.append(_finding("QR_UPI_INVALID", "high", 25,
                              T("The QR code on the image is not a valid UPI code", "तस्वीर का QR कोड सही UPI कोड नहीं है", "ಚಿತ್ರದ QR ಕೋಡ್ ಸರಿಯಾದ UPI ಕೋಡ್ ಅಲ್ಲ"),
                              T("A payment QR must be a correctly formed upi:// link. This one is broken or tampered with.",
                                "पेमेंट QR एक सही upi:// लिंक होना चाहिए। यह टूटा हुआ या छेड़छाड़ किया हुआ है।",
                                "ಪಾವತಿ QR ಸರಿಯಾದ upi:// ಲಿಂಕ್ ಆಗಿರಬೇಕು. ಇದು ಮುರಿದಿದೆ ಅಥವಾ ತಿದ್ದಲಾಗಿದೆ."),
                              [f"Problem: {p}" for p in q["problems"][:3]]))
        amt = ex["amount"]["value"] if ex.get("amount") else None
        if q["amount"] is not None and amt is not None and abs(q["amount"] - amt) > 0.5:
            F.append(_finding("QR_AMOUNT_MISMATCH", "critical", 45,
                              T("The QR code and the receipt show different amounts", "QR कोड और रसीद में अलग-अलग रकम है", "QR ಕೋಡ್ ಮತ್ತು ರಸೀದಿಯಲ್ಲಿ ಬೇರೆ ಬೇರೆ ಮೊತ್ತ ಇದೆ"),
                              T("The payment code embedded in the image asks for a different amount than the receipt claims was paid.",
                                "तस्वीर में लगा पेमेंट कोड उस रकम से अलग रकम माँगता है जो रसीद में चुकाई बताई गई है।",
                                "ಚಿತ್ರದಲ್ಲಿರುವ ಪಾವತಿ ಕೋಡ್ ರಸೀದಿ ಹೇಳುವ ಮೊತ್ತಕ್ಕಿಂತ ಬೇರೆ ಮೊತ್ತ ಕೇಳುತ್ತದೆ."),
                              [f"Receipt: ₹{amt:,.2f}", f"QR code: ₹{q['amount']:,.2f}"]))
        if q["payee_vpa"] and ids and q["payee_vpa"] not in ids:
            F.append(_finding("QR_PAYEE_MISMATCH", "high", 30,
                              T("The QR code pays a different UPI ID than the receipt shows", "QR कोड रसीद से अलग UPI ID को पैसे भेजता है",
                                "QR ಕೋಡ್ ರಸೀದಿಗಿಂತ ಬೇರೆ UPI ID ಗೆ ಹಣ ಕಳುಹಿಸುತ್ತದೆ"),
                              T("The code in the image sends money to someone other than the payee printed on the receipt.",
                                "तस्वीर का कोड रसीद पर छपे पाने वाले के बजाय किसी और को पैसे भेजता है।",
                                "ಚಿತ್ರದ ಕೋಡ್ ರಸೀದಿಯಲ್ಲಿ ಮುದ್ರಿತ ಪಾವತಿದಾರರ ಬದಲು ಬೇರೆಯವರಿಗೆ ಹಣ ಕಳುಹಿಸುತ್ತದೆ."),
                              [f"Receipt UPI ID: {ids[0]}", f"QR code UPI ID: {q['payee_vpa']}"]))
        elif q["payee_vpa"] and not ids and q["payee_name"] and ex.get("payee") and \
                _norm_name(q["payee_name"])[:6] not in _norm_name(ex["payee"]["text"]) and \
                _norm_name(ex["payee"]["text"])[:6] not in _norm_name(q["payee_name"]):
            F.append(_finding("QR_PAYEE_MISMATCH", "high", 30,
                              T("The QR code and the receipt name different payees", "QR कोड और रसीद में पाने वाले अलग हैं", "QR ಕೋಡ್ ಮತ್ತು ರಸೀದಿಯಲ್ಲಿ ಬೇರೆ ಪಾವತಿದಾರರಿದ್ದಾರೆ"),
                              T("The name in the embedded payment code doesn't match the name on the receipt.",
                                "तस्वीर में लगे पेमेंट कोड का नाम रसीद के नाम से मेल नहीं खाता।",
                                "ಚಿತ್ರದ ಪಾವತಿ ಕೋಡ್‌ನ ಹೆಸರು ರಸೀದಿಯ ಹೆಸರಿಗೆ ಹೊಂದುವುದಿಲ್ಲ."),
                              [f"Receipt: {ex['payee']['text']}", f"QR code: {q['payee_name']}"]))
    return F, extra


def _reference_detail(ex: dict) -> str:
    utr = ex.get("utr")
    if utr:
        return f"UTR {utr['utr']} has 12 digits"
    if not ex.get("has_utr_label"):
        return "No reference number label on the receipt"
    runs = [r for r in re.findall(r"(?<!\d)\d{6,20}(?!\d)", re.sub(r"(?<=\d) (?=\d)", "", ex.get("text") or "")) if len(r) != 12]
    return f"Reference label found, but the number has {len(runs[0])} digits (UPI references have 12)" if runs else \
        "Reference label found, but no 12-digit number"


def summarize(rep: dict, ex: dict, extra: dict, ran_ocr: bool, bank_sms_given: bool, history_checked: bool) -> dict:
    d = rep["details"]
    F = rep["findings"]
    by_id: dict[str, list[dict]] = {}
    for f in F:
        by_id.setdefault(f["id"], []).append(f)
    text_ok = ran_ocr and d.get("text_read") and "TEXT_UNREADABLE" not in by_id

    fields = {
        "amount": d.get("amount"), "upi_id": extra.get("upi_id"), "payee_name": d.get("payee"),
        "transaction_id": d.get("utr"), "app_transaction_id": d.get("txn_id"), "date_time": d.get("date"),
        "date_time_iso": d.get("date_iso"), "status": d.get("status"), "app": d.get("app"),
        "qr": extra.get("qr") or None,
    }
    missing = [k for k in ("amount", "status", "transaction_id", "date_time") if fields[k] in (None, "")] if text_ok else []
    if text_ok and not (fields["payee_name"] or fields["upi_id"]):
        missing.append("payee")

    def state(cid, ids, performed=True, detail=""):
        hits = [f for i in ids for f in by_id.get(i, [])]
        bad = [f for f in hits if f["severity"] in SERIOUS]
        warn = [f for f in hits if f["severity"] == "low"]
        if not performed:
            st = "skipped"
        elif bad:
            st = "fail"
        elif warn:
            st = "warn"
        else:
            st = "pass"
        found = "; ".join(f["title"]["en"] for f in (bad or warn) if f["severity"] != "info")
        return {"id": cid, "status": st, "detail": found or detail}

    checks = []
    for cid, name, ids in CHECKS:
        performed, detail = True, ""
        if cid in ("fields", "status", "amount", "upi_id", "reference", "datetime") and not text_ok:
            performed, detail = False, "Skipped: the text on the image could not be read"
        elif cid == "fields":
            detail = "All present" if not missing else "Missing: " + ", ".join(m.replace("_", " ") for m in missing)
        elif cid == "status":
            detail = f"Status reads “{d.get('status')}”" if d.get("status") else "No status word found"
        elif cid == "amount":
            detail = "One amount throughout" + (f", matches the expected ₹{d['expected_amount']:,.2f}" if d.get("expected_amount") else "")
        elif cid == "upi_id":
            performed = bool(extra.get("upi_ids_all"))
            detail = f"{extra['upi_id']} is a valid UPI ID" if performed else "Skipped: no UPI ID printed on the receipt"
        elif cid == "reference":
            detail = _reference_detail(ex)
        elif cid == "datetime":
            detail = f"{d['date']} is a real, past date" if d.get("date") else "No date read"
        elif cid == "qr":
            performed = bool(extra.get("qr"))
            detail = "The code's payee and amount agree with the receipt" if performed else "Skipped: no QR / UPI code on the image"
        elif cid == "history":
            performed = history_checked
            detail = ("No reuse of this reference number or earlier edited copies in PayGuard's records "
                      "(this can reveal fakes, but is never proof that a payment happened)") if performed else "Skipped: no reference number to look up"
        elif cid == "bank_sms":
            performed = bank_sms_given
            detail = ("Matches your pasted bank SMS (PayGuard cannot authenticate SMS text)" if performed
                      else "Skipped: no bank SMS pasted")
        elif cid == "metadata":
            detail = "No editing software or edit history in the file"
        elif cid == "pixels":
            detail = "No patched areas, mixed fonts, re-drawn digits or compression anomalies found"
        elif cid == "ocr":
            performed = ran_ocr
            detail = "Text read" if text_ok else ("Skipped: no OCR engine on this server" if not ran_ocr else "")
        c = state(cid, ids, performed, detail)
        c["name"] = name
        if cid == "fields" and missing and c["status"] == "pass":
            c["status"] = "warn"
        checks.append(c)

    trusted = None
    for src in TRUSTED_SOURCES:
        try:
            trusted = src(fields)
        except Exception:
            trusted = None
        if trusted:
            break
    checks.append({"id": "trusted_source", "name": "Confirmed by a trusted transaction source (bank / UPI records)",
                   "status": ("pass" if trusted and trusted.get("confirmed") else "fail") if trusted else "skipped",
                   "detail": trusted.get("detail", "") if trusted else
                   "Not available: PayGuard is not connected to any bank or UPI records, so it cannot see whether money actually moved"})

    issues = [{"id": f["id"], "severity": f["severity"], "title": f["title"], "category": "tampering" if f["id"] in TAMPERING else
               "inconsistency" if f["id"] in INCONSISTENT else "quality"}
              for f in F if f["severity"] != "info"]
    serious = [i for i in issues if i["category"] in ("tampering", "inconsistency") and i["severity"] in SERIOUS]

    if serious or rep["verdict"]["level"] in ("suspicious", "danger"):
        status = "SUSPICIOUS"
        top = serious[0]["title"]["en"] if serious else rep["verdict"]["headline"]["en"]
        reason = (f"{len(serious)} sign{'s' if len(serious) != 1 else ''} of tampering or inconsistency found. Most important: {top}. "
                  "Do not treat this screenshot as proof of payment.")
    elif trusted and not trusted.get("confirmed"):
        status = "SUSPICIOUS"
        reason = (f"{trusted.get('source', 'The trusted transaction source')} could not confirm this payment: "
                  f"{trusted.get('detail', '')}".strip() + " Do not treat this screenshot as proof of payment.")
    elif trusted and trusted.get("confirmed"):
        status = "VERIFIED"
        reason = f"Confirmed by {trusted.get('source', 'a trusted transaction source')}: {trusted.get('detail', '')}".strip()
    else:
        status = "UNVERIFIED"
        if not text_ok:
            reason = ("PayGuard couldn't read the text on this image, so it could only check the file and pixels. No signs of editing "
                      "were found, but that is not confirmation. Check your own bank or UPI app.")
        else:
            reason = ("The screenshot is internally consistent and no signs of editing were found, but a screenshot cannot prove a payment "
                      "and PayGuard cannot see bank records. Confirm the money in your own bank or UPI app"
                      + (f" using reference {fields['transaction_id']}." if fields["transaction_id"] else "."))
    return {"status": status, "reason": reason, "fields": fields, "missing_fields": missing, "issues": issues, "checks": checks,
            "trusted_source_connected": bool(TRUSTED_SOURCES),
            "note": "Only the payment network or your own bank can confirm a payment. PayGuard's records are used to spot fakes, never as proof."}
