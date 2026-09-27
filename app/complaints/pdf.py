"""Evidence PDF to attach to the cybercrime.gov.in complaint (English, A4)."""
from __future__ import annotations

import datetime as dt
import io
from xml.sax.saxutils import escape

from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (Image as RLImage, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)
import base64

INK = colors.HexColor("#161a2c")
DIM = colors.HexColor("#5b6078")
LINE = colors.HexColor("#d9dce8")
BRAND = colors.HexColor("#4f46e5")
SEV = {"critical": colors.HexColor("#c02640"), "high": colors.HexColor("#d9480f"),
       "medium": colors.HexColor("#b7791f"), "low": colors.HexColor("#2f855a"), "info": DIM}

ss = getSampleStyleSheet()
S = {
    "h1": ParagraphStyle("h1", parent=ss["Title"], fontName="Helvetica-Bold", fontSize=18, leading=22, textColor=INK, alignment=TA_LEFT, spaceAfter=2),
    "h2": ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=11.5, leading=14, textColor=BRAND, spaceBefore=10, spaceAfter=4),
    "p": ParagraphStyle("p", parent=ss["BodyText"], fontName="Helvetica", fontSize=9.5, leading=13, textColor=INK),
    "small": ParagraphStyle("small", parent=ss["BodyText"], fontName="Helvetica", fontSize=8, leading=10.5, textColor=DIM),
    "mono": ParagraphStyle("mono", parent=ss["BodyText"], fontName="Courier", fontSize=8, leading=10, textColor=INK),
    "k": ParagraphStyle("k", parent=ss["BodyText"], fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=DIM),
}


def _t(s) -> str:
    """Escape for Paragraph and replace glyphs the core PDF fonts don't have."""
    s = "" if s is None else str(s)
    for a, b in (("₹", "Rs. "), ("→", "->"), ("—", "-"), ("–", "-"), ("“", '"'), ("”", '"'), ("‘", "'"), ("’", "'"), ("…", "...")):
        s = s.replace(a, b)
    s = s.encode("latin-1", "replace").decode("latin-1")
    return escape(s)


def _kv(rows, col=42 * mm):
    data = [[Paragraph(_t(k), S["k"]), Paragraph(_t(v), S["mono"] if mono else S["p"])] for k, v, mono in rows]
    t = Table(data, colWidths=[col, None])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    return t


def _qr(payload: str, size=34 * mm):
    w = QrCodeWidget(payload)
    b = w.getBounds()
    d = Drawing(size, size, transform=[size / (b[2] - b[0]), 0, 0, size / (b[3] - b[1]), 0, 0])
    d.add(w)
    return d


def render(c: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm, bottomMargin=16 * mm,
                            title=f"PayGuard evidence report {c['ref']}", author="PayGuard")
    sc, inc = c["scan"], c["incident"]
    story = []

    head = [[Paragraph("Cyber fraud evidence report", S["h1"]),
             Paragraph(f"<b>Ref {c['ref']}</b><br/>Generated {_t(dt.datetime.fromisoformat(c['created_at']).astimezone(dt.timezone(dt.timedelta(hours=5, minutes=30))).strftime('%d %b %Y %I:%M %p IST'))}", S["small"])]]
    ht = Table(head, colWidths=[None, 55 * mm])
    ht.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "BOTTOM"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                            ("LINEBELOW", (0, 0), (-1, 0), 1.2, INK), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    story += [ht, Spacer(1, 5)]
    story.append(Paragraph(
        "Prepared by the victim using PayGuard, an automated scam-detection tool, to attach to a complaint on "
        "cybercrime.gov.in or to share with the 1930 helpline, the bank or the police. It is supporting evidence, "
        "not a complaint by itself.", S["small"]))

    # Summary
    lv = sc["level"]
    story.append(Paragraph("1. Summary", S["h2"]))
    story.append(_kv([
        ("Complaint category", f"{c['category']['category']} / {c['category']['subcategory']}", False),
        ("Automated verdict", f"{sc['headline']['en']} - risk {sc['score']}/100 ({lv})", False),
        ("Money lost", ("Yes - " + _money(inc.get("amount"))) if inc.get("lost_money") else "No (attempted fraud)", False),
        ("Incident time", _time(inc.get("incident_time")), False),
        ("Received via", {"whatsapp": "WhatsApp", "sms": "SMS", "call": "Phone call", "email": "Email", "social": "Social media",
                          "website": "Website / online ad", "in_person": "In person", "other": "Other"}.get(inc.get("channel") or "", "Not provided"), False),
    ]))

    # Suspects
    story.append(Paragraph("2. Suspect identifiers", S["h2"]))
    story.append(_kv([(s["label"], s["value"], True) for s in c["suspects"]] or [("-", "None extracted", False)], col=55 * mm))

    # Transaction
    if inc.get("lost_money"):
        story.append(Paragraph("3. Transaction details", S["h2"]))
        story.append(_kv([
            ("Amount", _money(inc.get("amount")), False),
            ("Method", (inc.get("payment_method") or "Not provided").upper() if inc.get("payment_method") == "upi" else (inc.get("payment_method") or "Not provided"), False),
            ("Victim's bank / wallet", inc.get("victim_bank") or "Not provided", False),
            ("Transaction ID(s) / UTR", ", ".join(inc.get("transaction_ids") or []) or "Not provided", True),
            ("Beneficiary", inc.get("paid_to") or next((x["value"] for x in c["suspects"] if x["kind"] == "upi"), "Not provided"), True),
        ]))

    n = 4 if inc.get("lost_money") else 3
    # Scanned item
    story.append(Paragraph(f"{n}. What was scanned", S["h2"]))
    if sc["kind"] == "screenshot":
        f, d = sc["file"], sc["details"]
        rows = [("File", f"{f['name']} ({f['format']}, {f['width']}x{f['height']})", False), ("SHA-256", f["sha256"], True),
                ("Payment app shown", d.get("app") or "not identified", False), ("Status shown", d.get("status") or "-", False),
                ("Amount claimed", _money(d.get("amount")) if d.get("amount") else "not read", False),
                ("Reference number shown", d.get("utr") or "none", True), ("Date shown", d.get("date") or "-", False),
                ("Paid to (shown)", d.get("payee") or "-", False)]
        img = None
        if sc.get("annotated", "").startswith("data:image"):
            raw = base64.b64decode(sc["annotated"].split(",", 1)[1])
            img = RLImage(io.BytesIO(raw))
            ratio = img.imageHeight / img.imageWidth
            img.drawWidth, img.drawHeight = 45 * mm, 45 * mm * ratio
            if img.drawHeight > 95 * mm:
                img.drawHeight, img.drawWidth = 95 * mm, 95 * mm / ratio
        qt = Table([[_kv(rows, col=38 * mm), [img, Paragraph("Screenshot with suspicious areas marked", S["small"])] if img else ""]],
                   colWidths=[None, 50 * mm])
        qt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        story.append(qt)
    elif sc["kind"] == "message":
        d = sc["details"]
        rows = [("Message received", sc["payload"][:1500], False)]
        if d.get("category_name"):
            rows.append(("Matches scam pattern", d["category_name"]["en"], False))
        if d.get("asks"):
            rows.append(("What it asked the victim to do", "; ".join(a["label"]["en"] for a in d["asks"]), False))
        for l in d.get("links") or []:
            rows.append(("Link in message", f"{l['url']} ({'official' if l.get('official') else 'NOT official'})", True))
        for u in d.get("upi_ids") or []:
            rows.append(("UPI ID in message", u, True))
        for ph in d.get("phones") or []:
            rows.append(("Phone number in message", ph, True))
        story.append(_kv(rows, col=38 * mm))
    elif sc["kind"] == "qr":
        d = sc["details"]
        rows = [("Content type", (d.get("type") or "").upper(), False), ("Exact QR / link content", sc["payload"], True)]
        if d.get("type") == "upi":
            rows += [("Payee UPI ID", d.get("payee_vpa"), True), ("Payee name shown", d.get("payee_name") or "-", False),
                     ("Amount requested", _money(d.get("amount")) if d.get("amount") else "Not pre-filled", False),
                     ("Note shown", d.get("note") or "-", False),
                     ("Merchant code", d.get("merchant_code") or "none (personal account)", False)]
        elif d.get("type") == "url":
            rows += [("Website", d.get("registered_domain") or d.get("host"), True), ("Full host", d.get("host"), True)]
        qt = Table([[_kv(rows, col=38 * mm), [_qr(sc["payload"]), Paragraph("QR regenerated from the scanned content", S["small"])]]],
                   colWidths=[None, 40 * mm])
        qt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
        story.append(qt)
    else:
        f, a, sg = sc["file"], sc["app"], sc["signing"]
        story.append(_kv([
            ("File name", f["name"], False), ("File size", f"{f['size']:,} bytes", False),
            ("App name / package", f"{a.get('name') or '-'} / {a.get('package')}", True),
            ("SHA-256", f["sha256"], True), ("SHA-1", f["sha1"], True), ("MD5", f["md5"], True),
            ("Signed by", sg.get("subject") or "unsigned", False), ("Certificate SHA-256", sg.get("sha256") or "-", True),
        ], col=38 * mm))

    # Findings
    story.append(Paragraph(f"{n + 1}. Automated findings", S["h2"]))
    rows = []
    for x in sc["findings"]:
        ev = "<br/>".join(_t(e) for e in x.get("evidence", [])[:3])
        rows.append([Paragraph(f"<font color='{SEV.get(x['severity'], DIM).hexval()}'><b>{x['severity'].upper()}</b></font>", S["small"]),
                     [Paragraph(f"<b>{_t(x['title']['en'])}</b>", S["p"]), Paragraph(_t(x["detail"]["en"]), S["small"])]
                     + ([Paragraph(ev, S["mono"])] if ev else [])])
    if rows:
        ft = Table(rows, colWidths=[20 * mm, None])
        ft.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -2), 0.4, LINE),
                                ("LEFTPADDING", (0, 0), (-1, -1), 0), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story.append(ft)

    # Statement
    story.append(KeepTogether([Paragraph(f"{n + 2}. Victim's statement", S["h2"]), Paragraph(_t(c["complaint_text"]), S["p"])]))

    v = c.get("victim") or {}
    if any(v.values()):
        story.append(Paragraph(f"{n + 3}. Complainant", S["h2"]))
        story.append(_kv([("Name", v.get("name") or "-", False), ("Mobile", v.get("mobile") or "-", False), ("Email", v.get("email") or "-", False)]))

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"Evidence fingerprint (SHA-256 of the scan findings, suspects and incident details): <font face='Courier'>{c['evidence_sha256']}</font>. "
        "Findings are produced by static analysis of the file or QR content and indicate known scam patterns; "
        "they are not a forensic certificate. Helpline 1930 · cybercrime.gov.in", S["small"]))

    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(DIM)
        canvas.drawString(16 * mm, 9 * mm, f"PayGuard evidence report {c['ref']}")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {doc_.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def _money(x):
    if x in (None, ""):
        return "Not provided"
    return "Rs. " + f"{float(x):,.2f}"


def _time(s):
    if not s:
        return "Not provided"
    try:
        return dt.datetime.fromisoformat(s).astimezone(dt.timezone(dt.timedelta(hours=5, minutes=30))).strftime("%d %b %Y, %I:%M %p IST")
    except Exception:
        return str(s)
