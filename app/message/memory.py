"""Scam Memory (server side) for messages: have PayGuard users already reported anything in this message?

Looks up every identifier the message contains - UPI IDs, website domains, phone numbers, the sender (mobile number
or SMS header) and the message's wording template - in PayGuard's own records: filed complaints (indicators table)
and one-tap "It's fake" / "It got me" reports (votes), minus anything a moderator cleared as genuine.

The strongest match is already scored by complaints.community.apply_reports (REPORTED_BY_USERS). This module lists
*all* matches for the explanation and adds the sender, which the text alone doesn't contain. Reports are hints from
users (they can be wrong or malicious), which is why disputed indicators are shown but not counted.
The on-device Scam Memory (static/memory.js, the user's own history) is separate and never leaves the device.
"""
from __future__ import annotations

from .. import store
from ..complaints.builder import norm_phone

LABELS = {"upi": "UPI ID", "domain": "website", "phone": "phone number", "msg_template": "message wording",
          "sender_phone": "sender number", "sms_header": "SMS sender header"}


def indicators(rep: dict) -> list[tuple[str, str, str]]:
    d = rep.get("details") or {}
    out = [("upi", u.lower(), "upi") for u in d.get("upi_ids", [])]
    out += [("domain", l["domain"].lower(), "domain") for l in d.get("links", []) if l.get("domain") and not l.get("official") and not l.get("whatsapp")]
    out += [("phone", norm_phone(p), "phone") for p in d.get("phones", [])]
    if d.get("template"):
        out.append(("msg_template", d["template"], "msg_template"))
    s = d.get("sender") or {}
    if s.get("type") == "mobile" and s.get("number"):
        out.append(("phone", norm_phone(s["number"]), "sender_phone"))
    elif s.get("type") == "international" and s.get("number"):
        out.append(("phone", s["number"], "sender_phone"))
    elif s.get("type") == "dlt_header" and s.get("header") and not s.get("org"):
        out.append(("sms_header", s["header"].upper(), "sms_header"))
    seen, uniq = set(), []
    for k, v, lab in out:
        if (k, v) not in seen:
            seen.add((k, v))
            uniq.append((k, v, lab))
    return uniq


def lookup(rep: dict) -> dict:
    matches = []
    inds = indicators(rep)
    for kind, value, lab in inds:
        try:
            if store.moderation_status(kind, value) == "cleared":
                continue
            complaints = store.indicator_count(kind, value)
            v = store.vote_counts(kind, value)
        except Exception:
            continue
        total = complaints + v["total"]
        if total or v["disputes"]:
            shown = value if kind != "msg_template" else "same wording as a reported message"
            matches.append({"kind": lab, "label": LABELS[lab], "value": shown, "reports": total, "complaints": complaints,
                            "lost_money": v["got_me"], "disputes": v["disputes"], "disputed": v["disputes"] * 2 >= max(total, 1)})
    matches.sort(key=lambda m: -m["reports"])
    return {"checked": len(inds), "matches": matches, "found": any(m["reports"] and not m["disputed"] for m in matches)}

