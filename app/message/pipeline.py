"""The layered SMS / message pipeline.

    message (+ sender, time) from the Android app, the web page or a share
      -> text normalisation + URL / phone / UPI extraction          (analyzer._extract, urlextract)
      -> rule analysis (scam scripts, requests, pressure)            (analyzer.analyze_message)
      -> URL analysis, nothing opened                                (urlcheck: link rules + heuristics)
      -> sender analysis                                             (sender)
      -> Scam Memory: reported senders / links / numbers / wording   (memory)
      -> threat intelligence, optional                               (threatintel: Google Safe Browsing)
      -> risk engine, deterministic part                             (risk.combine)
      -> Gemini Flash only if still ambiguous                        (ai)
      -> risk engine, final (after community reports in _after_check) (risk.finalize)

Every layer reports its status in rep["risk"]["layers"], so the UI can say what ran, what was skipped and what was
unavailable. Any layer failing leaves the others working.
"""
from __future__ import annotations

import asyncio
import datetime as dt

from . import ai as ai_layer
from . import memory, risk, sender as sender_mod, threatintel
from .analyzer import analyze_message

LIMITATIONS = [
    "Brand-new scam websites may not be listed anywhere yet, and a link's real destination (redirects) isn't followed.",
    "Carefully worded scams can pass the rules; the AI reading helps but can be wrong or misled.",
    "A sender name or number can be faked (spoofing), and genuine senders can be hacked.",
    "Scam Memory only knows what PayGuard users reported; reports can be mistaken.",
    "No result is a guarantee: if a message asks for money, codes or apps, confirm through an official channel first.",
]


def _received(ts) -> str | None:
    if ts in (None, ""):
        return None
    try:
        if isinstance(ts, (int, float)) or str(ts).isdigit():
            v = float(ts)
            return dt.datetime.fromtimestamp(v / 1000 if v > 1e11 else v, dt.timezone.utc).isoformat()
        return dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00")).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


async def check(text: str, sender: str | None = None, received_at=None, use_ai: bool = True, use_threat_intel: bool = True) -> dict:
    rep = analyze_message(text)                                   # raises ValueError for empty / too short text
    d = rep["details"]
    info, sender_signals = sender_mod.analyze_sender(sender, rep["payload"], d.get("category"))
    d["sender"] = info
    d["received_at"] = _received(received_at)
    rep["sms"] = {"sender_signals": sender_signals}
    layers = {"rules": {"status": "ok", "detail": f"{sum(1 for f in rep['findings'] if f['severity'] != 'info')} rule signal(s)"},
              "urls": {"status": "ok" if d["links"] else "not_needed",
                       "detail": f"{len(d['links'])} link(s) extracted and checked without opening them" if d["links"] else "No links in the message"},
              "sender": {"status": "ok" if info["type"] != "unknown" else "not_provided",
                         "detail": {"dlt_header": "Registered SMS header", "mobile": "Personal mobile number", "international": "Foreign number",
                                    "short_code": "Short code", "email": "E-mail address", "other_name": "Unregistered sender name",
                                    "unknown": "Sender not provided (paste/share doesn't include it)"}[info["type"]]}}

    # Scam Memory (local SQLite) and threat intelligence (network) - the latter only for non-official links
    try:
        mem = memory.lookup(rep)
        layers["memory"] = {"status": "ok", "detail": (f"{len(mem['matches'])} reported indicator(s) found" if mem["matches"]
                                                     else f"No reports for the {mem['checked']} indicator(s) checked")}
    except Exception as e:
        mem, layers["memory"] = None, {"status": "error", "detail": type(e).__name__}
    rep["sms"]["memory"] = mem
    ti_urls = [l["url"] if l["url"].lower().startswith("http") else "http://" + l["url"]
               for l in d["links"] if not l["official"] and not l["whatsapp"]]
    ti = await threatintel.check_urls(ti_urls) if use_threat_intel else {"service": threatintel.SERVICE, "status": "skipped", "matches": []}
    rep["sms"]["threat_intel"] = ti
    layers["threat_intel"] = {"status": ti["status"], "service": ti["service"], "detail": {
        "ok": (f"Listed as dangerous: {len(ti['matches'])} link(s)" if ti["matches"] else f"{ti.get('checked', 0)} link(s) not listed (new sites may not be listed yet)"),
        "not_needed": "No links to look up", "disabled": "Not configured on this server", "skipped": "Turned off for this request",
        "timeout": "Didn't answer in time - result based on PayGuard's own checks", "error": "Unavailable - result based on PayGuard's own checks",
    }.get(ti["status"], ti["status"])}

    pre = risk.combine(rep)
    try:
        ai = await asyncio.wait_for(ai_layer.analyze(rep, pre, allow=use_ai), timeout=30)
    except Exception as e:                                        # the AI must never break a check
        ai = {"status": "error", "reason": type(e).__name__}
    rep["sms"]["ai"] = ai
    layers["ai"] = {"status": ai["status"], "detail": ai.get("reason") if ai["status"] != "ok" else
                    ("Answered from cache (identical message)" if ai.get("cached") else "Gemini Flash read the masked message"),
                    "model": ai.get("model")}
    if ai["status"] in ("timeout", "error"):
        layers["ai"]["detail"] = "AI unavailable - result based on the deterministic checks"
    rep["risk"] = {"layers": layers}
    if ai.get("status") == "ok":
        rep["ai"] = {k: ai[k] for k in ("risk_level", "impersonation", "impersonated_entity", "credential_request", "payment_request",
                                        "social_engineering", "tactics", "reason", "model", "cached") if k in ai}
    rep["limitations"] = LIMITATIONS
    return risk.finalize(rep)
