"""Risk engine for messages: combines every layer into one explainable result.

Layers and how much each may contribute (points, not probabilities):
  rules         the existing message rules (asks for OTP/PIN, remote-access app, APK, fee, threat, urgency, scam script,
                dangerous/unofficial link...). Full points; a critical finding sets a floor of 70 (HIGH).
  url           heuristics on the extracted links (typosquat, disguised IP, odd port, redirect, encoding, obfuscation,
                long domain) plus the existing link rules when they did not already produce a link finding. Capped at 35:
                a strange-looking link alone is never proof.
  sender        sender format vs. what the message claims (personal number posing as a bank, foreign number...).
                Capped at 25: senders can be spoofed and friends use mobile numbers.
  memory        PayGuard's Scam Memory: the sender, links, numbers, UPI IDs or wording were reported before
                (1 report = 15, 2 = 35, 3+ = 50/critical). Disputed indicators count 0.
  threat_intel  Google Safe Browsing listed a link: critical, floor 70.
  ai            Gemini's reading. HIGH = +20 (+5 with a credential/payment request), MEDIUM = +10, LOW = 0. The AI never
                lowers the score, and on its own it can lift a message at most to MEDIUM (50): it can be wrong or be
                talked into things by the message text.

Score = sum of points (max 100). Levels use the existing message thresholds: >=70 HIGH, >=35 MEDIUM, >=15 LOW (be
careful), else no scam signs found. The score is a count of weighted evidence, NOT a calibrated probability.
"""
from __future__ import annotations

from ..analyzer.rules import SEVERITY_ORDER, T
from .analyzer import MSG_VERDICTS

URL_CAP, SENDER_CAP, AI_ALONE_CAP = 35, 25, 50
RISK_LABEL = {"danger": "HIGH", "suspicious": "MEDIUM", "caution": "LOW", "low": "MINIMAL"}
MEMORY_IDS = {"REPORTED_BY_USERS", "UPI_MUTATION", "SENDER_REPORTED"}
SCORE_NOTE = "Risk points from weighted evidence (0-100). Not a probability."


def _factor(id_, title, sev, pts, layer, evidence=None):
    return {"id": id_, "title": title, "severity": sev, "points": pts, "layer": layer, "evidence": evidence or []}


def _capped(factors: list[dict], cap: int) -> list[dict]:
    left = cap
    for f in sorted(factors, key=lambda x: -x["points"]):
        f["points"] = max(0, min(f["points"], left))
        left -= f["points"]
    return factors


def url_factors(rep: dict) -> list[dict]:
    d = rep.get("details") or {}
    have_link_finding = any(f["id"] in ("DANGEROUS_LINK", "UNOFFICIAL_LINK", "APK_LINK") for f in rep.get("findings") or [])
    seen, out = set(), []
    for l in d.get("links") or []:
        for h in l.get("heuristics") or []:
            if h["id"] not in seen:
                seen.add(h["id"])
                out.append(_factor(h["id"], h["title"], h["severity"], h["points"], "url", [f"{l['host']}"]))
        if l.get("shortener") and "SHORT_LINK" not in seen and not have_link_finding:
            seen.add("SHORT_LINK")
            out.append(_factor("SHORT_LINK", T("Shortened link hides where it goes", "छोटा किया गया लिंक असली पता छिपाता है",
                                                "ಚಿಕ್ಕದಾಗಿಸಿದ ಲಿಂಕ್ ನಿಜವಾದ ವಿಳಾಸ ಮರೆಮಾಡುತ್ತದೆ"), "low", 8, "url", [l["host"]]))
        if l.get("is_ip") and "IP_LINK" not in seen and not have_link_finding:
            seen.add("IP_LINK")
            out.append(_factor("IP_LINK", T("Link points to a bare server address (IP)", "लिंक सीधे सर्वर पते (IP) पर जाता है",
                                             "ಲಿಂಕ್ ನೇರವಾಗಿ ಸರ್ವರ್ ವಿಳಾಸಕ್ಕೆ (IP) ಹೋಗುತ್ತದೆ"), "medium", 15, "url", [l["host"]]))
    return _capped(out, URL_CAP)


def memory_factors(mem: dict | None) -> list[dict]:
    if not mem:
        return []
    best = next((m for m in mem.get("matches") or [] if m["reports"] and not m["disputed"]), None)
    if not best:
        return []
    n = best["reports"]
    sev, pts = ("critical", 50) if n >= 3 else ("high", 35) if n == 2 else ("medium", 15)
    others = sum(1 for m in mem["matches"] if m["reports"] and not m["disputed"]) - 1
    return [_factor("SCAM_MEMORY", T(f"Similar indicator found in Scam Memory: {best['label']} reported by {n} {'person' if n == 1 else 'people'}",
                                     f"Scam Memory में मिलता-जुलता संकेत: {best['label']} को {n} लोगों ने रिपोर्ट किया",
                                     f"Scam Memory ಯಲ್ಲಿ ಹೋಲುವ ಸೂಚನೆ: {best['label']} ಅನ್ನು {n} ಜನ ವರದಿ ಮಾಡಿದ್ದಾರೆ"),
                    sev, pts, "memory", [f"{best['label']}: {best['value']}"] + ([f"{others} more reported indicator(s)"] if others > 0 else []))]


def ti_factors(ti: dict | None) -> list[dict]:
    if not ti or not ti.get("matches"):
        return []
    m = ti["matches"][0]
    kind = {"SOCIAL_ENGINEERING": "phishing", "MALWARE": "malware", "UNWANTED_SOFTWARE": "unwanted software",
            "POTENTIALLY_HARMFUL_APPLICATION": "harmful app"}.get(m["threat_type"], "a threat")
    return [_factor("THREAT_INTEL_MATCH", T(f"{ti['service']} lists this link as {kind}", f"{ti['service']} इस लिंक को {kind} बताता है",
                                            f"{ti['service']} ಈ ಲಿಂಕ್ ಅನ್ನು {kind} ಎಂದು ಪಟ್ಟಿ ಮಾಡಿದೆ"),
                    "critical", 50, "threat_intel", [m["url"][:120]])]


def ai_factor(ai: dict | None) -> dict | None:
    if not ai or ai.get("status") != "ok":
        return None
    lvl = ai["risk_level"]
    if lvl == "LOW":
        return None
    pts = 20 + (5 if ai.get("credential_request") or ai.get("payment_request") else 0) if lvl == "HIGH" else 10
    what = [w for w, on in (("impersonation", ai.get("impersonation")), ("asks for credentials", ai.get("credential_request")),
                            ("asks for payment", ai.get("payment_request")), ("social engineering", ai.get("social_engineering"))) if on]
    return _factor("AI_SEMANTIC", T(f"AI reading: {lvl.lower()} risk" + (f" ({', '.join(what)})" if what else ""),
                                    f"AI का आकलन: {'ऊँचा' if lvl == 'HIGH' else 'मध्यम'} जोखिम", f"AI ಓದು: {'ಹೆಚ್ಚು' if lvl == 'HIGH' else 'ಮಧ್ಯಮ'} ಅಪಾಯ"),
                   "high" if lvl == "HIGH" else "medium", pts, "ai", [ai.get("reason", "")[:200]])


def _level(score: int):
    for threshold, level, headline, advice in MSG_VERDICTS:
        if score >= threshold:
            return level, headline, advice
    return MSG_VERDICTS[-1][1:]


SAFE_ACTIONS = {
    "share_code": "Never share an OTP, PIN, CVV or password with anyone, whoever they say they are.",
    "enter_pin_to_receive": "Never enter your UPI PIN to receive money: a PIN only ever sends money.",
    "install_remote_app": "Don't install AnyDesk, TeamViewer or any app someone asks you to install.",
    "install_apk": "Don't install apps from links; use the Play Store only.",
    "open_link": "Don't tap the link. Open the official app or type the official website address yourself.",
    "call_number": "Don't call or WhatsApp the number in the message; use the helpline printed on your card, bill or the official website.",
    "pay_fee": "Don't pay any fee or deposit to 'release', 'receive' or 'reactivate' something.",
    "send_money": "Don't send money before confirming with the person on a number you already know.",
    "video_call": "Police and officials never question or 'arrest' anyone over a video call. Hang up.",
    "keep_secret": "Tell a family member before doing anything this message asks.",
}


def combine(rep: dict, ai: dict | None = None) -> dict:
    """The explainable result. Pure function of the report (+ AI result); safe to call again after new evidence."""
    d = rep.get("details") or {}
    sms = rep.get("sms") or {}
    factors: list[dict] = []
    for f in rep.get("findings") or []:
        if f["severity"] == "info" or f["id"] == "REPORTED_BY_USERS":    # community reports are counted in memory below
            continue
        factors.append(_factor(f["id"], f["title"], f["severity"], f["points"], "memory" if f["id"] in MEMORY_IDS else "rules",
                               f.get("evidence") or []))
    factors += url_factors(rep)
    factors += _capped([_factor(s["id"], s["title"], s["severity"], s["points"], "sender", s.get("evidence")) for s in sms.get("sender_signals") or []],
                       SENDER_CAP)
    factors += memory_factors(sms.get("memory"))
    factors += ti_factors(sms.get("threat_intel"))
    det = [f for f in factors if f["points"] > 0]
    det_score = min(100, sum(f["points"] for f in det))
    critical = [f for f in det if f["severity"] == "critical"]
    if critical:
        det_score = max(det_score, 70)
    det_level = _level(det_score)[0]
    score = det_score
    af = ai_factor(ai if ai is not None else sms.get("ai"))
    if af:
        factors.append(af)
        score = min(100, det_score + af["points"])
        if det_level in ("low", "caution"):
            score = min(score, AI_ALONE_CAP)             # the AI alone can't make a message HIGH risk
    level, headline, advice = _level(score)
    factors = [f for f in factors if f["points"] > 0]
    factors.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], -f["points"]))
    acts = [a["id"] for a in d.get("asks") or []]
    safe = [SAFE_ACTIONS[a] for a in acts if a in SAFE_ACTIONS][:4]
    if level in ("danger", "suspicious"):
        safe.append("Block and delete the message. If you already paid or shared a code, call 1930 now and report at cybercrime.gov.in.")
    elif not safe:
        safe.append("If you weren't expecting it, confirm with the company or person yourself using a number you already know.")
    return {
        "level": RISK_LABEL[level], "verdict_level": level, "score": score, "score_note": SCORE_NOTE,
        "deterministic_score": det_score, "deterministic_level": RISK_LABEL[det_level],
        "decided_by_hard_evidence": bool(critical) and det_score >= 70,
        "factors": factors[:12], "safe_actions": safe,
        "verdict": {"score": score, "level": level, "headline": headline, "advice": advice, "source": "risk_engine"},
    }


def finalize(rep: dict) -> dict:
    """Recompute after community reports were applied (called from _after_check). Idempotent."""
    if rep.get("kind") != "msg" or "sms" not in rep:
        return rep
    r = combine(rep)
    rep["verdict"] = r.pop("verdict")
    rep["risk"] = r | {"layers": (rep.get("risk") or {}).get("layers") or {}}
    return rep
