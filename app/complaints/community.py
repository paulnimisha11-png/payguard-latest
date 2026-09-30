"""Feed complaints back into scans: 'this UPI ID / website / app has already
been reported N times by PayGuard users'. Applied at response time only, so
cached scan reports are never modified."""
from __future__ import annotations

from .. import store
from ..analyzer.rules import SEVERITY_ORDER, T, VERDICTS
from ..qr.analyzer import QR_VERDICTS
from ..screenshot.analyzer import SHOT_VERDICTS
from ..message.analyzer import MSG_VERDICTS


def scan_indicators(rep: dict) -> list[tuple[str, str, str]]:
    """(kind, value, label) the community counter is looked up with."""
    if rep.get("kind") == "qr":
        d = rep["details"]
        if d.get("type") == "upi" and d.get("payee_vpa"):
            return [("upi", d["payee_vpa"].lower(), "UPI ID")]
        if d.get("type") == "url" and not d.get("official") and (d.get("registered_domain") or d.get("host")):
            return [("domain", (d.get("registered_domain") or d.get("host")).lower(), "website")]
        if d.get("type") in ("tel", "sms") and d.get("number"):
            from .builder import norm_phone
            return [("phone", norm_phone(d["number"]), "number")]
        if d.get("type") == "url":
            return []  # official website: never let reports mark a real bank/government site as a scam
        import hashlib
        return [("qr_payload", hashlib.sha256((rep.get("payload") or "").encode()).hexdigest(), "QR code")]
    if rep.get("kind") == "msg":
        d = rep["details"]
        from .builder import norm_phone
        out = [("upi", u.lower(), "UPI ID") for u in d.get("upi_ids", [])]
        out += [("domain", l["domain"].lower(), "website") for l in d.get("links", []) if l.get("domain") and not l.get("official") and not l.get("whatsapp")]
        out += [("phone", norm_phone(p), "number") for p in d.get("phones", [])]
        if d.get("template"):
            out.append(("msg_template", d["template"], "message"))
        return out
    if rep.get("kind") == "shot":
        out = [("shot_sha256", rep["file"]["sha256"].lower(), "screenshot")]
        if rep["details"].get("utr"):
            out.append(("utr_claimed", rep["details"]["utr"], "reference number"))
        return out
    return [("apk_sha256", rep["file"]["sha256"].lower(), "app file")]


def community_counts(rep: dict) -> dict:
    """People who reported this thing: filed complaints + one-tap reports, for its strongest identifier."""
    best = {"reports": 0, "complaints": 0, "got_me": 0, "fake": 0, "disputes": 0, "label": None, "value": None, "kind": None}
    for k, v, label in scan_indicators(rep):
        if store.moderation_status(k, v) == "cleared":
            continue  # a moderator confirmed this is genuine
        c = store.indicator_count(k, v)
        vc = store.vote_counts(k, v)
        total = c + vc["total"]
        if total > best["reports"] or (not best["reports"] and vc["disputes"] > best["disputes"]):
            best = {"reports": total, "complaints": c, "got_me": vc["got_me"], "fake": vc["fake"], "disputes": vc["disputes"],
                    "label": label, "value": v, "kind": k}
    return best


def apply_reports(rep: dict) -> dict:
    cc = community_counts(rep)
    rep.setdefault("community", {}).update({k: cc[k] for k in ("reports", "complaints", "got_me", "fake", "disputes")})
    rep["community"]["can_report"] = bool(scan_indicators(rep))
    if not cc["reports"]:
        return rep
    label, value, n = cc["label"], cc["value"], cc["reports"]
    disputed = cc["disputes"] * 2 >= n
    # One report could be a mistake or a grudge, so it only asks for care; several independent reports are a warning.
    sev, pts = ("info", 0) if disputed else ("critical", 50) if n >= 3 else ("high", 35) if n == 2 else ("medium", 15)
    f = {
        "id": "REPORTED_BY_USERS", "severity": sev, "points": pts,
        "title": T(f"Already reported as a scam by {n} {'person' if n == 1 else 'people'}",
                   f"{n} लोग इसे पहले ही ठगी के रूप में रिपोर्ट कर चुके हैं",
                   f"{n} ಜನರು ಇದನ್ನು ಈಗಾಗಲೇ ವಂಚನೆ ಎಂದು ವರದಿ ಮಾಡಿದ್ದಾರೆ"),
        "detail": T(f"{n} PayGuard {'user has' if n == 1 else 'users have'} flagged this {label} as a scam"
                    + (f", {cc['got_me']} of them lost money to it" if cc["got_me"] else "") + "."
                    + (f" {cc['disputes']} other {'person says' if cc['disputes'] == 1 else 'people say'} it is genuine." if cc["disputes"] else ""),
                    f"{n} PayGuard उपयोगकर्ताओं ने इस {label} को ठगी बताया है" + (f", इनमें से {cc['got_me']} के पैसे गए" if cc["got_me"] else "") + "।"
                    + (f" {cc['disputes']} लोग इसे असली बताते हैं।" if cc["disputes"] else ""),
                    f"{n} PayGuard ಬಳಕೆದಾರರು ಈ {label} ಅನ್ನು ವಂಚನೆ ಎಂದು ಗುರುತಿಸಿದ್ದಾರೆ" + (f", ಅವರಲ್ಲಿ {cc['got_me']} ಜನ ಹಣ ಕಳೆದುಕೊಂಡರು" if cc["got_me"] else "") + "."
                    + (f" {cc['disputes']} ಜನ ಇದು ನಿಜವಾದದ್ದು ಎನ್ನುತ್ತಾರೆ." if cc["disputes"] else "")),
        "evidence": [f"{label}: {value}", f"one-tap reports: {cc['got_me'] + cc['fake']} ({cc['got_me']} lost money)", f"filed complaints: {cc['complaints']}"]
                    + ([f"marked genuine by: {cc['disputes']}"] if cc["disputes"] else []),
    }
    rep["findings"] = sorted([f] + [x for x in rep["findings"] if x["id"] != "REPORTED_BY_USERS"],
                             key=lambda x: (SEVERITY_ORDER[x["severity"]], -x["points"]))
    table, floor = {"qr": (QR_VERDICTS, 70), "shot": (SHOT_VERDICTS, 70), "msg": (MSG_VERDICTS, 70)}.get(rep.get("kind"), (VERDICTS, 45))
    if pts == 0:
        return rep
    score = min(100, rep["verdict"]["score"] + pts)
    if sev == "critical":
        score = max(score, floor)
    for threshold, level, headline, advice in table:
        if score >= threshold:
            break
    rep["verdict"] = {"score": score, "level": level, "headline": headline, "advice": advice}
    return rep
