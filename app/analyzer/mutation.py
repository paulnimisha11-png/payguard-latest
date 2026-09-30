"""Scam mutation matching: catch a scam that came back slightly changed.

Blacklists only match exact values, so a scammer whose UPI ID was reported just opens a new one a character away
(sbi-refund-support@ybl -> sbi-refunds-support@ybl), and a reported trojan comes back with a new name and version
but the same insides. This module compares what is being checked with what people already reported:

* UPI IDs: edit distance (Levenshtein) + character-pair overlap (Jaccard), plus a look-alike check (0/o, 1/l,
  dots vs dashes). An ID that is >= 85% structurally similar to a reported scam ID gets a warning.
* APKs: a permission/behaviour fingerprint (permissions, capabilities, component types, sensitive APIs; never the
  name, package, version or signature). Identical fingerprint = "topology hash" match; >= 85% Jaccard overlap with
  an app rated danger = likely a repackaged copy.

Applied at response time (complaints.community.apply_reports), so cached reports are never modified.
"""
from __future__ import annotations

import difflib
import hashlib
import re

from .. import store
from .rules import T

UPI_THRESHOLD = 0.85
APK_THRESHOLD = 0.85
# Capabilities that make an app worth fingerprint-matching; apps with fewer than two of these share too much with
# ordinary apps (INTERNET, notifications ...) for a match to mean anything.
RISKY_CAPS = {"sms_receiver", "sms_read_api", "sms_inbox_query", "sms_send", "accessibility", "overlay", "notif_listener",
              "device_admin", "install_packages", "hide_icon_api", "dynamic_code", "embedded_apk", "telegram_bot",
              "sms_handler", "screen_capture", "call_phone", "no_launcher"}
_SKELETON = str.maketrans({"0": "o", "1": "l", "i": "l", "|": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b"})


# ------------------------------------------------------------------ string similarity

def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _bigrams(s: str) -> set[str]:
    s = f"^{s}$"
    return {s[i:i + 2] for i in range(len(s) - 1)}


def jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if (a or b) else 1.0


def skeleton(vpa: str) -> str:
    """What a VPA looks like to a hurried reader: look-alike characters folded, separators dropped."""
    return re.sub(r"[.\-_]", "", vpa.lower().replace("rn", "m").replace("vv", "w").translate(_SKELETON))


def vpa_similarity(a: str, b: str) -> float:
    """0..1: half edit-distance similarity, half character-pair overlap. The pair overlap stops two short, genuinely
    different IDs (ravi.k@ybl / ravi.m@ybl) from looking alike just because they differ in one character."""
    a, b = a.lower(), b.lower()
    lev = 1 - levenshtein(a, b) / max(len(a), len(b), 1)
    sim = 0.5 * lev + 0.5 * jaccard(_bigrams(a), _bigrams(b))
    if skeleton(a) == skeleton(b):
        sim = max(sim, 0.95)  # sbi.refund@ybl vs sbi-refund@ybl vs sb1-refund@ybl
    return sim


def describe_edit(a: str, b: str) -> str:
    """Human-readable difference: 'refund' -> 'refunds'."""
    parts = []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, b, a, autojunk=False).get_opcodes():
        if op == "equal":
            continue
        lo, hi = max(0, i1 - 3), i2 + 3
        parts.append(f"'{b[lo:hi]}' -> '{a[max(0, j1 - 3):j2 + 3]}'")
    return ", ".join(parts[:3])


def _comparable(vpa: str, bad: str) -> bool:
    la, _, ha = vpa.partition("@")
    lb, _, hb = bad.partition("@")
    if len(re.sub(r"[^a-z]", "", la)) < 5:
        return False  # phone-number and very short IDs: a near miss is usually just a different person
    if re.sub(r"\d", "", la) == re.sub(r"\d", "", lb) and ha == hb:
        return False  # only digits differ (ravi.kumar1 / ravi.kumar2): different people, not a mutation
    return abs(len(vpa) - len(bad)) <= 4


def match_vpa(vpa: str, known_bad: list[str]) -> tuple[str, float] | None:
    """Closest reported scam ID that this one is a mutation of (never an exact match: that is a plain report)."""
    vpa = vpa.lower().strip()
    best = None
    for bad in known_bad:
        bad = bad.lower()
        if bad == vpa or not _comparable(vpa, bad):
            continue
        s = vpa_similarity(vpa, bad)
        if s >= UPI_THRESHOLD and (best is None or s > best[1]):
            best = (bad, s)
    return best


# ------------------------------------------------------------------ APK behaviour fingerprint

def apk_features(rep: dict) -> set[str]:
    f = {f"perm:{p['short']}" for p in rep.get("permissions", []) if p.get("short")}
    f |= {f"cap:{k}" for k, v in (rep.get("capabilities") or {}).items() if v is True}
    f |= {f"comp:{k}" for k, v in (rep.get("components") or {}).items() if isinstance(v, list) and v}
    f |= {f"api:{a['key']}" for a in (rep.get("code") or {}).get("suspicious_apis", []) if a.get("key")}
    return f


def topology_hash(features: set[str]) -> str:
    return "pt1:" + hashlib.sha256("|".join(sorted(features)).encode()).hexdigest()[:16]


def _risky(features) -> int:
    return sum(1 for x in features if x.startswith("cap:") and x[4:] in RISKY_CAPS)


def match_apk(features: set[str], sha: str, flagged: list[dict]) -> tuple[dict, float] | None:
    if _risky(features) < 2:
        return None
    topo = topology_hash(features)
    best = None
    for row in flagged:
        if row["sha256"] == sha or _risky(row["features"]) < 2:
            continue
        s = 1.0 if row["topo"] == topo else jaccard(features, set(row["features"]))
        if s >= APK_THRESHOLD and (best is None or s > best[1]):
            best = (row, s)
    return best


# ------------------------------------------------------------------ findings

def _vpas(rep: dict) -> list[str]:
    d = rep.get("details") or {}
    if rep.get("kind") == "qr" and d.get("type") == "upi" and d.get("payee_vpa"):
        return [d["payee_vpa"]]
    if rep.get("kind") == "msg":
        return list(d.get("upi_ids", []))
    return []


def _usable_report(value: str) -> int:
    """Number of scam reports on this ID, or 0 if a moderator cleared it or most people say it is genuine."""
    if store.moderation_status("upi", value) == "cleared":
        return 0
    vc = store.vote_counts("upi", value)
    n = store.indicator_count("upi", value) + vc["total"]
    return 0 if vc["disputes"] * 2 >= n else n


def upi_findings(rep: dict) -> list[dict]:
    vpas = _vpas(rep)
    if not vpas:
        return []
    known = store.reported_ids("upi")
    for vpa in vpas:
        m = match_vpa(vpa, known)
        if not m:
            continue
        bad, sim = m
        n = _usable_report(bad)
        if not n:
            continue
        pct = round(sim * 100)
        sev, pts = ("high", 40) if n >= 2 else ("medium", 20)
        return [{
            "id": "UPI_MUTATION", "severity": sev, "points": pts,
            "title": T(f"Look-alike of a reported scam UPI ID ({pct}% match)",
                       f"ठगी के रूप में रिपोर्ट किए गए UPI ID से मिलता-जुलता ({pct}% मेल)",
                       f"ವಂಚನೆ ಎಂದು ವರದಿಯಾದ UPI ID ಗೆ ಹೋಲುತ್ತದೆ ({pct}% ಹೊಂದಾಣಿಕೆ)"),
            "detail": T(f"{vpa} is almost the same as {bad}, which {n} {'person has' if n == 1 else 'people have'} reported as a scam. "
                        "Scammers open a new UPI ID a letter or two away when the old one gets reported or blocked. "
                        "Don't pay unless you know this person.",
                        f"{vpa} लगभग {bad} जैसा ही है, जिसे {n} लोग ठगी बता चुके हैं। पुराना UPI ID रिपोर्ट या ब्लॉक होने पर ठग "
                        "एक-दो अक्षर बदलकर नया UPI ID बना लेते हैं। जब तक आप इस व्यक्ति को नहीं जानते, पैसे न भेजें।",
                        f"{vpa} ಬಹುತೇಕ {bad} ನಂತೆಯೇ ಇದೆ, ಅದನ್ನು {n} ಜನರು ವಂಚನೆ ಎಂದು ವರದಿ ಮಾಡಿದ್ದಾರೆ. ಹಳೆಯ UPI ID ವರದಿ ಅಥವಾ "
                        "ಬ್ಲಾಕ್ ಆದಾಗ ವಂಚಕರು ಒಂದೆರಡು ಅಕ್ಷರ ಬದಲಿಸಿ ಹೊಸ UPI ID ತೆರೆಯುತ್ತಾರೆ. ಈ ವ್ಯಕ್ತಿ ನಿಮಗೆ ಗೊತ್ತಿಲ್ಲದಿದ್ದರೆ ಪಾವತಿಸಬೇಡಿ."),
            "evidence": [f"this UPI ID: {vpa}", f"reported scam UPI ID: {bad} ({n} reports)",
                         f"structural match: {pct}% (edit distance {levenshtein(vpa.lower(), bad)})",
                         f"changed: {describe_edit(vpa.lower(), bad)}"],
        }]
    return []


def apk_findings(rep: dict) -> list[dict]:
    feats = apk_features(rep)
    m = match_apk(feats, rep["file"]["sha256"].lower(), store.apk_fp_flagged())
    if not m:
        return []
    row, sim = m
    exact = sim >= 1.0
    pct = round(sim * 100)
    other = f"{row['name'] or 'unnamed app'} ({row['package'] or 'unknown package'})"
    same_pkg = row["package"] and row["package"] == (rep.get("app") or {}).get("package")
    sev, pts = ("critical", 50) if exact else ("high", 35)
    return [{
        "id": "APK_REPACKAGED", "severity": sev, "points": pts,
        "title": T("Same insides as a known dangerous app" if exact else f"Built like a known dangerous app ({pct}% match)",
                   "एक जाने-माने खतरनाक ऐप जैसा ही अंदरूनी ढाँचा" if exact else f"एक जाने-माने खतरनाक ऐप जैसा बना है ({pct}% मेल)",
                   "ತಿಳಿದಿರುವ ಅಪಾಯಕಾರಿ ಆ್ಯಪ್‌ನಂತೆಯೇ ಒಳರಚನೆ" if exact else f"ತಿಳಿದಿರುವ ಅಪಾಯಕಾರಿ ಆ್ಯಪ್‌ನಂತೆ ನಿರ್ಮಿತ ({pct}% ಹೊಂದಾಣಿಕೆ)"),
        "detail": T(f"Its permissions and behaviour match {other}, which was found to be dangerous. Scammers re-release the same "
                    "trojan under a new name and version to get past blacklists.",
                    f"इसकी परमिशन और काम करने का तरीका {other} से मेल खाता है, जो खतरनाक पाया गया था। ठग ब्लैकलिस्ट से बचने के लिए वही "
                    "ट्रोजन नए नाम और वर्ज़न से दोबारा भेजते हैं।",
                    f"ಇದರ ಅನುಮತಿಗಳು ಮತ್ತು ವರ್ತನೆ {other} ಗೆ ಹೊಂದುತ್ತವೆ, ಅದು ಅಪಾಯಕಾರಿ ಎಂದು ಕಂಡುಬಂದಿತ್ತು. ಬ್ಲಾಕ್‌ಲಿಸ್ಟ್ ತಪ್ಪಿಸಲು ವಂಚಕರು "
                    "ಅದೇ ಟ್ರೋಜನ್ ಅನ್ನು ಹೊಸ ಹೆಸರು ಮತ್ತು ಆವೃತ್ತಿಯಲ್ಲಿ ಮತ್ತೆ ಬಿಡುತ್ತಾರೆ."),
        "evidence": [f"behaviour fingerprint: {topology_hash(feats)}", f"matches: {other}, fingerprint {row['topo']}",
                     f"similarity: {pct}% of {len(feats | set(row['features']))} traits"]
                    + ([] if same_pkg else ["different package name: likely repackaged"]),
    }]


def findings(rep: dict) -> list[dict]:
    """Mutation findings for any scan report. Never raises: matching must not break a scan."""
    try:
        if rep.get("kind") in ("qr", "msg"):
            return upi_findings(rep)
        if rep.get("kind") is None and rep.get("permissions") is not None:
            return apk_findings(rep)
    except Exception:
        pass
    return []


def record(rep: dict) -> None:
    """Remember an APK's fingerprint and rating so later repackaged copies can be matched against it."""
    try:
        if rep.get("kind") is None and rep.get("permissions") is not None:
            feats = apk_features(rep)
            store.apk_fp_put(rep["file"]["sha256"], rep["app"].get("package"), rep["app"].get("name"),
                             topology_hash(feats), list(feats), rep["verdict"]["level"])
    except Exception:
        pass
