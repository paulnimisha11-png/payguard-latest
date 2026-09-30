"""Runtime for the UPI scam model: loads app/ml/upi_model.json (trees + calibration exported by
scripts/train_upi_model.py) and scores a UPI QR report. Pure Python, no scikit-learn at runtime (memory budget).

    apply(rep) -> rep   adds rep["ml"] and, for UPI payment QRs, makes the model's calibrated probability the
                        primary verdict (the rule verdict is kept in rep["rule_verdict"]).

Safety floor: the ML probability decides the verdict, but it can never go below what PayGuard's hard evidence
requires: a malformed link, a critical rule finding (e.g. hidden AutoPay), real community reports, or a look-alike of
a reported scam ID. In those cases the verdict is the stricter of the two and rep["ml"]["safety_guard"] says why.
"""
from __future__ import annotations

import json
import math
import os
import struct
from bisect import bisect_right

from . import features as F

MODEL_PATH = os.environ.get("PAYGUARD_UPI_MODEL", os.path.join(os.path.dirname(__file__), "upi_model.json"))
BANDS = [(0.80, "danger"), (0.50, "suspicious"), (0.20, "caution"), (0.0, "low")]   # on the CALIBRATED probability
ORDER = {"low": 0, "caution": 1, "suspicious": 2, "danger": 3}
# findings that are hard evidence rather than a pattern guess: the verdict never goes below the rule level for these
HARD_EVIDENCE = {"INVALID_UPI_FORMAT", "REPORTED_BY_USERS", "UPI_MUTATION", "COMMUNITY_REPORTED", "AUTOPAY_MANDATE"}
_M: dict | None = None


def load(path: str | None = None) -> dict | None:
    global _M
    if path is None and _M is not None:
        return _M
    try:
        with open(path or MODEL_PATH, encoding="utf-8") as f:
            m = json.load(f)
    except (OSError, ValueError):
        return None
    if [n for n in m.get("features", [])] != F.FEATURE_NAMES:
        return None                                    # model trained on a different feature set: don't use it
    if path is None:
        _M = m
    return m


def _tree(t: dict, x: list[float]) -> float:
    n = 0
    left, right, feat, thr, val = t["l"], t["r"], t["f"], t["t"], t["v"]
    while left[n] != -1:
        n = left[n] if x[feat[n]] <= thr[n] else right[n]
    return val[n]


def _f32(v: float) -> float:
    return struct.unpack("f", struct.pack("f", v))[0]       # scikit-learn trees compare features as float32


def raw_probability(m: dict, x: list[float]) -> float:
    """Uncalibrated model output, identical to scikit-learn's predict_proba (checked at training time)."""
    x = [_f32(v) for v in x]
    mod = m["model"]
    if mod["type"] == "gradient_boosting":
        z = mod["init"] + mod["learning_rate"] * sum(_tree(t, x) for t in mod["trees"])
        return 1.0 / (1.0 + math.exp(-z))
    return sum(_tree(t, x) for t in mod["trees"]) / len(mod["trees"])      # random forest: mean of leaf P(scam)


def calibrate(m: dict, p: float) -> float:
    c = m["calibration"]
    if c["method"] == "isotonic":
        xs, ys = c["x"], c["y"]
        if p <= xs[0]:
            return ys[0]
        if p >= xs[-1]:
            return ys[-1]
        i = bisect_right(xs, p) - 1
        x0, x1, y0, y1 = xs[i], xs[i + 1], ys[i], ys[i + 1]
        return y0 if x1 == x0 else y0 + (y1 - y0) * (p - x0) / (x1 - x0)
    if c["method"] == "sigmoid":                         # Platt scaling on the logit of the raw probability
        q = min(max(p, 1e-6), 1 - 1e-6)
        z = c["a"] * math.log(q / (1 - q)) + c["b"]
        return 1.0 / (1.0 + math.exp(-z))
    return p


P_MIN, P_MAX = 0.01, 0.99      # a model calibrated on ~1,000 examples cannot justify certainty either way


def probability(m: dict, x: list[float]) -> float:
    return min(P_MAX, max(P_MIN, calibrate(m, raw_probability(m, x))))


def _logit(p: float) -> float:
    p = min(max(p, 1e-9), 1 - 1e-9)
    return math.log(p / (1 - p))


def explain(m: dict, x: list[float], k: int = 4) -> list[dict]:
    """Local explanation by occlusion: how much the model's score (log-odds) changes when one signal is set back to
    what a typical legitimate payment looks like. Positive = pushed towards scam, negative = towards legitimate."""
    base = m["baseline_legit"]
    z = _logit(raw_probability(m, x))
    out = []
    for i, name in enumerate(F.FEATURE_NAMES):
        if abs(x[i] - base[i]) < 1e-9:
            continue
        y = list(x)
        y[i] = base[i]
        d = z - _logit(raw_probability(m, y))
        if abs(d) >= 0.25:
            out.append({"feature": name, "label": F.describe(name, x[i], base[i]), "value": round(x[i], 3), "effect": round(d, 2),
                        "direction": "scam" if d > 0 else "legitimate"})
    out.sort(key=lambda e: -abs(e["effect"]))
    return out[:k]


def predict(x: list[float], m: dict | None = None) -> dict:
    m = m or load()
    p = probability(m, x)
    return {
        "status": "ok",
        "scam_probability": round(p, 4),
        "scam_probability_percent": round(100 * p, 1),
        "prediction": "Scam" if p >= m["threshold"] else "Legitimate",
        "threshold": m["threshold"],
        "model": f"{m['model']['type']} {m['version']}",
        "prototype": bool(m.get("prototype")),
        "trained_on": m["dataset"]["description"],
        "signals": explain(m, x),
        "note": "Estimated scam probability from a machine-learning model. It is an estimate, not a certainty.",
    }


def apply(rep: dict) -> dict:
    """Score a QR report. Idempotent (safe to call twice). Never raises."""
    try:
        if rep.get("kind") != "qr":
            return rep
        if (rep.get("details") or {}).get("type") != "upi":
            rep["ml"] = {"status": "not_applicable",
                         "reason": "The ML model covers UPI payment QR codes. This QR was checked by PayGuard's rules."}
            return rep
        m = load()
        if not m:
            rep["ml"] = {"status": "unavailable", "reason": "ML model file not found; showing the rule-based result."}
            return rep
        x = F.from_report(rep)
        ml = predict(x, m)
        rule = rep.get("rule_verdict") or dict(rep["verdict"])
        rep["rule_verdict"] = rule
        p = ml["scam_probability"]
        level = next(lv for cut, lv in BANDS if p >= cut)
        # Safety floor: hard evidence the model cannot overrule (it was trained on synthetic data, these are facts).
        rule_level = rule.get("level", "low")
        fmt = rep["details"].get("upi_format") or {}
        hard = [f["id"] for f in rep.get("findings") or []
                if f.get("id") in HARD_EVIDENCE or f.get("severity") == "critical"]
        if fmt and not fmt.get("valid", True) and "INVALID_UPI_FORMAT" not in hard:
            hard.insert(0, "INVALID_UPI_FORMAT")
        guard = None
        if hard:
            floor = rule_level                         # exactly as strong as the rules rate that evidence, no stronger
            if ORDER[level] < ORDER[floor]:
                level, guard = floor, hard
        if guard:
            ml["safety_guard"] = guard
        from ..qr.analyzer import INVALID_UPI_ADVICE, INVALID_UPI_HEADLINE, QR_VERDICTS
        head, adv = next((h, a) for _, lv, h, a in QR_VERDICTS if lv == level)
        if fmt and not fmt.get("valid", True):          # a malformed link always says so, whatever the level
            head, adv = INVALID_UPI_HEADLINE, INVALID_UPI_ADVICE
        rep["verdict"] = {"score": int(round(100 * p)), "level": level, "headline": head, "advice": adv,
                          "source": "ml+safety_guard" if ml.get("safety_guard") else "ml"}
        rep["ml"] = ml
    except Exception as e:                                  # the model must never break a scan
        rep["ml"] = {"status": "error", "reason": type(e).__name__}
    return rep
