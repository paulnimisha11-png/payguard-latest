"""ML scam prediction for UPI QR codes: legitimate, suspicious, known-scam and malformed examples, end to end."""
import csv
import io
import json
import os
import subprocess
import sys

import pytest
import qrcode
from fastapi.testclient import TestClient

from app.main import app
from app.ml import features as F
from app.ml import upi_model as M
from app.qr.analyzer import analyze_payload

ROOT = os.path.join(os.path.dirname(__file__), "..")

LEGIT = [
    "upi://pay?pa=merchant123@upi&pn=ABC%20Store&am=5000",
    "upi://pay?pa=ravi.kumar@oksbi&pn=Ravi%20Kumar&am=250&tn=dinner",
    "upi://pay?pa=paytmqr2810050501011abcd@paytm&pn=Sharma%20General%20Store&mc=5411",
    "upi://pay?pa=9845012345@ybl&pn=Suresh%20Rao&am=25000&tn=rent",
]
SUSPICIOUS = [  # the old rules only said "check before you pay" for this one
    "upi://pay?pa=9876543210@ybl&pn=HDFC%20Customer%20Care&am=1999",
]
KNOWN_SCAM = [
    "upi://pay?pa=9876501234@ybl&pn=SBI%20Refund%20Dept&am=4999&tn=Scan%20to%20receive%20your%20refund",
    "upi://pay?pa=anil4521@ybl&pn=Paytm%20KYC%20Team&am=99&tn=KYC%20update%20charge",
    "upi://collect?pa=7012345678@ybl&pn=Army%20Officer%20Rakesh&am=15000&tn=security%20deposit",
]
MALFORMED = [
    "upi:\\pay?pa=merchant123@upi&pn=ABC%20Store&am=5000",
    "upi://pay?pn=ABC%20Store&am=5000",
    "upi://pay?pa=merchant123@upi&pa=thief99@ybl&am=5000",
]


def post(c, text):
    r = c.post("/api/qr/text", json={"text": text})
    assert r.status_code == 200, r.text
    return r.json()


def check_shape(ml):
    assert ml["status"] == "ok"
    assert 0.0 <= ml["scam_probability"] <= 1.0 and 0.0 <= ml["scam_probability_percent"] <= 100.0
    assert abs(ml["scam_probability_percent"] - 100 * ml["scam_probability"]) < 0.06
    assert ml["prediction"] in ("Scam", "Legitimate")
    assert ml["prediction"] == ("Scam" if ml["scam_probability"] >= ml["threshold"] else "Legitimate")
    assert ml["prototype"] is True and "estimate" in ml["note"] and "not a certainty" in ml["note"]


@pytest.mark.parametrize("text", LEGIT)
def test_legitimate(text):
    with TestClient(app) as c:
        r = post(c, text)
    check_shape(r["ml"])
    assert r["ml"]["prediction"] == "Legitimate" and r["ml"]["scam_probability"] < 0.2
    assert r["verdict"]["level"] == "low" and r["verdict"]["source"] == "ml"
    assert r["verdict"]["score"] == round(100 * r["ml"]["scam_probability"])        # the score IS the calibrated estimate


@pytest.mark.parametrize("text", SUSPICIOUS + KNOWN_SCAM)
def test_suspicious_and_known_scams(text):
    with TestClient(app) as c:
        r = post(c, text)
    check_shape(r["ml"])
    assert r["ml"]["prediction"] == "Scam" and r["verdict"]["level"] in ("suspicious", "danger")
    assert any(s["direction"] == "scam" for s in r["ml"]["signals"])               # it says why


@pytest.mark.parametrize("text", MALFORMED)
def test_malformed_is_never_safe(text):
    with TestClient(app) as c:
        r = post(c, text)
    check_shape(r["ml"])
    assert r["verdict"]["level"] in ("suspicious", "danger")
    assert r["verdict"]["headline"]["en"] == "Invalid UPI format — don't pay"
    assert r["details"]["upi_format"]["valid"] is False


def test_qr_image_goes_through_the_model():
    with TestClient(app) as c:
        for text, expect in ((LEGIT[0], "Legitimate"), (KNOWN_SCAM[0], "Scam"), (MALFORMED[0], None)):
            buf = io.BytesIO()
            qrcode.make(text).save(buf, format="PNG")
            r = c.post("/api/qr/image", files={"file": ("qr.png", buf.getvalue(), "image/png")}).json()
            assert r["payload"] == text
            check_shape(r["ml"])
            if expect:
                assert r["ml"]["prediction"] == expect
            else:
                assert r["verdict"]["level"] in ("suspicious", "danger")


def test_safety_floor_keeps_hard_evidence_but_shows_the_model_as_is(monkeypatch):
    # force the model to say "legitimate" for a hidden AutoPay mandate: the verdict must not drop below the rules
    monkeypatch.setattr(M, "probability", lambda m, x: 0.05)
    r = M.apply(analyze_payload("upi://mandate?pa=abc@ybl&pn=Netflix&am=499&recur=MONTHLY"))
    assert r["ml"]["prediction"] == "Legitimate" and r["ml"]["scam_probability"] == 0.05
    assert r["verdict"]["level"] == r["rule_verdict"]["level"] == "danger"
    assert r["ml"]["safety_guard"] == ["AUTOPAY_MANDATE"] and r["verdict"]["source"] == "ml+safety_guard"


def test_non_upi_qr_is_left_to_the_rules():
    with TestClient(app) as c:
        r = post(c, "https://www.onlinesbi.sbi/")
    assert r["ml"]["status"] == "not_applicable" and r["verdict"]["level"] == "low" and "rule_verdict" not in r


def test_rule_score_is_not_a_feature():
    names = " ".join(F.FEATURE_NAMES)
    assert "score" not in names and "verdict" not in names and "level" not in names
    rep = analyze_payload(KNOWN_SCAM[0])
    x1 = F.from_report(rep)
    rep["verdict"]["score"], rep["verdict"]["level"] = 0, "low"                       # tamper with the rule output
    assert F.from_report(rep) == x1


def test_model_file_is_a_labelled_prototype_with_metrics():
    m = M.load()
    assert m and m["prototype"] is True and m["features"] == F.FEATURE_NAMES
    assert m["dataset"]["split"]["train"] > m["dataset"]["split"]["validation"] > 0 and m["dataset"]["split"]["test"] > 0
    t = m["metrics"]["test_calibrated"]
    for k in ("precision", "recall", "f1", "roc_auc", "brier", "ece_10_bins", "confusion_matrix"):
        assert k in t
    assert m["metrics"]["export_max_abs_diff"] < 1e-9
    assert m["calibration"]["method"] in ("isotonic", "sigmoid")
    card = open(os.path.join(ROOT, "app", "ml", "MODEL_CARD.md"), encoding="utf-8").read()
    assert "PROTOTYPE" in card and "not** real-world accuracy" in card


def test_calibration_is_monotonic_and_bounded():
    m = M.load()
    ps = [M.calibrate(m, i / 200) for i in range(201)]
    assert all(b >= a - 1e-12 for a, b in zip(ps, ps[1:]))
    x = F.from_payload(KNOWN_SCAM[0])
    assert M.P_MIN <= M.probability(m, x) <= M.P_MAX


def test_training_pipeline_accepts_a_replacement_dataset(tmp_path):
    pytest.importorskip("sklearn")
    rows = list(csv.DictReader(open(os.path.join(ROOT, "app", "ml", "data", "upi_synthetic_v1.csv"), encoding="utf-8")))[:900]
    data = tmp_path / "my_real_labels.csv"
    with open(data, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["payload", "label"])                    # the minimum a real dataset needs
        w.writeheader()
        w.writerows({"payload": r["payload"], "label": r["label"]} for r in rows)
    out, card = tmp_path / "model.json", tmp_path / "card.md"
    res = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "train_upi_model.py"), "--no-synthetic", "--data", str(data),
                          "--out", str(out), "--card", str(card), "--fast"], capture_output=True, text=True, cwd=ROOT)
    assert res.returncode == 0, res.stdout + res.stderr
    m = json.loads(out.read_text())
    assert m["dataset"]["files"] == ["my_real_labels.csv"] and m["metrics"]["export_max_abs_diff"] < 1e-9
    assert M.load(str(out))["features"] == F.FEATURE_NAMES
