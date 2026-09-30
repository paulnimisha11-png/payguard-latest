"""Train, calibrate, evaluate and export the UPI scam model (PROTOTYPE).

    pip install -r requirements-ml.txt            # scikit-learn: needed for training only, not on the server
    python scripts/make_upi_dataset.py            # (re)build the synthetic prototype dataset
    python scripts/train_upi_model.py             # -> app/ml/upi_model.json + app/ml/MODEL_CARD.md
    python scripts/train_upi_model.py --data real_labels.csv [--data more.csv] [--no-synthetic]

Any CSV with columns payload,label (1 = scam, 0 = legitimate) and optionally reports,got_me,disputes,lookalike,
scenario,source can replace or extend the synthetic data. Steps: stratified 60/20/20 train/validation/test split;
Random Forest and Gradient Boosting are fitted on train and compared on validation (log-loss); the chosen model's
probabilities are calibrated on validation (isotonic, or Platt/sigmoid for small validation sets); everything is
reported once on the untouched test set. The exported JSON is checked to reproduce scikit-learn's probabilities.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import sys

import numpy as np

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from sklearn.calibration import calibration_curve  # noqa: E402
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier  # noqa: E402
from sklearn.isotonic import IsotonicRegression  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import (brier_score_loss, confusion_matrix, f1_score, log_loss, precision_score,  # noqa: E402
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split  # noqa: E402

from app.ml import features as F  # noqa: E402
from app.ml import upi_model as RT  # noqa: E402

SYNTH = os.path.join(ROOT, "app", "ml", "data", "upi_synthetic_v1.csv")
OUT = os.path.join(ROOT, "app", "ml", "upi_model.json")
CARD = os.path.join(ROOT, "app", "ml", "MODEL_CARD.md")
SEED = 7
VERSION = "v1"


def load_rows(paths):
    rows = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                r["_file"] = os.path.basename(p)
                rows.append(r)
    return rows


def featurize(rows):
    X, y, keep = [], [], []
    for r in rows:
        com = {"reports": int(r.get("reports") or 0), "got_me": int(r.get("got_me") or 0), "disputes": int(r.get("disputes") or 0)}
        x = F.from_payload(r["payload"], com, lookalike=str(r.get("lookalike") or "0") in ("1", "true", "True"))
        if x is None:
            continue                                   # not a UPI payload: outside this model's scope
        X.append(x)
        y.append(int(r["label"]))
        keep.append(r)
    return np.array(X, dtype=float), np.array(y), keep


def export_tree(t, value_fn):
    return {"l": t.children_left.tolist(), "r": t.children_right.tolist(), "f": [int(v) for v in t.feature],
            "t": [float(v) for v in t.threshold], "v": [float(value_fn(t.value[i])) for i in range(t.node_count)]}


def export(model):
    if isinstance(model, GradientBoostingClassifier):
        trees = [export_tree(e[0].tree_, lambda v: v[0][0]) for e in model.estimators_]
        x0 = np.zeros((1, len(F.FEATURE_NAMES)))
        tree_sum = sum(e[0].predict(x0)[0] for e in model.estimators_)
        init = float(model.decision_function(x0)[0] - model.learning_rate * tree_sum)
        return {"type": "gradient_boosting", "init": init, "learning_rate": model.learning_rate, "trees": trees,
                "params": {k: model.get_params()[k] for k in ("n_estimators", "max_depth", "learning_rate", "subsample", "min_samples_leaf")}}
    cls = list(model.classes_).index(1)
    trees = [export_tree(e.tree_, lambda v: v[0][cls] / v[0].sum()) for e in model.estimators_]
    return {"type": "random_forest", "trees": trees,
            "params": {k: model.get_params()[k] for k in ("n_estimators", "max_depth", "min_samples_leaf", "class_weight")}}


def ece(y, p, bins=10):
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges) - 1, 0, bins - 1)
    return float(sum(abs(p[idx == b].mean() - y[idx == b].mean()) * (idx == b).mean() for b in range(bins) if (idx == b).any()))


def metrics(y, p, thr):
    yhat = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, yhat, labels=[0, 1]).ravel()
    return {"n": int(len(y)), "scam_share": round(float(y.mean()), 4), "threshold": thr,
            "precision": round(precision_score(y, yhat, zero_division=0), 4), "recall": round(recall_score(y, yhat, zero_division=0), 4),
            "f1": round(f1_score(y, yhat, zero_division=0), 4), "roc_auc": round(roc_auc_score(y, p), 4),
            "log_loss": round(log_loss(y, np.clip(p, 1e-6, 1 - 1e-6)), 4), "brier": round(brier_score_loss(y, p), 4),
            "ece_10_bins": round(ece(y, p), 4),
            "confusion_matrix": {"true_legit_pred_legit": int(tn), "true_legit_pred_scam": int(fp),
                                 "true_scam_pred_legit": int(fn), "true_scam_pred_scam": int(tp)}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", action="append", default=[], help="extra labelled CSV (payload,label,...)")
    ap.add_argument("--no-synthetic", action="store_true", help="train only on --data files")
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--card", default=CARD)
    ap.add_argument("--fast", action="store_true", help="small models (tests)")
    a = ap.parse_args()
    paths = ([] if a.no_synthetic else [SYNTH]) + a.data
    rows = load_rows(paths)
    X, y, kept = featurize(rows)
    print(f"{len(y)} UPI rows ({int(y.sum())} scam) from {', '.join(os.path.basename(p) for p in paths)}")

    idx = np.arange(len(y))
    tr, rest = train_test_split(idx, test_size=0.4, stratify=y, random_state=SEED)
    va, te = train_test_split(rest, test_size=0.5, stratify=y[rest], random_state=SEED)

    n = 40 if a.fast else 300
    candidates = {
        "random_forest": RandomForestClassifier(n_estimators=n, max_depth=12, min_samples_leaf=3, class_weight="balanced",
                                                n_jobs=-1, random_state=SEED),
        "gradient_boosting": GradientBoostingClassifier(n_estimators=n, max_depth=3, learning_rate=0.05, subsample=0.8,
                                                        min_samples_leaf=5, random_state=SEED),
    }
    selection = {}
    for name, mdl in candidates.items():
        mdl.fit(X[tr], y[tr])
        pv = mdl.predict_proba(X[va])[:, 1]
        selection[name] = {"val_log_loss": round(log_loss(y[va], np.clip(pv, 1e-6, 1 - 1e-6)), 4),
                           "val_roc_auc": round(roc_auc_score(y[va], pv), 4)}
        print(f"  {name:18} validation log-loss {selection[name]['val_log_loss']}  ROC-AUC {selection[name]['val_roc_auc']}")
    best = min(selection, key=lambda k: selection[k]["val_log_loss"])
    model = candidates[best]
    print(f"selected: {best}")

    # calibration on the validation set (never on train, never on test). Isotonic vs Platt/sigmoid is chosen by
    # 5-fold cross-validated log-loss *within* the validation set, then the winner is refitted on all of it.
    raw_va = model.predict_proba(X[va])[:, 1]

    def fit_cal(method, p, t):
        if method == "isotonic":
            iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(p, t)
            return {"method": "isotonic", "x": [float(v) for v in iso.X_thresholds_], "y": [float(v) for v in iso.y_thresholds_]}
        z = np.log(np.clip(p, 1e-6, 1 - 1e-6) / (1 - np.clip(p, 1e-6, 1 - 1e-6))).reshape(-1, 1)
        lr = LogisticRegression(C=1e6).fit(z, t)
        return {"method": "sigmoid", "a": float(lr.coef_[0][0]), "b": float(lr.intercept_[0])}

    from sklearn.model_selection import StratifiedKFold
    cal_cv = {}
    for method in ("isotonic", "sigmoid"):
        losses = []
        for a_i, b_i in StratifiedKFold(5, shuffle=True, random_state=SEED).split(raw_va, y[va]):
            c = fit_cal(method, raw_va[a_i], y[va][a_i])
            pc = np.array([RT.calibrate({"calibration": c}, v) for v in raw_va[b_i]])
            losses.append(log_loss(y[va][b_i], np.clip(pc, RT.P_MIN, RT.P_MAX), labels=[0, 1]))
        cal_cv[method] = round(float(np.mean(losses)), 4)
    cal = fit_cal(min(cal_cv, key=cal_cv.get), raw_va, y[va])
    print(f"calibration CV log-loss {cal_cv} -> {cal['method']}")

    thr = 0.5
    art = {
        "version": VERSION, "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "prototype": True, "threshold": thr, "features": F.FEATURE_NAMES, "feature_labels": F.LABELS,
        "model": export(model), "calibration": cal,
        "baseline_legit": [float(v) for v in np.median(X[tr][y[tr] == 0], axis=0)],
        "dataset": {"files": [os.path.basename(p) for p in paths], "rows": int(len(y)), "scam": int(y.sum()),
                    "split": {"train": int(len(tr)), "validation": int(len(va)), "test": int(len(te))},
                    "description": ("synthetic prototype data (scripts/make_upi_dataset.py)" if paths == [SYNTH]
                                    else "labelled data: " + ", ".join(os.path.basename(p) for p in paths))},
        "selection": selection, "calibration_selection": cal_cv,
    }

    # the exported JSON must reproduce scikit-learn exactly
    raw_te_sk = model.predict_proba(X[te])[:, 1]
    raw_te_rt = np.array([RT.raw_probability(art, list(x)) for x in X[te]])
    diff = float(np.max(np.abs(raw_te_sk - raw_te_rt)))
    assert diff < 1e-9, f"exported model differs from scikit-learn by {diff}"
    cal_te = np.array([RT.probability(art, list(x)) for x in X[te]])

    art["metrics"] = {
        "test_calibrated": metrics(y[te], cal_te, thr),
        "test_uncalibrated": metrics(y[te], raw_te_sk, thr),
        "export_max_abs_diff": diff,
        "reliability_test": dict(zip(("mean_predicted", "observed_scam_rate"),
                                     [list(map(lambda v: round(float(v), 3), a_)) for a_ in
                                      calibration_curve(y[te], cal_te, n_bins=10, strategy="quantile")[::-1]])),
    }
    scen = {}
    for i in te:
        s = kept[i].get("scenario") or "unknown"
        d = scen.setdefault(s, {"n": 0, "correct": 0, "label": int(y[i])})
        d["n"] += 1
        d["correct"] += int((RT.probability(art, list(X[i])) >= thr) == bool(y[i]))
    art["metrics"]["test_by_scenario"] = {k: {**v, "accuracy": round(v["correct"] / v["n"], 3)} for k, v in sorted(scen.items())}
    imp = getattr(model, "feature_importances_", None)
    art["feature_importance"] = sorted(([n_, round(float(v), 4)] for n_, v in zip(F.FEATURE_NAMES, imp)), key=lambda t: -t[1])

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(art, f, separators=(",", ":"))
    write_card(art, a.card)
    m = art["metrics"]["test_calibrated"]
    print(f"test (calibrated): precision {m['precision']} recall {m['recall']} F1 {m['f1']} ROC-AUC {m['roc_auc']} "
          f"Brier {m['brier']} ECE {m['ece_10_bins']}  |  export diff {diff:.1e}")
    print(f"wrote {os.path.relpath(a.out)} ({os.path.getsize(a.out) // 1024} KB) and {os.path.relpath(a.card)}")


def write_card(art, path):
    m, u = art["metrics"]["test_calibrated"], art["metrics"]["test_uncalibrated"]
    cm = m["confusion_matrix"]
    ds = art["dataset"]
    lines = [
        "# PayGuard UPI scam model: model card", "",
        f"**Status: PROTOTYPE ({art['version']}).** Trained on {ds['description']}. The metrics below measure how well the "
        "model learned the scenarios in that dataset. They are **not** real-world accuracy and must not be presented as such. "
        "Replace the data with real labelled UPI payloads (see scripts/train_upi_model.py) before relying on the numbers.", "",
        "## Model", f"- Selected: **{art['model']['type']}** ({art['model']['params']}), chosen on validation log-loss: {art['selection']}",
        f"- Calibration: **{art['calibration']['method']}** (chosen by 5-fold CV log-loss within the validation split: "
        f"{art['calibration_selection']}), fitted on the validation split only. Output is limited to 1-99%: a model calibrated on "
        "about a thousand examples cannot justify certainty.",
        f"- **Base rate:** {round(100 * art['dataset']['scam'] / art['dataset']['rows'])}% of the training payloads are scams. Real-world "
        "scam rates are far lower, so on real traffic these probabilities overstate risk: read them as relative risk until the model is "
        "recalibrated on real data.",
        f"- Decision threshold: calibrated scam probability >= {art['threshold']} → *Scam*.",
        "- Runtime: trees + calibration exported to `app/ml/upi_model.json` and evaluated in pure Python "
        f"(max difference from scikit-learn on the test set: {art['metrics']['export_max_abs_diff']:.1e}).", "",
        "## Data", f"- Files: {', '.join(ds['files'])}; {ds['rows']} UPI payloads, {ds['scam']} scam / {ds['rows'] - ds['scam']} legitimate.",
        f"- Split (stratified, seed {SEED}): train {ds['split']['train']}, validation {ds['split']['validation']}, test {ds['split']['test']}.", "",
        "## Test-set results (synthetic data)", "",
        "| | precision | recall | F1 | ROC-AUC | Brier | ECE (10 bins) |", "|---|---|---|---|---|---|---|",
        f"| calibrated | {m['precision']} | {m['recall']} | {m['f1']} | {m['roc_auc']} | {m['brier']} | {m['ece_10_bins']} |",
        f"| uncalibrated | {u['precision']} | {u['recall']} | {u['f1']} | {u['roc_auc']} | {u['brier']} | {u['ece_10_bins']} |", "",
        "Confusion matrix (calibrated, test):", "", "| | predicted legitimate | predicted scam |", "|---|---|---|",
        f"| actually legitimate | {cm['true_legit_pred_legit']} | {cm['true_legit_pred_scam']} |",
        f"| actually scam | {cm['true_scam_pred_legit']} | {cm['true_scam_pred_scam']} |", "",
        "Accuracy by scenario (test):", "", "| scenario | label | n | accuracy |", "|---|---|---|---|",
    ] + [f"| {k} | {'scam' if v['label'] else 'legit'} | {v['n']} | {v['accuracy']} |" for k, v in art["metrics"]["test_by_scenario"].items()] + [
        "", "## Features", "", "| feature | meaning | importance |", "|---|---|---|",
    ] + [f"| `{n}` | {art['feature_labels'][n]} | {v} |" for n, v in art["feature_importance"]] + [
        "", "## Known limitations",
        "- Synthetic scenarios encode PayGuard's own understanding of scams; the model can only be as good as that picture.",
        "- 'Quiet' scams (an ordinary-looking personal UPI ID) are only catchable through community reports.",
        "- The probability is an estimate for payloads like the training data; unusual real-world QRs can be misjudged.",
        "- PayGuard's safety guard still raises malformed links and critical rule findings to at least 'suspicious'.",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
