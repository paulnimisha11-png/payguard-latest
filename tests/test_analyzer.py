import os, zipfile, pytest
from fastapi.testclient import TestClient
from app.analyzer import analyze_apk, AnalysisError
from app.main import app

S = os.path.join(os.path.dirname(__file__), "..", "samples")
p = lambda n: os.path.join(S, n)


def ids(r):
    return {f["id"] for f in r["findings"]}


def test_trojan_fixture_is_danger(tmp_path):
    r = analyze_apk(p("Courier_Delivery_Update.apk"), "Courier_Delivery_Update.apk", workdir=str(tmp_path))
    assert r["verdict"]["level"] == "danger" and r["verdict"]["score"] == 100
    for must in ["BANKING_TROJAN_TRIAD", "TELEGRAM_EXFILTRATION", "SMS_OTP_THEFT", "CALL_FORWARDING",
                 "BANK_APP_TARGET_LIST", "CREDENTIAL_PHISHING_FORM", "SCAM_LURE_MISMATCH"]:
        assert must in ids(r), must
    assert r["capabilities"]["accessibility"] and r["capabilities"]["overlay"] and r["capabilities"]["sms_any"]
    for f in r["findings"]:
        assert all(f["title"][l] and f["detail"][l] for l in ("en", "hi", "kn"))


@pytest.mark.parametrize("name", ["com.politedroid_4.apk", "com.teleca.jamendo_35.apk"])
def test_benign_apps_low(name, tmp_path):
    r = analyze_apk(p(name), name, workdir=str(tmp_path))
    assert r["verdict"]["level"] == "low", r["findings"]


def test_not_a_zip(tmp_path):
    f = tmp_path / "x.apk"; f.write_bytes(b"hello")
    with pytest.raises(AnalysisError):
        analyze_apk(str(f), "x.apk", workdir=str(tmp_path))


def test_zip_without_manifest(tmp_path):
    f = tmp_path / "x.apk"
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("readme.txt", "hi")
    with pytest.raises(AnalysisError):
        analyze_apk(str(f), "x.apk", workdir=str(tmp_path))


def test_split_bundle(tmp_path):
    f = tmp_path / "bundle.apks"
    with zipfile.ZipFile(f, "w") as z:
        z.write(p("Courier_Delivery_Update.apk"), "base.apk")
    r = analyze_apk(str(f), "bundle.apks", workdir=str(tmp_path))
    assert r["file"]["bundle_member"] == "base.apk" and r["verdict"]["level"] == "danger"


def test_api_roundtrip(tmp_path, monkeypatch):
    with TestClient(app) as c:
        with open(p("Courier_Delivery_Update.apk"), "rb") as fh:
            r = c.post("/api/scan", files={"file": ("Courier_Delivery_Update.apk", fh)})
        assert r.status_code == 200, r.text
        sha = r.json()["file"]["sha256"]
        assert c.get(f"/api/report/{sha}").status_code == 200
        e = c.post("/api/explain", json={"sha256": sha, "lang": "kn"}).json()
        assert "1930" in e["message"]
        assert c.post("/api/scan", files={"file": ("x.apk", b"nope")}).status_code == 422


# ---------------------------------------------------------------- scam mutation matching (app/analyzer/mutation.py)
from app.analyzer import mutation as M


def test_vpa_similarity_rules():
    assert M.vpa_similarity("sbi-refunds-support@ybl", "sbi-refund-support@ybl") >= 0.85
    assert M.vpa_similarity("sbi.refund.support@ybl", "sbi-refund-support@ybl") >= 0.95   # separators swapped
    assert M.vpa_similarity("sb1-refund-supp0rt@ybl", "sbi-refund-support@ybl") >= 0.95   # look-alike characters
    assert M.vpa_similarity("ravi.k@ybl", "ravi.m@ybl") < 0.85                             # short IDs: different people
    known = ["sbi-refund-support@ybl", "ravi.kumar1@oksbi", "9876501234@ybl"]
    assert M.match_vpa("sbi-refunds-support@ybl", known)[0] == "sbi-refund-support@ybl"
    assert M.match_vpa("sbi-refund-support@ybl", known) is None      # exact: that's a plain report, not a mutation
    assert M.match_vpa("ravi.kumar2@oksbi", known) is None            # only digits differ
    assert M.match_vpa("9876501235@ybl", known) is None               # phone-number IDs
    assert M.match_vpa("mithu.singh@okaxis", known) is None


def test_upi_mutation_warns_via_api():
    import uuid
    from app import store
    tag = uuid.uuid4().hex[:6]
    bad, mutated = f"sbi-refund-help{tag}@ybl", f"sbi-refunds-help{tag}@ybl"
    for i in range(3):
        store.vote_add([("upi", bad)], f"test-mut-{tag}-{i}", "fake", f"net-{tag}-{i}")
    with TestClient(app) as c:
        r = c.post("/api/qr/text", json={"text": f"upi://pay?pa={mutated}&pn=Help%20Desk"}).json()
        f = next(f for f in r["findings"] if f["id"] == "UPI_MUTATION")
        assert f["severity"] == "high" and bad in " ".join(f["evidence"])
        assert all(f["title"][l] and f["detail"][l] for l in ("en", "hi", "kn"))
        assert r["verdict"]["level"] in ("suspicious", "danger")
        # a disputed report doesn't spread to look-alikes
        for i in range(4):
            store.vote_add([("upi", bad)], f"test-mut-d-{tag}-{i}", "not_scam", f"net-d-{tag}-{i}")
        r = c.post("/api/qr/text", json={"text": f"upi://pay?pa={mutated}&pn=Help%20Desk"}).json()
        assert "UPI_MUTATION" not in ids(r)


def test_repackaged_apk_is_caught(tmp_path):
    import shutil, uuid
    variant = tmp_path / "Parcel_Tracker_v2.apk"
    shutil.copy(p("Courier_Delivery_Update.apk"), variant)
    with zipfile.ZipFile(variant, "a") as z:
        z.comment = f"repack {uuid.uuid4().hex}".encode()  # new file hash, same app inside
    with TestClient(app) as c:
        with open(p("Courier_Delivery_Update.apk"), "rb") as fh:
            assert c.post("/api/scan", files={"file": ("Courier_Delivery_Update.apk", fh)}).json()["verdict"]["level"] == "danger"
        with open(variant, "rb") as fh:
            r = c.post("/api/scan", files={"file": ("Parcel_Tracker_v2.apk", fh)}).json()
        f = next(f for f in r["findings"] if f["id"] == "APK_REPACKAGED")
        assert f["severity"] == "critical" and any(e.startswith("behaviour fingerprint: pt1:") for e in f["evidence"])
        for name in ("com.politedroid_4.apk", "com.teleca.jamendo_35.apk"):
            with open(p(name), "rb") as fh:
                r = c.post("/api/scan", files={"file": (name, fh)}).json()
            assert "APK_REPACKAGED" not in ids(r) and r["verdict"]["level"] == "low"
