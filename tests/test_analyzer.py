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
