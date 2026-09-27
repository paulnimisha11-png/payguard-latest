import glob, os, pytest
from fastapi.testclient import TestClient
from app.main import app
from app.qr.analyzer import analyze_payload, decode_qr_image

Q = os.path.join(os.path.dirname(__file__), "..", "samples", "qr")


def level(t):
    return analyze_payload(t)["verdict"]["level"]


@pytest.mark.parametrize("text", [
    "upi://pay?pa=9876501234@ybl&pn=SBI%20Refund%20Dept&am=4999&tn=Scan%20to%20receive%20your%20refund",
    "upi://mandate?pa=abc@ybl&pn=Netflix&am=499&recur=MONTHLY",
    "https://sbi-kyc-update.xyz/login",
    "http://103.21.58.14/Courier_Delivery.apk",
    "tel:*21*9876543210%23",
])
def test_scams_are_danger(text):
    assert level(text) == "danger"


@pytest.mark.parametrize("text", [
    "upi://pay?pa=paytmqr2810050501011abcd@paytm&pn=Sharma%20General%20Store&mc=5411",
    "upi://pay?pa=ravi.kumar@oksbi&pn=Ravi%20Kumar",
    "https://www.onlinesbi.sbi/", "https://www.amazon.in/deal", "https://incometax.gov.in/refund",
    "https://mybucket.s3.amazonaws.com/x.png",
])
def test_genuine_are_low(text):
    assert level(text) == "low"


def test_upi_always_says_money_goes_out():
    r = analyze_payload("upi://pay?pa=ravi.kumar@oksbi&pn=Ravi&am=100")
    assert r["details"]["money_direction"] == "out" and r["details"]["amount"] == 100
    assert any(f["id"] == "MONEY_GOES_OUT" for f in r["findings"])
    for f in r["findings"]:
        assert all(f["title"][l] and f["detail"][l] for l in ("en", "hi", "kn"))


@pytest.mark.parametrize("path", sorted(glob.glob(os.path.join(Q, "*"))))
def test_sample_images_decode_and_classify(path):
    codes = decode_qr_image(open(path, "rb").read())
    assert codes
    expected = "low" if "genuine" in path else "danger"
    assert analyze_payload(codes[0])["verdict"]["level"] == expected


def test_qr_api():
    with TestClient(app) as c:
        with open(os.path.join(Q, "whatsapp_screenshot_scam.jpg"), "rb") as fh:
            r = c.post("/api/qr/image", files={"file": ("s.jpg", fh, "image/jpeg")})
        assert r.status_code == 200 and r.json()["verdict"]["level"] == "danger"
        assert c.post("/api/qr/text", json={"text": "https://www.amazon.in"}).json()["verdict"]["level"] == "low"
        assert c.post("/api/qr/image", files={"file": ("x.png", b"notanimage", "image/png")}).status_code == 422
