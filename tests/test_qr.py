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


# ---------------------------------------------------------------- strict UPI format validation

VALID_UPI = [
    "upi://pay?pa=merchant123@upi&pn=ABC%20Store&am=5000",
    "upi://pay?pa=ravi.kumar@oksbi&pn=Ravi%20Kumar",
    "UPI://PAY?PA=RAVI.KUMAR@OKSBI&PN=Ravi",                       # some printed QRs are upper-case
    "upi://pay/?pa=shop-01@ybl&pn=Shop&am=99.50&cu=INR&tn=Order%2012",
    "upi://pay?pa=ravi.kumar@oksbi&pn=Ravi&",                       # trailing '&' is harmless
]

MALFORMED_UPI = [                                                   # (payload, part of the expected reason)
    ("upi:\\pay?pa=merchant123@upi&pn=ABC%20Store&am=5000", "starts with 'upi:\\'"),
    ("upi:/pay?pa=merchant123@upi&pn=ABC%20Store&am=5000", "starts with 'upi:/'"),
    ("upi:pay?pa=merchant123@upi&pn=ABC%20Store&am=5000", "starts with 'upi:'"),
    ("upi//pay?pa=merchant123@upi&am=5000", "starts with 'upi//'"),
    ("upi://pay?pn=ABC%20Store&am=5000", "missing payee UPI ID"),
    ("upi://pay?pa=&pn=ABC", "'pa') is empty"),
    ("upi://pay?pa=merchant123&pn=ABC", "exactly one '@'"),
    ("upi://pay?pa=merchant@123@upi", "exactly one '@'"),
    ("upi://pay?pa=mer chant@upi", "invalid characters"),
    ("upi://pay?pa=merchant123@upi&pa=thief99@ybl", "appears more than once"),
    ("upi://pay?pa=merchant123@upi&am", "has no value"),
    ("upi://pay?pa=merchant123@upi&=5000", "invalid parameter name"),
    ("upi://pay?pa=merchant123@upi&pn=%ZZ", "%-encoding"),
    ("upi://pay?pa=merchant123@upi&am=50,00", "not a valid number"),
    ("upi://pay?pa=merchant123@upi&am=0", "more than zero"),
    ("upi://pay?pa=merchant123@upi&cu=USD", "not INR"),
    ("upi://pya?pa=merchant123@upi", "unknown UPI action"),
    ("upi://pay", "missing '?pa=...'"),
]


@pytest.mark.parametrize("text", VALID_UPI)
def test_valid_upi_goes_through_normal_risk_analysis(text):
    r = analyze_payload(text)
    assert r["details"]["type"] == "upi" and r["details"]["upi_format"] == {"valid": True, "problems": []}
    assert not any(f["id"] == "INVALID_UPI_FORMAT" for f in r["findings"])
    assert r["verdict"]["level"] == "low"
    assert r["details"]["payee_vpa"].lower() in text.lower()


@pytest.mark.parametrize("text, reason", MALFORMED_UPI)
def test_malformed_upi_is_never_safe_and_says_why(text, reason):
    r = analyze_payload(text)
    assert r["details"]["type"] == "upi"                     # handled by the UPI checker, not as plain text
    assert r["verdict"]["level"] in ("suspicious", "danger"), r["verdict"]
    assert r["verdict"]["level"] != "low"
    fmt = r["details"]["upi_format"]
    assert fmt["valid"] is False and any(reason in p for p in fmt["problems"]), fmt["problems"]
    f = next(f for f in r["findings"] if f["id"] == "INVALID_UPI_FORMAT")
    assert f["title"]["en"] == "Invalid UPI format" and any(reason in e for e in f["evidence"])
    assert all(f["title"][l] and f["detail"][l] for l in ("en", "hi", "kn"))


def test_malformed_upi_headline_is_explicit():
    v = analyze_payload("upi:\\pay?pa=merchant123@upi&pn=ABC%20Store&am=5000")["verdict"]
    assert v["level"] == "suspicious" and v["headline"]["en"] == "Invalid UPI format — don't pay" and v["score"] >= 40


def test_malformed_upi_scam_stays_danger():
    # a broken link that is ALSO a refund scam keeps the stronger verdict
    r = analyze_payload("upi:/pay?pa=9876501234@ybl&pn=SBI%20Refund%20Dept&am=4999&tn=Scan%20to%20receive%20your%20refund")
    assert r["verdict"]["level"] == "danger" and r["details"]["upi_format"]["valid"] is False


def test_backslash_upi_not_safe_via_text_and_qr_image():
    import io
    import qrcode
    bad = "upi:\\pay?pa=merchant123@upi&pn=ABC%20Store&am=5000"
    with TestClient(app) as c:
        typed = c.post("/api/qr/text", json={"text": bad}).json()
        assert typed["verdict"]["level"] == "suspicious" and typed["details"]["upi_format"]["valid"] is False
        buf = io.BytesIO()
        qrcode.make(bad).save(buf, format="PNG")
        scanned = c.post("/api/qr/image", files={"file": ("qr.png", buf.getvalue(), "image/png")}).json()
        rep = scanned["results"][0] if "results" in scanned else scanned
        assert rep["payload"] == bad and rep["verdict"]["level"] == "suspicious"
        good = c.post("/api/qr/text", json={"text": VALID_UPI[0]}).json()
        assert good["verdict"]["level"] == "low" and good["details"]["upi_format"]["valid"] is True


def test_malformed_upi_inside_a_web_link_is_flagged():
    r = analyze_payload("https://example.com/pay?next=upi:\\pay?pa=merchant123@upi%26am=5000")
    assert any(f["id"] == "INVALID_UPI_FORMAT" for f in r["findings"]) and r["verdict"]["level"] != "low"
