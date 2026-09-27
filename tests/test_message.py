"""Scam message checker: real-world Indian scam scripts must be flagged, everyday genuine messages must not."""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.message import analyze_message

SCAMS = [
    # (text, expected category or None)
    ("Dear Consumer, your electricity power will be disconnected tonight at 9.30pm because your previous month bill was not updated. "
     "Please immediately contact our electricity officer 9876543210. Thank you", "electricity"),
    ("Dear SBI user, your YONO account will be blocked today. Update your PAN card immediately: http://sbi-kyc-update.xyz/login", "kyc_bank"),
    ("Your India Post parcel is held at our warehouse due to incomplete address. Update within 24 hours: https://indiapost-redelivery.top/in", "parcel"),
    ("Congratulations! You have received a refund of Rs 5,000 from Income Tax Dept. Click to claim: bit.ly/itr-refund26", "refund_prize"),
    ("Part time job: earn Rs 3000-8000 daily by liking YouTube videos. Contact on WhatsApp wa.me/919812345678", "job_task"),
    ("This is Inspector Sharma from Mumbai Cyber Crime. A parcel with drugs in your name was seized by customs. "
     "Do not disconnect the call, join Skype video call for verification or you will be arrested.", "digital_arrest"),
    ("Hello sir I am calling from customer care. To process your refund please install AnyDesk and share the code shown.", None),
    ("Your Paytm KYC has expired. Your account will be suspended in 24 hrs. Call KYC officer 7012345678 now", "kyc_bank"),
    ("Hi, I sent you Rs 2000 by mistake on Google Pay, please return it to 9812345678@ybl", "wrong_transfer"),
    ("प्रिय उपभोक्ता, आपकी बिजली आज रात 9:30 बजे काट दी जाएगी क्योंकि पिछले महीने का बिल अपडेट नहीं हुआ है। तुरंत बिजली अधिकारी से संपर्क करें 9876543210", "electricity"),
    ("Aapka bijli connection aaj raat kaat diya jayega. Turant is number pe call karein 9876543210", "electricity"),
    ("Dear customer your SBI reward points worth Rs 7,250 will expire today. Redeem now by installing SBI Rewards app: http://sbi-rewardz.in/SBI_Rewards.apk", "refund_prize"),
    ("Hi Mum, this is my new number, my phone broke. Can you send me Rs 15,000 urgently? I'll pay you back tomorrow", "family_emergency"),
    ("Share the OTP you received to confirm your refund", None),
    ("Your FASTag KYC is pending. Update now or your tag will be blacklisted: https://fastag-kyc.online/", "fastag"),
    ("Your mobile number will be disconnected within 2 hours by TRAI due to illegal activity. Press 9 or call 9123456780", "telecom"),
    ("ನಿಮ್ಮ ವಿದ್ಯುತ್ ಸಂಪರ್ಕ ಇಂದು ರಾತ್ರಿ ಕಡಿತಗೊಳ್ಳುತ್ತದೆ. ತಕ್ಷಣ 9876543210 ಗೆ ಕರೆ ಮಾಡಿ", "electricity"),
    ("Your parcel could not be delivered. Pay a redelivery fee of Rs 25 to reschedule: https://dtdc-reschedule.site/pay", "parcel"),
    ("Your pre-approved loan of Rs 2,00,000 is sanctioned. Pay processing fee Rs 999 to 9876512345@paytm to get it today", "loan"),
    ("Your vehicle has a pending e-challan of Rs 2000. Pay now to avoid court action: https://echallan-parivahan.xyz", "challan"),
    ("To receive your cashback of Rs 500, enter your UPI PIN in the request we sent", None),
    ("Join our VIP stock tips group for guaranteed returns of 10% daily. Message +91 98450 12345 on WhatsApp", "investment"),
]

GENUINE = [
    "123456 is your OTP for login to SBI YONO. Do not share it with anyone. -SBI",
    "Rs.500.00 debited from A/c XX1234 on 26-09-26 to VPA shop@okaxis (UPI Ref No 426912345678). Not you? Call 18002586161 - HDFC Bank",
    "Your Amazon order #408-1234567 has been shipped. Track your package: https://amazon.in/progress-tracker/package",
    "Dear customer, your electricity bill of Rs 845 for September is generated. Due date 10-10-2026. Pay at https://bescom.karnataka.gov.in",
    "Hi, are we still meeting at 6 today? Call me on 9876543210 if you're late",
    "Your Airtel bill of Rs 499 is due on 5 Oct. Pay easily via the Airtel Thanks app.",
    "Your Swiggy order is on its way! Your delivery partner will reach you in 20 minutes.",
    "Mom, I reached college safely. Will call you in the evening.",
    "आपका OTP 482913 है। इसे किसी के साथ साझा न करें।",
    "Your KYC has been successfully completed. Thank you for banking with ICICI Bank.",
    "Use OTP 7781 to verify your mobile number on Zomato. Valid for 10 minutes.",
    "Happy birthday! Party at my place on Saturday, bring snacks",
    "Rs 1,200 credited to your a/c XX4821 by UPI from RAHUL K. Avl bal Rs 15,322. -Canara Bank",
    "Meeting moved to 3pm tomorrow. The link is https://meet.google.com/abc-defg-hij",
]


@pytest.mark.parametrize("text,cat", SCAMS)
def test_scam_messages_are_flagged(text, cat):
    r = analyze_message(text)
    assert r["verdict"]["level"] in ("danger", "suspicious"), (r["verdict"], [f["id"] for f in r["findings"]])
    if cat:
        assert r["details"]["category"] == cat, r["details"]["category"]


@pytest.mark.parametrize("text", GENUINE)
def test_genuine_messages_stay_calm(text):
    r = analyze_message(text)
    assert r["verdict"]["level"] in ("low", "caution"), (r["verdict"], [(f["id"], f["evidence"]) for f in r["findings"]])


def test_most_scams_are_danger():
    danger = sum(analyze_message(t)["verdict"]["level"] == "danger" for t, _ in SCAMS)
    assert danger >= len(SCAMS) - 2


def test_entities_extracted():
    r = analyze_message("Pay Rs 999 to 9876512345@paytm or call +91 98450-12345. Details: bit.ly/x1 and www.sbi-help.top/kyc")
    d = r["details"]
    assert "9876512345@paytm" in d["upi_ids"]
    assert "9845012345" in d["phones"]
    assert any("bit.ly" in l["url"] for l in d["links"]) and any("sbi-help.top" in l["url"] for l in d["links"])
    assert 999 in d["amounts"]


def test_template_hash_ignores_numbers_and_links():
    a = analyze_message("Dear Consumer, your electricity power will be disconnected tonight at 9.30pm. Call officer 9876543210 immediately")
    b = analyze_message("Dear Consumer, your electricity power will be disconnected tonight at 10.30pm. Call officer 9123456789 immediately")
    assert a["details"]["template"] and a["details"]["template"] == b["details"]["template"]


def test_api_and_one_tap_report_counts_across_variants():
    base = "Dear Consumer, your electricity power will be disconnected tonight at 9.30pm. Please call electricity officer {} immediately"
    with TestClient(app) as c:
        r = c.post("/api/message", json={"text": base.format("9811100001")})
        assert r.status_code == 200 and r.json()["kind"] == "msg" and r.json()["community"]["can_report"]
        for i in range(3):
            v = c.post("/api/reports", json={"kind": "msg", "payload": base.format(f"98111000{i:02d}"), "reason": "fake", "voter": f"m{i}"})
            assert v.status_code == 200, v.text
        # a new victim gets the same script with yet another number: warned by the template count
        again = c.post("/api/message", json={"text": base.format("9811100099")}).json()
        assert again["community"]["reports"] >= 3
        assert any(f["id"] == "REPORTED_BY_USERS" for f in again["findings"])
        assert c.post("/api/message", json={"text": ""}).status_code == 422
        assert c.post("/api/message", json={"text": "x" * 20001}).status_code == 422


def test_message_complaint_and_pdf():
    text = "Your SBI account will be blocked today. Update PAN at http://sbi-kyc-update.xyz/login or pay to 9876512345@ybl"
    with TestClient(app) as c:
        r = c.post("/api/complaints", json={"source": "message", "payload": text, "lang": "en", "lost_money": True, "amount": 2500,
                                            "payment_method": "upi", "channel": "sms", "sender_contact": "+91 90000 11111"})
        assert r.status_code == 201, r.text
        b = r.json()
        kinds = {s["kind"] for s in b["suspects"]}
        assert {"upi", "domain", "phone"} <= kinds
        fields = {f["key"]: f["value"] for f in b["portal_fields"]}
        assert fields["subcategory"] == "UPI Related Frauds" and "sbi-kyc-update.xyz" in fields["description"]
        pdf = c.get(f"/api/complaints/{b['ref']}/pdf", params={"token": b["token"]})
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
        assert c.post("/api/complaints", json={"source": "message", "payload": ""}).status_code == 422
