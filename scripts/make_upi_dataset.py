"""Generate the PROTOTYPE labelled dataset for the UPI scam model.

PayGuard does not (yet) have enough real, labelled UPI QR payloads, so this script builds a synthetic dataset from
documented scenarios: common legitimate payments (friends, shops, billers, temples) and the Indian UPI scam
patterns PayGuard's rules were written for (refund / "scan to receive", impersonation, KYC fees, prize, OLX
"army officer", AutoPay traps, collect requests, fake merchants, links in notes, tampered QRs, and "quiet" scams
that look ordinary). Hard cases and 2% label noise are added on purpose so the problem is not trivially separable.

Because the scenarios encode our own understanding of scams, metrics measured on this data show how well the
model learned THESE patterns - NOT real-world accuracy. Replace or extend the CSV with real labelled data
(same columns; label 1 = scam, 0 = legitimate) and re-run scripts/train_upi_model.py.

    python scripts/make_upi_dataset.py          # writes app/ml/data/upi_synthetic_v1.csv
Columns: payload,label,scenario,reports,got_me,disputes,lookalike,source
"""
from __future__ import annotations

import csv
import os
import random
from urllib.parse import quote

SEED = 20260930
OUT = os.path.join(os.path.dirname(__file__), "..", "app", "ml", "data", "upi_synthetic_v1.csv")

FIRST = ["ravi", "asha", "priya", "arjun", "meera", "rahul", "kiran", "deepa", "vikram", "sneha", "anil", "pooja", "suresh",
         "divya", "manoj", "kavya", "rohit", "lakshmi", "sanjay", "neha", "farhan", "ayesha", "joseph", "mary", "gurpreet",
         "harish", "shreya", "nikhil", "fatima", "arun", "sunita", "prakash", "anjali", "varun", "swati"]
LAST = ["kumar", "sharma", "rao", "patel", "reddy", "nair", "iyer", "singh", "das", "khan", "joshi", "gupta", "menon",
        "shetty", "bose", "verma", "mishra", "pillai", "gowda", "naik"]
P2P_HANDLES = ["okaxis", "oksbi", "okhdfcbank", "okicici", "ybl", "ibl", "axl", "paytm", "upi", "apl", "sbi", "icici",
               "hdfcbank", "axisbank", "kotak", "idfcbank", "yesbank", "fbl", "barodampay", "pnb"]
RARE_HANDLES = ["kvb", "dbs", "rbl", "jupiteraxis", "timecosmos", "tjsb", "dlb", "cmsidfc"]   # real but less common
SHOPS = ["Sharma General Store", "Sri Lakshmi Medicals", "Hotel Annapoorna", "Green Leaf Veg", "City Bakery",
         "Balaji Fancy Store", "Raj Mobile Point", "Fresh Mart", "Anand Sweets", "Janata Hardware", "Om Sai Kirana",
         "Metro Tailors", "Royal Fruits", "Kumar Auto Works", "Blue Star Salon"]
MCC = ["5411", "5812", "5499", "5912", "5732", "5311", "7230", "5331", "5814", "4121", "5942", "7538"]
P2P_NOTES = ["dinner", "rent", "fees", "trip share", "gift", "loan return", "groceries", "birthday gift", "movie",
             "petrol", "tuition", "maid salary", "electricity share", "chai", "cab share", "", "", ""]
IMPERSONATE = ["SBI Refund Dept", "Income Tax Department", "Electricity Board Officer", "HDFC Customer Care",
               "Police Cyber Cell", "RBI Grievance Cell", "Paytm KYC Team", "Amazon Refund Desk", "ICICI Bank Support",
               "PhonePe Cashback", "Customs Clearance Officer", "TRAI Helpline", "Flipkart Refund Team", "Govt Subsidy Office"]
RECEIVE_NOTES = ["Scan to receive your refund", "Cashback credited on scan", "Enter PIN to receive money",
                 "Refund of Rs {am}", "Claim your reward", "Receive payment from buyer", "Get cashback now",
                 "Prize money credit", "Refund processing - scan to get"]
KYC_NOTES = ["KYC update charge", "Account unblock fee", "PAN link fee", "KYC verification", "Re-activation charges"]
PRIZE_NAMES = ["KBC Lottery Winner", "Lucky Draw Office", "Jio Prize Department", "Amazon Lucky Winner", "Mega Prize Claim"]
ARMY_NAMES = ["Army Officer Rakesh", "CRPF Jawan Sunil", "Indian Army Canteen", "BSF Officer Vijay"]
BRAND_LOCAL = ["sbi.refund", "hdfc.care", "icici.helpdesk", "paytm.kyc", "phonepe.cashback", "amazon.refund",
               "gpay.reward", "npci.support", "sbi.kyc.update", "incometax.refund", "customer.care.help", "rbi.claim"]
QUIET_NOTES = ["urgent", "please send fast", "hospital", "investment", "trading profit", "task payment", "", "", "help"]


def rnd_person(r):
    return f"{r.choice(FIRST).title()} {r.choice(LAST).title()}"


def person_vpa(r, handles=P2P_HANDLES):
    f, l = r.choice(FIRST), r.choice(LAST)
    style = r.random()
    if style < 0.3:
        local = f"{f}.{l}"
    elif style < 0.55:
        local = f"{f}{l}{r.randint(1, 999)}"
    elif style < 0.8:
        local = f"{r.choice('6789')}{r.randint(100000000, 999999999)}"         # mobile number
    else:
        local = f"{f}{r.randint(10, 99)}"
    return f"{local}@{r.choice(handles)}"


def scam_vpa(r):
    s = r.random()
    if s < 0.45:
        local = f"{r.choice('6789')}{r.randint(100000000, 999999999)}"
    elif s < 0.7:
        local = f"{r.choice(['pay', 'user', 'acc', 'upi', ''])}{r.randint(100000, 99999999)}"
    elif s < 0.85:
        local = f"{r.choice(FIRST)}{r.randint(1000, 999999)}"
    else:
        local = f"{r.choice(FIRST)}.{r.choice(LAST)}"
    return f"{local}@{r.choice(P2P_HANDLES + RARE_HANDLES[:3])}"


def uri(action="pay", **p):
    parts = [f"{k}={quote(str(v), safe='@.-_')}" for k, v in p.items() if v not in (None, "")]
    return f"upi://{action}?" + "&".join(parts)


def amount(r, lo, hi, ends99=0.0, rounded=0.0):
    a = r.randint(lo, hi)
    x = r.random()
    if x < ends99:
        a = max(99, (a // 100) * 100 + 99)
    elif x < ends99 + rounded:
        a = max(1000, (a // 1000) * 1000)
    return f"{a}" if r.random() < 0.8 else f"{a}.{r.randint(0, 99):02d}"


def community(r, scam: bool, quiet: bool = False):
    if quiet:                     # a quiet scam is only knowable once victims report it
        if r.random() < 0.7:
            rep = min(40, int(r.expovariate(1 / 6)) + 2 if r.random() < 0.85 else 1)
            return rep, r.randint(1, rep), 0, r.random() < 0.15
        return 0, 0, 0, False
    if scam:
        if r.random() < 0.5:
            rep = min(40, int(r.expovariate(1 / 6)) + 2 if r.random() < 0.85 else 1)   # real scams collect several reports
            return rep, r.randint(1 if rep > 1 else 0, rep), 0 if r.random() < 0.9 else 1, r.random() < 0.08
        return 0, 0, 0, r.random() < 0.04
    if r.random() < 0.08:                  # false, mistaken or malicious reports against genuine accounts: usually just one
        rep = 1 if r.random() < 0.75 else r.randint(2, 3)
        return rep, (1 if r.random() < 0.3 else 0), r.randint(0, 3), False
    return 0, 0, (1 if r.random() < 0.03 else 0), r.random() < 0.01


# ------------------------------------------------------------------ scenarios: (name, label, weight, generator)

def legit_p2p(r):
    am = None if r.random() < 0.4 else (amount(r, 10, 5000, rounded=0.25) if r.random() < 0.85 else amount(r, 8000, 45000, rounded=0.6))
    return uri(pa=person_vpa(r), pn=rnd_person(r) if r.random() < 0.85 else "", am=am, tn=r.choice(P2P_NOTES))


SMALL_SHOPS = ["ABC Store", "Ganesh Tea Stall", "Lakshmi Tiffin Centre", "Sai Vegetables", "Raju Juice Corner", "New Style Tailors",
               "Anna Idli Stall", "Kumar Xerox", "Shiva Flowers", "Mahalakshmi Stores", "Priya Beauty Parlour", "Om Paan Shop",
               "Rahul Mobile Repair", "Fresh Fish Stall", "Krishna Bakery", "Metro Chaat", "City Laundry", "Balaji Stores"]


def legit_small_shop(r):
    # very common in India: a small shop's QR on an ordinary (non-merchant) UPI ID, no merchant code, often round amounts
    shop = r.choice(SMALL_SHOPS)
    s = r.random()
    if s < 0.35:
        local = shop.split()[0].lower() + r.choice(["", "store", "stall", "shop", str(r.randint(1, 999))])
    elif s < 0.7:
        local = f"{r.choice('6789')}{r.randint(100000000, 999999999)}"
    else:
        local = f"{r.choice(FIRST)}{r.choice(['', str(r.randint(1, 999))])}"
    am = None if r.random() < 0.45 else (str(r.choice([50, 100, 200, 250, 300, 500, 1000, 1500, 2000, 3000, 5000, 10000]))
                                        if r.random() < 0.6 else amount(r, 20, 8000))
    return uri(pa=f"{local}@{r.choice(P2P_HANDLES)}", pn=shop if r.random() < 0.9 else "", am=am,
               tn=r.choice(["", "", "payment", "bill", "order"]))


def legit_rare_handle(r):
    return uri(pa=person_vpa(r, RARE_HANDLES), pn=rnd_person(r), am=None if r.random() < 0.5 else amount(r, 50, 3000))


def legit_merchant_static(r):
    s = r.random()
    if s < 0.35:
        pa = f"paytmqr{r.randint(10 ** 9, 10 ** 10)}@paytm"
    elif s < 0.6:
        pa = f"q{r.randint(10 ** 8, 10 ** 9)}@ybl"
    elif s < 0.8:
        pa = f"bharatpe.{r.randint(10 ** 7, 10 ** 8)}@fbpe"
    else:
        pa = f"{r.choice(SHOPS).split()[0].lower()}{r.choice(['store', 'shop', 'mart'])}{r.randint(1, 99)}@okaxis"
    return uri(pa=pa, pn=r.choice(SHOPS), mc=r.choice(MCC) if r.random() < 0.85 else "", tn="" if r.random() < 0.7 else "Payment")


def legit_merchant_dynamic(r):
    pa = r.choice([f"paytmqr{r.randint(10 ** 9, 10 ** 10)}@paytm", f"razorpay.{r.randint(10 ** 6, 10 ** 7)}@icici",
                   f"cf.{r.choice(SHOPS).split()[0].lower()}{r.randint(1, 999)}@axisbank", f"pinelabs.{r.randint(10 ** 5, 10 ** 6)}@hdfcbank"])
    return uri(pa=pa, pn=r.choice(SHOPS), am=amount(r, 20, 20000), mc=r.choice(MCC), tr=f"ORD{r.randint(10 ** 6, 10 ** 9)}",
               tn=r.choice(["Order payment", "Bill", "Invoice {}".format(r.randint(100, 9999)), ""]),
               sign=("MEUCIQ" + "".join(r.choice("abcdefXYZ0123456789") for _ in range(20))) if r.random() < 0.15 else "")


def legit_biller(r):
    # genuine government / utility collection QRs: official-sounding names, but registered merchant accounts
    name, local, h = r.choice([("BBMP Property Tax", "bbmp.propertytax", "sbi"), ("BESCOM Bill Payment", "bescom.billdesk", "hdfcbank"),
                               ("Municipal Water Board", "waterboard.collect", "icici"), ("Kerala Govt Treasury", "treasury.ker", "sbi"),
                               ("LIC Premium", "lic.premium", "axisbank"), ("Indian Railways IRCTC", "irctc.pay", "hdfcbank")])
    return uri(pa=f"{local}@{h}", pn=name, am=amount(r, 100, 15000), mc=r.choice(["9399", "9311", "4900", "6300", "4112"]),
               tr=f"TXN{r.randint(10 ** 7, 10 ** 10)}", tn=r.choice(["Bill payment", "Property tax", "Consumer no {}".format(r.randint(10 ** 5, 10 ** 7))]))


def legit_temple(r):
    return uri(pa=r.choice(["tirumala.donations@sbi", "iskcon.bangalore@icici", "gurudwara.seva@pnb", "cry.donate@hdfcbank",
                            "akshayapatra@axisbank"]), pn=r.choice(["TTD Donations", "ISKCON Temple", "Gurudwara Seva", "CRY Donations", "Akshaya Patra"]),
               mc=r.choice(["8398", "8661", ""]), am=None if r.random() < 0.6 else amount(r, 51, 5001))


def legit_family(r):   # large genuine transfer with a normal note
    return uri(pa=person_vpa(r), pn=rnd_person(r), am=amount(r, 10000, 90000, rounded=0.7),
               tn=r.choice(["rent", "college fees", "hospital bill", "wedding", "house deposit", "car emi"]))


def scam_refund_receive(r):
    am = amount(r, 999, 49999, ends99=0.5, rounded=0.3)
    return uri(pa=scam_vpa(r), pn=r.choice(IMPERSONATE + [rnd_person(r)]), am=am, tn=r.choice(RECEIVE_NOTES).format(am=am))


def scam_impersonation(r):
    return uri(pa=scam_vpa(r), pn=r.choice(IMPERSONATE), am=None if r.random() < 0.3 else amount(r, 499, 25000, ends99=0.4),
               tn=r.choice(["", "verification", "processing fee", "case closure", "pending bill", "security deposit"]))


def scam_kyc(r):
    return uri(pa=scam_vpa(r), pn=r.choice(["Paytm KYC Team", "SBI KYC Cell", "Bank KYC Update", rnd_person(r)]),
               am=amount(r, 10, 2999, ends99=0.4), tn=r.choice(KYC_NOTES))


def scam_prize(r):
    return uri(pa=scam_vpa(r), pn=r.choice(PRIZE_NAMES), am=amount(r, 1999, 25000, ends99=0.5),
               tn=r.choice(["prize claim fee", "lottery processing", "GST on prize", "winner registration", "tax on winning"]))


def scam_olx_army(r):
    action = "collect" if r.random() < 0.4 else "pay"
    return uri(action, pa=scam_vpa(r), pn=r.choice(ARMY_NAMES), am=amount(r, 2000, 30000, rounded=0.5),
               tn=r.choice(["security deposit", "advance for item", "army canteen", "refundable deposit", "verification amount"]))


def scam_autopay(r):
    action = r.choice(["mandate", "mandate", "autopay"])
    return uri(action, pa=scam_vpa(r), pn=r.choice(["Netflix", "Jio Recharge", "Amazon Prime", "Electricity Board", rnd_person(r)]),
               am=amount(r, 99, 9999, ends99=0.5), recur=r.choice(["MONTHLY", "WEEKLY", "DAILY"]),
               tn=r.choice(["subscription", "verify account", "KYC", "cashback activation"]))


def scam_collect(r):
    return uri("collect", pa=scam_vpa(r), pn=r.choice(IMPERSONATE + ARMY_NAMES + [rnd_person(r)]), am=amount(r, 500, 20000),
               tn=r.choice(RECEIVE_NOTES + ["approve to receive", ""]).format(am="5000"))


def scam_fake_merchant(r):
    return uri(pa=f"{r.choice(BRAND_LOCAL)}{r.choice(['', str(r.randint(1, 99))])}@{r.choice(P2P_HANDLES + RARE_HANDLES)}",
               pn=r.choice(IMPERSONATE), mc=r.choice(["0000", "", ""]), am=None if r.random() < 0.4 else amount(r, 99, 9999, ends99=0.5),
               tn=r.choice(["", "refund", "cashback", "offer"]))


def scam_link_note(r):
    tn = r.choice([f"call {r.choice('6789')}{r.randint(100000000, 999999999)} for refund",
                   f"visit bit.ly/{r.randint(1000, 99999)} to claim", f"details http://kyc-{r.randint(10, 999)}.xyz",
                   f"whatsapp {r.choice('6789')}{r.randint(100000000, 999999999)}", "check www.refund-status.online"])
    return uri(pa=scam_vpa(r), pn=r.choice(IMPERSONATE + [rnd_person(r)]), am=None if r.random() < 0.5 else amount(r, 99, 9999), tn=tn)


def scam_tampered(r):
    good = uri(pa=scam_vpa(r), pn=r.choice(SHOPS + IMPERSONATE), am=None if r.random() < 0.5 else amount(r, 100, 9999))
    t = r.random()
    if t < 0.25:
        return good.replace("upi://", r.choice(["upi:\\", "upi:/", "upi:", "upi//"]), 1)
    if t < 0.45:
        return good + f"&pa={scam_vpa(r)}"                         # second payee hidden at the end
    if t < 0.6:
        return good.replace("pa=", "pn=Shop&x=", 1)                 # payee removed
    if t < 0.75:
        return good.replace("@", "@@", 1)
    if t < 0.9:
        return good.replace("upi://pay", "upi://pya", 1)
    return good + "&am=1,00,000"


def scam_quiet(r):
    # "friend in trouble", task/investment scams: nothing in the QR itself looks wrong. Only history (if any) helps.
    return uri(pa=scam_vpa(r) if r.random() < 0.7 else person_vpa(r), pn=rnd_person(r) if r.random() < 0.8 else "",
               am=amount(r, 500, 50000, rounded=0.5), tn=r.choice(QUIET_NOTES))


SCENARIOS = [
    ("legit_p2p", 0, 1300, legit_p2p), ("legit_rare_handle", 0, 150, legit_rare_handle),
    ("legit_small_shop", 0, 450, legit_small_shop),
    ("legit_merchant_static", 0, 700, legit_merchant_static), ("legit_merchant_dynamic", 0, 500, legit_merchant_dynamic),
    ("legit_biller", 0, 200, legit_biller), ("legit_temple", 0, 120, legit_temple), ("legit_family_large", 0, 350, legit_family),
    ("scam_refund_receive", 1, 450, scam_refund_receive), ("scam_impersonation", 1, 400, scam_impersonation),
    ("scam_kyc_fee", 1, 200, scam_kyc), ("scam_prize", 1, 200, scam_prize), ("scam_olx_army", 1, 200, scam_olx_army),
    ("scam_autopay", 1, 150, scam_autopay), ("scam_collect", 1, 150, scam_collect),
    ("scam_fake_merchant", 1, 200, scam_fake_merchant), ("scam_link_in_note", 1, 150, scam_link_note),
    ("scam_tampered_qr", 1, 200, scam_tampered), ("scam_quiet", 1, 250, scam_quiet),
]
LABEL_NOISE = 0.02


def generate(seed: int = SEED) -> list[dict]:
    r = random.Random(seed)
    rows = []
    for name, label, n, gen in SCENARIOS:
        for _ in range(n):
            rep, got, disp, look = community(r, bool(label), quiet=name == "scam_quiet")
            y = label if r.random() >= LABEL_NOISE else 1 - label
            rows.append({"payload": gen(r), "label": y, "scenario": name, "reports": rep, "got_me": got, "disputes": disp,
                         "lookalike": int(look), "source": "synthetic-v1"})
    r.shuffle(rows)
    return rows


def main():
    rows = generate()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    n1 = sum(r["label"] for r in rows)
    print(f"wrote {len(rows)} rows ({n1} scam, {len(rows) - n1} legitimate) to {os.path.relpath(OUT)}")


if __name__ == "__main__":
    main()
