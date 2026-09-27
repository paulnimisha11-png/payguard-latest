"""Fill the trends page with clearly-labelled DEMO data for a presentation, or remove it again.

    python scripts/seed_demo.py            # add 14 days of demo checks + demo reports
    python scripts/seed_demo.py --remove   # delete every demo report (demo check counts are subtracted too)

Demo reports use obviously fictional identifiers (…demo@ybl, *.example websites) and the trends page shows a
"includes demo data" banner while any are present. Never run this on a server real people use.
"""
import datetime as dt
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import store  # noqa: E402

random.seed(7)
DAYS = 14
# kind, level, category, typical per-day count, growth factor per day (rising types grow)
MIX = [
    ("msg", "danger", "electricity", 6, 1.12), ("msg", "danger", "kyc_bank", 8, 1.0), ("msg", "danger", "parcel", 4, 1.03),
    ("msg", "suspicious", "job_task", 5, 1.08), ("msg", "danger", "digital_arrest", 2, 1.15), ("msg", "danger", "refund_prize", 3, 0.97),
    ("qr", "danger", "qr_receive_lure", 5, 1.02), ("qr", "danger", "phishing_link", 3, 1.0), ("shot", "danger", "fake_screenshot", 4, 1.05),
    ("apk", "danger", "banking_trojan", 2, 1.0), ("msg", "low", "", 25, 1.02), ("qr", "low", "", 40, 1.02), ("shot", "low", "", 10, 1.0),
    ("apk", "low", "", 3, 1.0),
]
REPORTS = [("upi", "sbi.refund.demo@ybl", 14, 5), ("upi", "kyc.helpdesk.demo@okaxis", 9, 2), ("upi", "prize.claim.demo@paytm", 6, 1),
           ("phone", "9000000001", 11, 3), ("phone", "9000000002", 7, 0), ("domain", "sbi-kyc-update.example", 12, 4),
           ("domain", "indiapost-redeliver.example", 8, 1), ("domain", "fastag-kyc.example", 4, 0),
           ("upi", "newshop.demo@ybl", 2, 0)]  # the last one stays under the public threshold ("pending review")


def seed():
    today = dt.date.today()
    for i in range(DAYS):
        day = (today - dt.timedelta(days=DAYS - 1 - i)).isoformat()
        for kind, level, cat, base, growth in MIX:
            n = max(0, round(base * growth ** i * random.uniform(0.7, 1.3)))
            if n:
                store.event_add(kind, level, cat or None, day=day, n=n)
    now = time.time()
    for kind, value, n, got_me in REPORTS:
        for j in range(n):
            when = now - random.uniform(0, DAYS * 86400)
            store.vote_add([(kind, value)], f"demo:{kind}:{value}:{j}", "got_me" if j < got_me else "fake", f"demo-net-{j}", when=when)
    print("Demo data added. Remove it with: python scripts/seed_demo.py --remove")


def remove():
    with store._lock:
        n = store._db.execute("DELETE FROM votes WHERE voter LIKE 'demo:%'").rowcount
        store._db.commit()
    # subtract the demo check counts: re-run the same random sequence and decrement
    random.seed(7)
    today = dt.date.today()
    for i in range(DAYS):
        day = (today - dt.timedelta(days=DAYS - 1 - i)).isoformat()
        for kind, level, cat, base, growth in MIX:
            k = max(0, round(base * growth ** i * random.uniform(0.7, 1.3)))
            if k:
                with store._lock:
                    store._db.execute("UPDATE events SET n = MAX(0, n - ?) WHERE day=? AND kind=? AND level=? AND category=?",
                                      (k, day, kind, level, cat))
                    store._db.commit()
    print(f"Removed {n} demo reports and the demo check counts (only exact if run on the same day as seeding).")


if __name__ == "__main__":
    remove() if "--remove" in sys.argv else seed()
