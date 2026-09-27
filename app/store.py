"""SQLite store: caches reports by SHA-256 and counts how often each file is seen.

Uploaded APK bytes are never stored — only the analysis report.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

DB_PATH = os.environ.get("APKXRAY_DB", os.path.join(os.path.dirname(__file__), "..", "data", "apkxray.db"))
_lock = threading.Lock()


def _conn():
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.execute("""CREATE TABLE IF NOT EXISTS reports(
        sha256 TEXT PRIMARY KEY, engine TEXT, level TEXT, score INTEGER, package TEXT, app_name TEXT,
        report TEXT, first_seen REAL, last_seen REAL, seen_count INTEGER DEFAULT 1)""")
    return c


_db = _conn()


def get(sha256: str, engine: str | None = None) -> dict | None:
    with _lock:
        row = _db.execute("SELECT report, engine, seen_count, first_seen FROM reports WHERE sha256=?", (sha256,)).fetchone()
    if not row or (engine and row[1] != engine):
        return None
    rep = json.loads(row[0])
    rep["community"] = {"seen_count": row[2], "first_seen": row[3]}
    return rep


def touch(sha256: str) -> None:
    with _lock:
        _db.execute("UPDATE reports SET seen_count=seen_count+1, last_seen=? WHERE sha256=?", (time.time(), sha256))
        _db.commit()


def put(rep: dict) -> None:
    sha = rep["file"]["sha256"]
    now = time.time()
    with _lock:
        prev = _db.execute("SELECT seen_count, first_seen FROM reports WHERE sha256=?", (sha,)).fetchone()
        seen, first = (prev[0] + 1, prev[1]) if prev else (1, now)
        _db.execute("INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (sha, rep["engine_version"], rep["verdict"]["level"], rep["verdict"]["score"],
                     rep["app"]["package"], rep["app"]["name"], json.dumps(rep), first, now, seen))
        _db.commit()
    rep["community"] = {"seen_count": seen, "first_seen": first}


def stats() -> dict:
    with _lock:
        total, scans = _db.execute("SELECT COUNT(*), COALESCE(SUM(seen_count),0) FROM reports").fetchone()
        by = dict(_db.execute("SELECT level, COUNT(*) FROM reports GROUP BY level").fetchall())
        top = _db.execute("""SELECT app_name, package, seen_count, score FROM reports
                             WHERE level IN ('danger','suspicious') ORDER BY seen_count DESC, last_seen DESC LIMIT 8""").fetchall()
    return {"unique_files": total, "total_scans": scans, "by_level": by,
            "top_threats": [{"app_name": a, "package": p, "seen_count": s, "score": sc} for a, p, s, sc in top]}


# ------------------------------------------------------------------ complaints
# A complaint contains victim details, so it is protected by a random access
# token (only its SHA-256 is stored) and deleted automatically after
# COMPLAINT_TTL_DAYS. The `indicators` table keeps only scammer identifiers
# (UPI ID, domain, phone, app hash) and counts, never victim data.

import hashlib as _hashlib
import hmac as _hmac

COMPLAINT_TTL_DAYS = int(os.environ.get("APKXRAY_COMPLAINT_TTL_DAYS", "30"))

with _lock:
    _db.execute("""CREATE TABLE IF NOT EXISTS complaints(
        ref TEXT PRIMARY KEY, token_hash TEXT NOT NULL, created REAL, expires REAL, source TEXT,
        lost_money INTEGER, amount REAL, body TEXT)""")
    _db.execute("""CREATE TABLE IF NOT EXISTS indicators(
        kind TEXT, value TEXT, ref TEXT, created REAL, PRIMARY KEY(kind, value, ref))""")
    _db.execute("CREATE INDEX IF NOT EXISTS idx_ind ON indicators(kind, value)")
    _db.commit()


def _th(token: str) -> str:
    return _hashlib.sha256(token.encode()).hexdigest()


def purge_expired() -> int:
    now = time.time()
    with _lock:
        cur = _db.execute("DELETE FROM complaints WHERE expires < ?", (now,))
        _db.commit()
        return cur.rowcount


def complaint_put(body: dict, token: str, countable: set[str]) -> None:
    now = time.time()
    inc = body["incident"]
    with _lock:
        _db.execute("INSERT INTO complaints VALUES (?,?,?,?,?,?,?,?)",
                    (body["ref"], _th(token), now, now + COMPLAINT_TTL_DAYS * 86400, body["scan"]["kind"],
                     int(bool(inc.get("lost_money"))), inc.get("amount"), json.dumps(body, ensure_ascii=False)))
        for s in body["suspects"]:
            if s["kind"] in countable:
                _db.execute("INSERT OR IGNORE INTO indicators VALUES (?,?,?,?)", (s["kind"], s["value"].lower(), body["ref"], now))
        _db.commit()


def complaint_get(ref: str, token: str) -> dict | None:
    with _lock:
        row = _db.execute("SELECT token_hash, body, expires FROM complaints WHERE ref=?", (ref,)).fetchone()
    if not row or row[2] < time.time() or not _hmac.compare_digest(row[0], _th(token or "")):
        return None
    body = json.loads(row[1])
    body["expires_at"] = row[2]
    return body


def complaint_delete(ref: str, token: str) -> bool:
    with _lock:
        row = _db.execute("SELECT token_hash FROM complaints WHERE ref=?", (ref,)).fetchone()
        if not row or not _hmac.compare_digest(row[0], _th(token or "")):
            return False
        _db.execute("DELETE FROM complaints WHERE ref=?", (ref,))
        _db.commit()   # indicator counts stay: they hold no personal data
        return True


def indicator_count(kind: str, value: str) -> int:
    if not value:
        return 0
    with _lock:
        (n,) = _db.execute("SELECT COUNT(DISTINCT ref) FROM indicators WHERE kind=? AND value=?", (kind, value.lower())).fetchone()
    return n


def complaint_stats() -> dict:
    with _lock:
        total, lost, amt = _db.execute(
            "SELECT COUNT(*), COALESCE(SUM(lost_money),0), COALESCE(SUM(amount),0) FROM complaints").fetchone()
        top = _db.execute("""SELECT kind, value, COUNT(DISTINCT ref) n FROM indicators WHERE kind IN ('upi','domain','phone','package')
                             GROUP BY kind, value ORDER BY n DESC LIMIT 10""").fetchall()
    return {"active_complaints": total, "with_money_lost": lost, "amount_reported": amt,
            "most_reported": [{"kind": k, "value": v, "reports": n} for k, v, n in top]}


# ------------------------------------------------------------------ payment screenshots
with _lock:
    _db.execute("CREATE TABLE IF NOT EXISTS shots(sha256 TEXT PRIMARY KEY, report TEXT, created REAL)")
    _db.execute("CREATE TABLE IF NOT EXISTS utr_seen(utr TEXT, sha256 TEXT, amount REAL, created REAL, phash TEXT, PRIMARY KEY(utr, sha256))")
    _db.execute("""CREATE TABLE IF NOT EXISTS shot_fp(sha256 TEXT PRIMARY KEY, utr TEXT, txn TEXT, txn_minute TEXT,
                   date_text TEXT, amount REAL, created REAL)""")
    _db.execute("CREATE INDEX IF NOT EXISTS idx_fp_min ON shot_fp(txn_minute)")
    _db.commit()


def shot_put(rep: dict) -> None:
    with _lock:
        _db.execute("INSERT OR REPLACE INTO shots VALUES (?,?,?)", (rep["id"], json.dumps(rep, ensure_ascii=False), time.time()))
        d = rep["details"]
        if d.get("utr"):
            _db.execute("INSERT OR IGNORE INTO utr_seen VALUES (?,?,?,?,?)", (d["utr"], rep["id"], d.get("amount"), time.time(), rep["file"].get("phash")))
        fp = d.get("fingerprint") or {}
        if fp.get("utr") or fp.get("txn"):
            txn = fp.get("txn") or ""
            _db.execute("INSERT OR REPLACE INTO shot_fp VALUES (?,?,?,?,?,?,?)",
                        (rep["id"], fp.get("utr"), txn, txn[:11] if txn else None, fp.get("date"), fp.get("amount"), time.time()))
        _db.commit()


def shot_get(sha: str) -> dict | None:
    with _lock:
        row = _db.execute("SELECT report FROM shots WHERE sha256=?", (sha,)).fetchone()
    return json.loads(row[0]) if row else None


def utr_seen_elsewhere(utr: str, sha: str, phash: str | None = None, amount: float | None = None) -> dict | None:
    """Has this reference number appeared on a *different-looking* image before?
    The same screenshot forwarded again (recompressed = new file hash) is not counted."""
    from .screenshot.analyzer import hamming
    with _lock:
        rows = _db.execute("SELECT amount, phash, sha256 FROM utr_seen WHERE utr=? AND sha256<>? ORDER BY created", (utr, sha)).fetchall()
    # Same-looking image with the same amount = the same receipt forwarded again, not reuse.
    rows = [r for r in rows if not (phash and r[1] and hamming(phash, r[1]) <= 24 and (amount is None or r[0] is None or abs(r[0] - amount) < 0.01))]
    if not rows:
        return None
    return {"count": len(rows), "amount": rows[0][0], "other_score": min(_own_score(r[2]) for r in rows)}


def _own_score(sha: str) -> int:
    """Score a stored screenshot earned from its OWN pixels/text, before it was compared with other screenshots.
    Used to decide which of two versions of the same receipt is the edited one."""
    rep = shot_get(sha)
    if not rep:
        return 0
    d = rep.get("details") or {}
    return int(d["own_score"]) if d.get("own_score") is not None else int(rep.get("verdict", {}).get("score", 0))


def _digit_diff(a: str, b: str) -> int:
    return sum(x != y for x, y in zip(a, b)) + abs(len(a) - len(b))


def similar_receipts(fp: dict, sha: str) -> dict | None:
    """Another receipt for the same payment moment (same transaction-ID minute or same printed date/time) whose
    reference numbers differ by only a few digits but whose amount is different: the signature of an edited copy."""
    amt = fp.get("amount")
    with _lock:
        rows = _db.execute("SELECT utr, txn, date_text, amount, sha256 FROM shot_fp WHERE sha256<>? ORDER BY created DESC LIMIT 5000", (sha,)).fetchall()
    for utr, txn, date_text, amount, other in rows:
        if amt is None or amount is None or abs(amount - amt) < 0.01:
            continue
        same_moment = bool((fp.get("txn") and txn and fp["txn"][:11] == txn[:11]) or (fp.get("date") and date_text and fp["date"] == date_text))
        near_utr = bool(fp.get("utr") and utr and len(utr) == len(fp["utr"]) and 0 < _digit_diff(utr, fp["utr"]) <= 3)
        near_txn = bool(fp.get("txn") and txn and len(txn) == len(fp["txn"]) and 0 < _digit_diff(txn, fp["txn"]) <= 6)
        if same_moment and (near_utr or near_txn):
            ev = [f"Other receipt: ₹{amount:,.2f}" + (f", reference {utr}" if utr else ""), f"This one: ₹{amt:,.2f}" + (f", reference {fp['utr']}" if fp.get("utr") else "")]
            if txn and fp.get("txn"):
                ev.append(f"Same payment minute in transaction IDs: {txn[:11]}…")
            return {"evidence": ev, "other_score": _own_score(other), "other_amount": amount}
    return None


# ------------------------------------------------------------------ one-tap scam reports ("It got me" / "It's fake")
# One row per (thing, person). `voter` is a salted hash of the browser/app's random id + network, never an IP.
with _lock:
    _db.execute("""CREATE TABLE IF NOT EXISTS votes(kind TEXT, value TEXT, voter TEXT, reason TEXT, created REAL,
                   PRIMARY KEY(kind, value, voter))""")
    _db.execute("CREATE INDEX IF NOT EXISTS idx_votes ON votes(kind, value)")
    _db.commit()


# `net` = salted hash of the reporter's network (IP /24 or /48). A public listing needs reports from several
# different networks, so one person inventing many browser ids can't push a rival's shop onto the public page.
with _lock:
    if "net" not in [r[1] for r in _db.execute("PRAGMA table_info(votes)").fetchall()]:
        _db.execute("ALTER TABLE votes ADD COLUMN net TEXT")
        _db.commit()

REPORT_REASONS = ("got_me", "fake")


def vote_add(indicators: list[tuple[str, str]], voter: str, reason: str, net: str | None = None, when: float | None = None) -> bool:
    """Returns False if this person had already reported (or disputed) it. A person can change their mind:
    a dispute ("not_scam") replaces their earlier report and vice versa."""
    now, new = when or time.time(), False
    with _lock:
        for kind, value in indicators:
            prev = _db.execute("SELECT reason FROM votes WHERE kind=? AND value=? AND voter=?", (kind, value.lower(), voter)).fetchone()
            if prev and prev[0] == reason:
                continue
            if prev and not ((prev[0] == "not_scam") != (reason == "not_scam")):
                continue  # got_me <-> fake: same side, keep the first answer
            _db.execute("INSERT OR REPLACE INTO votes(kind, value, voter, reason, created, net) VALUES (?,?,?,?,?,?)",
                        (kind, value.lower(), voter, reason, now, net))
            new = True
        _db.commit()
    return new


def vote_counts(kind: str, value: str) -> dict:
    with _lock:
        rows = _db.execute("SELECT reason, COUNT(*) FROM votes WHERE kind=? AND value=? GROUP BY reason", (kind, value.lower())).fetchall()
        (nets,) = _db.execute("SELECT COUNT(DISTINCT COALESCE(net, voter)) FROM votes WHERE kind=? AND value=? AND reason<>'not_scam'",
                              (kind, value.lower())).fetchone()
    d = dict(rows)
    return {"got_me": d.get("got_me", 0), "fake": d.get("fake", 0), "total": d.get("got_me", 0) + d.get("fake", 0),
            "disputes": d.get("not_scam", 0), "networks": nets}


def has_voted(indicators: list[tuple[str, str]], voter: str) -> bool:
    with _lock:
        for kind, value in indicators:
            if _db.execute("SELECT 1 FROM votes WHERE kind=? AND value=? AND voter=?", (kind, value.lower(), voter)).fetchone():
                return True
    return False


# ------------------------------------------------------------------ anonymous check counters (for the trends page)
# Only day / kind / verdict level / scam type are counted. No identifiers, no IPs, no content.
with _lock:
    _db.execute("""CREATE TABLE IF NOT EXISTS events(day TEXT, kind TEXT, level TEXT, category TEXT, n INTEGER,
                   PRIMARY KEY(day, kind, level, category))""")
    _db.execute("""CREATE TABLE IF NOT EXISTS moderation(kind TEXT, value TEXT, status TEXT, note TEXT, updated REAL,
                   PRIMARY KEY(kind, value))""")
    _db.commit()


def event_add(kind: str, level: str, category: str | None, day: str | None = None, n: int = 1) -> None:
    day = day or time.strftime("%Y-%m-%d", time.localtime())
    with _lock:
        _db.execute("""INSERT INTO events VALUES (?,?,?,?,?) ON CONFLICT(day, kind, level, category)
                       DO UPDATE SET n = n + excluded.n""", (day, kind, level, category or "", n))
        _db.commit()


def events_since(day: str) -> list[tuple]:
    with _lock:
        return _db.execute("SELECT day, kind, level, category, n FROM events WHERE day >= ?", (day,)).fetchall()


def report_rows(since: float) -> list[tuple]:
    """(created, kind, value, reason) for one-tap reports and complaints since a time."""
    with _lock:
        v = _db.execute("SELECT created, kind, value, reason FROM votes WHERE created >= ?", (since,)).fetchall()
        c = _db.execute("SELECT created, kind, value, 'complaint' FROM indicators WHERE created >= ?", (since,)).fetchall()
    return v + c


def reported_values(kinds: tuple[str, ...]) -> list[dict]:
    """Every reported identifier of these kinds with its counts (the trends module decides what is public)."""
    q = ",".join("?" * len(kinds))
    with _lock:
        votes = _db.execute(f"""SELECT kind, value,
                SUM(reason='got_me'), SUM(reason='fake'), SUM(reason='not_scam'),
                COUNT(DISTINCT CASE WHEN reason<>'not_scam' THEN COALESCE(net, voter) END),
                MIN(created), MAX(created), SUM(voter LIKE 'demo:%')
                FROM votes WHERE kind IN ({q}) GROUP BY kind, value""", kinds).fetchall()
        comp = _db.execute(f"""SELECT kind, value, COUNT(DISTINCT ref), MIN(created), MAX(created)
                FROM indicators WHERE kind IN ({q}) GROUP BY kind, value""", kinds).fetchall()
        mod = {(k, v): (st, note) for k, v, st, note in _db.execute("SELECT kind, value, status, note FROM moderation").fetchall()}
    out: dict[tuple, dict] = {}
    for k, v, gm, fk, ns, nets, first, last, demo in votes:
        out[(k, v)] = {"kind": k, "value": v, "got_me": gm or 0, "fake": fk or 0, "disputes": ns or 0, "networks": nets or 0,
                       "complaints": 0, "first": first, "last": last, "demo": bool(demo)}
    for k, v, n, first, last in comp:
        e = out.setdefault((k, v), {"kind": k, "value": v, "got_me": 0, "fake": 0, "disputes": 0, "networks": 0,
                                    "complaints": 0, "first": first, "last": last, "demo": False})
        e["complaints"] = n
        e["networks"] += n            # each filed complaint is a separate, deliberate report
        e["first"] = min(e["first"] or first, first)
        e["last"] = max(e["last"] or last, last)
    for key, e in out.items():
        e["reports"] = e["got_me"] + e["fake"] + e["complaints"]
        e["status"], e["note"] = mod.get(key, (None, None))
    return list(out.values())


def moderate(kind: str, value: str, status: str | None, note: str = "") -> None:
    with _lock:
        if status:
            _db.execute("INSERT OR REPLACE INTO moderation VALUES (?,?,?,?,?)", (kind, value.lower(), status, note[:300], time.time()))
        else:
            _db.execute("DELETE FROM moderation WHERE kind=? AND value=?", (kind, value.lower()))
        _db.commit()


def moderation_status(kind: str, value: str) -> str | None:
    with _lock:
        row = _db.execute("SELECT status FROM moderation WHERE kind=? AND value=?", (kind, value.lower())).fetchone()
    return row[0] if row else None
