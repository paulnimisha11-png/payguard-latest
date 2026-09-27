"""APK X-Ray web server (FastAPI).

Endpoints
  POST /api/scan               multipart 'file' -> full report JSON
  GET  /api/report/{sha256}    cached report
  POST /api/explain            {"sha256": ..., "lang": "en|hi|kn"} -> family message
  GET  /api/stats              aggregate counters + most-seen threats
  GET  /api/health
  POST /api/complaints          scan + victim answers -> ready-to-file complaint (+ one-time access token)
  GET  /api/complaints/{ref}    ?token=  -> complaint
  GET  /api/complaints/{ref}/pdf ?token= -> evidence PDF
  DELETE /api/complaints/{ref}  ?token=  -> erase victim data
  GET  /api/indicators          ?kind=&value= -> how many complaints name this UPI ID / domain / phone / app
  GET  /                       web app;  /r/{sha256} -> shareable report page
"""
from __future__ import annotations

import asyncio
import hashlib
import mimetypes
import os
import re
import shutil
import tempfile
import time
from collections import defaultdict, deque
from concurrent.futures import ProcessPoolExecutor

import httpx
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import store
from .analyzer import ENGINE_VERSION, AnalysisError, analyze_apk
from .explain import llm_message, template_message
from .qr.analyzer import analyze_payload, decode_qr_image
from .complaints import builder as cb
from .screenshot.analyzer import analyze_screenshot
from .message import analyze_message
from . import family, trends
from .complaints.community import apply_reports
from .complaints.pdf import render as render_pdf

MAX_UPLOAD = int(os.environ.get("APKXRAY_MAX_MB", "150")) * 1024 * 1024
SCAN_TIMEOUT = int(os.environ.get("APKXRAY_TIMEOUT", "120"))
RATE_PER_MIN = int(os.environ.get("APKXRAY_RATE_PER_MIN", "12"))
VT_KEY = os.environ.get("VT_API_KEY")
STATIC = os.path.join(os.path.dirname(__file__), "..", "static")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")

mimetypes.add_type("application/manifest+json", ".webmanifest")
mimetypes.add_type("text/javascript", ".js")
app = FastAPI(title="APK X-Ray", version=ENGINE_VERSION)


@app.on_event("startup")
async def _startup_checks():
    from .screenshot.analyzer import HAS_OCR, OCR_ENGINE
    if not HAS_OCR:
        print("\n  WARNING: no OCR engine found - payment screenshot checks will be incomplete."
              "\n  Fix: pip install -r requirements.txt   (installs rapidocr_onnxruntime)\n", flush=True)
    else:
        print(f"  Screenshot OCR engine: {OCR_ENGINE}", flush=True)
pool = ProcessPoolExecutor(max_workers=int(os.environ.get("APKXRAY_WORKERS", "2")))
_hits: dict[str, deque] = defaultdict(deque)


def _client_ip(request: Request) -> str:
    # Behind a proxy / tunnel every request comes from 127.0.0.1; use the forwarded client address instead.
    # Only trust the header when the direct peer is a local/private proxy, so clients can't spoof it.
    peer = request.client.host if request.client else "?"
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        try:
            import ipaddress
            if ipaddress.ip_address(peer).is_private or ipaddress.ip_address(peer).is_loopback:
                return fwd.split(",")[0].strip()
        except ValueError:
            pass
    return peer


def _rate_limit(ip: str) -> None:
    now, q = time.time(), _hits[ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= RATE_PER_MIN:
        raise HTTPException(429, "Too many scans from your network. Please wait a minute.")
    q.append(now)


def _worker(path: str, name: str, workdir: str) -> dict:
    return analyze_apk(path, name, workdir=workdir)


async def _virustotal(sha256: str) -> dict | None:
    if not VT_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": VT_KEY})
        if r.status_code == 404:
            return {"known": False}
        r.raise_for_status()
        st = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"known": True, "malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
                "engines": sum(st.values())}
    except Exception:
        return None


def _after_check(request: Request, rep: dict) -> dict:
    """Every check: add community reports, count it for the trends page, alert family guardians."""
    rep = apply_reports(rep)
    trends.record(rep)
    did = family.authenticate(request.headers.get("x-pg-device"))
    if did:
        try:
            rep["family_alerted"] = family.alert_for_scan(did, rep)
        except Exception:
            rep["family_alerted"] = 0
    return rep


@app.post("/api/scan")
async def scan(request: Request, file: UploadFile = File(...)):
    _rate_limit(_client_ip(request))
    name = os.path.basename(file.filename or "upload.apk")[:200]
    workdir = tempfile.mkdtemp(prefix="apkx_")
    path = os.path.join(workdir, "upload.bin")
    sha, size = hashlib.sha256(), 0
    try:
        with open(path, "wb") as out:
            while chunk := await file.read(1 << 20):
                size += len(chunk)
                if size > MAX_UPLOAD:
                    raise HTTPException(413, f"File is larger than {MAX_UPLOAD // (1024 * 1024)} MB.")
                sha.update(chunk)
                out.write(chunk)
        if size == 0:
            raise HTTPException(400, "The file is empty.")
        digest = sha.hexdigest()

        cached = store.get(digest, ENGINE_VERSION)
        if cached:
            store.touch(digest)
            cached["community"]["seen_count"] += 1
            cached["cached"] = True
            cached["file"]["name"] = name
            return _after_check(request, cached)

        loop = asyncio.get_running_loop()
        try:
            rep = await asyncio.wait_for(loop.run_in_executor(pool, _worker, path, name, workdir), SCAN_TIMEOUT)
        except asyncio.TimeoutError:
            raise HTTPException(504, "Analysis took too long. The file may be unusually large or deliberately malformed.")
        except AnalysisError as e:
            raise HTTPException(422, str(e))
        except Exception as e:
            if type(e).__name__ == "AnalysisError":  # raised inside the worker process
                raise HTTPException(422, str(e))
            raise HTTPException(422, f"Could not analyse this file: {type(e).__name__}")

        rep["external"] = {"virustotal": await _virustotal(digest),
                           "virustotal_url": f"https://www.virustotal.com/gui/file/{digest}"}
        store.put(rep)
        rep["cached"] = False
        return _after_check(request, rep)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


@app.get("/api/report/{sha256}")
async def report(sha256: str):
    sha256 = sha256.lower()
    if not SHA_RE.match(sha256):
        raise HTTPException(400, "Invalid SHA-256")
    rep = store.get(sha256)
    if not rep:
        raise HTTPException(404, "No report for this file yet. Upload it to scan.")
    return apply_reports(rep)


class ExplainReq(BaseModel):
    sha256: str
    lang: str = "en"


@app.post("/api/explain")
async def explain(req: ExplainReq):
    rep = store.get(req.sha256.lower())
    if not rep:
        raise HTTPException(404, "Unknown report")
    lang = req.lang if req.lang in ("en", "hi", "kn", "ta", "te", "mr", "bn") else "en"
    text = await llm_message(rep, lang)
    return {"message": text or template_message(rep, lang), "source": "llm" if text else "template"}


# ------------------------------------------------------------------ QR / UPI (PayPause)

MAX_IMAGE = 12 * 1024 * 1024


class QRText(BaseModel):
    text: str


@app.post("/api/qr/image")
async def qr_image(request: Request, file: UploadFile = File(...)):
    _rate_limit(_client_ip(request))
    data = await file.read(MAX_IMAGE + 1)
    if len(data) > MAX_IMAGE:
        raise HTTPException(413, "Image is larger than 12 MB.")
    loop = asyncio.get_running_loop()
    try:
        codes = await asyncio.wait_for(loop.run_in_executor(None, decode_qr_image, data), 20)
    except ValueError as e:
        raise HTTPException(422, str(e))
    except asyncio.TimeoutError:
        raise HTTPException(504, "Decoding the image took too long.")
    if not codes:
        raise HTTPException(422, "No QR code found in this image. Try a sharper, closer screenshot with the whole QR visible.")
    reports = [apply_reports(analyze_payload(c)) for c in codes[:5]]
    reports.sort(key=lambda r: -r["verdict"]["score"])  # worst first
    worst = _after_check(request, reports[0])
    return {**worst, "all_codes": len(codes), "others": reports[1:]}


@app.post("/api/qr/text")
async def qr_text(request: Request, req: QRText):
    try:
        return _after_check(request, analyze_payload(req.text))
    except ValueError as e:
        raise HTTPException(422, str(e))


# ------------------------------------------------------------------ scam messages (SMS / WhatsApp / email)

class MessageIn(BaseModel):
    text: str


@app.post("/api/message")
async def check_message(request: Request, m: MessageIn):
    _rate_limit(_client_ip(request))
    if len(m.text or "") > 20000:
        raise HTTPException(422, "That message is too long. Paste just the suspicious message.")
    try:
        rep = analyze_message(m.text)
    except ValueError as e:
        raise HTTPException(422, str(e))
    return _after_check(request, rep)


# ------------------------------------------------------------------ payment screenshots

@app.post("/api/screenshot")
async def screenshot(request: Request, file: UploadFile = File(...), expected_amount: str = Form(""), bank_sms: str = Form("")):
    _rate_limit(_client_ip(request))
    data = await file.read(MAX_IMAGE + 1)
    if len(data) > MAX_IMAGE:
        raise HTTPException(413, "Image is larger than 12 MB.")
    if not data:
        raise HTTPException(400, "The file is empty.")
    exp = None
    if expected_amount.strip():
        try:
            exp = float(expected_amount.replace(",", "").replace("₹", "").strip())
            if not (0 < exp < 100_000_000):
                raise ValueError
        except ValueError:
            raise HTTPException(422, "Expected amount must be a number, like 2450.")
    name = os.path.basename(file.filename or "screenshot.png")[:200]
    loop = asyncio.get_running_loop()
    try:
        rep = await asyncio.wait_for(loop.run_in_executor(None, lambda: analyze_screenshot(data, name, exp, store.utr_seen_elsewhere, store.similar_receipts, bank_sms[:2000] or None)), 60)
    except ValueError as e:
        raise HTTPException(422, str(e))
    except asyncio.TimeoutError:
        raise HTTPException(504, "Checking the image took too long.")
    store.shot_put(rep)
    return _after_check(request, rep)


@app.get("/api/screenshot/{sha256}")
async def screenshot_report(sha256: str):
    sha256 = sha256.lower()
    if not SHA_RE.match(sha256):
        raise HTTPException(400, "Invalid SHA-256")
    rep = store.shot_get(sha256)
    if not rep:
        raise HTTPException(404, "No check for this screenshot yet. Upload it to check.")
    return apply_reports(rep)


# ------------------------------------------------------------------ Android app

APK_PATH = os.environ.get("APKXRAY_APP_APK", os.path.join(os.path.dirname(__file__), "..", "downloads", "payguard.apk"))


APK_URL = os.environ.get("APKXRAY_APP_APK_URL", "")  # e.g. the GitHub release asset built by Actions


@app.get("/download/payguard.apk")
async def download_app():
    if not os.path.isfile(APK_PATH):
        if APK_URL:
            from fastapi.responses import RedirectResponse
            return RedirectResponse(APK_URL, status_code=302)
        raise HTTPException(404, "The Android app hasn't been uploaded to this server yet. Put the built APK at downloads/payguard.apk.")
    return FileResponse(APK_PATH, media_type="application/vnd.android.package-archive", filename="PayGuard.apk")


@app.get("/api/app/connect.png")
async def connect_qr(request: Request):
    """QR the Android app scans to learn this server's address (payguard://connect?server=...)."""
    import io
    from urllib.parse import quote
    import qrcode
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    base = f"{proto}://{host}"
    img = qrcode.make(f"payguard://connect?server={quote(base, safe='')}", box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return Response(buf.getvalue(), media_type="image/png", headers={"Cache-Control": "no-store", "X-PayGuard-Server": base})


# ------------------------------------------------------------------ one-tap scam reports

class QuickReport(BaseModel):
    kind: str                      # "apk" | "qr" | "shot" | "msg"
    id: str | None = None          # sha256 of the scanned app / screenshot
    payload: str | None = None     # QR / link content, or the message text
    reason: str = "fake"           # "got_me" (I lost money) | "fake" (I spotted it) | "not_scam" (I know it's genuine)
    voter: str = ""                # random id kept by the browser / app


def _scan_for(kind: str, id_: str | None, payload: str | None) -> dict:
    if kind == "msg":
        try:
            return analyze_message((payload or "")[:20000])
        except ValueError as e:
            raise HTTPException(422, str(e))
    if kind == "qr":
        if not payload or not payload.strip():
            raise HTTPException(422, "Missing QR / link content.")
        try:
            return analyze_payload(payload)   # re-derive on the server; never trust identifiers sent by the client
        except ValueError as e:
            raise HTTPException(422, str(e))
    if not id_ or not SHA_RE.match(id_.lower()):
        raise HTTPException(422, "Missing scan reference.")
    rep = store.get(id_.lower()) if kind == "apk" else store.shot_get(id_.lower()) if kind == "shot" else None
    if not rep:
        raise HTTPException(404, "That scan isn't on this server any more. Scan it again, then report it.")
    return rep


def _net_hash(request: Request) -> str:
    """Salted hash of the reporter's network (/24 for IPv4, /48 for IPv6): lets the trends page require reports
    from several different networks before listing anything publicly. The IP itself is never stored."""
    import ipaddress
    salt = os.environ.get("APKXRAY_VOTE_SALT", "payguard-votes")
    ip = _client_ip(request)
    try:
        a = ipaddress.ip_address(ip)
        net = str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 48}", strict=False))
    except ValueError:
        net = ip
    return hashlib.sha256(f"{salt}|net|{net}".encode()).hexdigest()[:32]


def _voter_hash(request: Request, voter: str) -> str:
    salt = os.environ.get("APKXRAY_VOTE_SALT", "payguard-votes")
    raw = (voter or "")[:64] or _client_ip(request)
    return hashlib.sha256(f"{salt}|{raw}".encode()).hexdigest()


@app.post("/api/reports")
async def quick_report(request: Request, r: QuickReport):
    _rate_limit(_client_ip(request))
    if r.kind not in ("apk", "qr", "shot", "msg") or r.reason not in ("got_me", "fake", "not_scam"):
        raise HTTPException(422, "Unknown report type.")
    from .complaints.community import community_counts, scan_indicators
    rep = _scan_for(r.kind, r.id, r.payload)
    inds = [(k, v) for k, v, _ in scan_indicators(rep)]
    if not inds:
        raise HTTPException(422, "This points to an official website, so it can't be reported here. Report the message that sent you to it instead.")
    new = store.vote_add(inds, _voter_hash(request, r.voter), r.reason, _net_hash(request))
    trends.invalidate()
    cc = community_counts(rep)
    return {"recorded": new, "already": not new, **{k: cc[k] for k in ("reports", "got_me", "fake", "complaints", "disputes")}}


@app.get("/api/qr/render.png")
async def render_qr(data: str):
    """PNG of a QR code (used to show a UPI payment QR on desktop so it can be scanned with a phone)."""
    import io
    import qrcode
    if not data or len(data) > 1500:
        raise HTTPException(422, "Nothing to encode.")
    buf = io.BytesIO()
    qrcode.make(data, box_size=8, border=2).save(buf, "PNG")
    return Response(buf.getvalue(), media_type="image/png", headers={"Cache-Control": "no-store"})


# ------------------------------------------------------------------ complaints

REF_RE = re.compile(r"^PG-\d{6}-[A-Z2-9]{6}$")


def _load_complaint(ref: str, token: str) -> dict:
    if not REF_RE.match(ref or ""):
        raise HTTPException(400, "Invalid complaint reference.")
    body = store.complaint_get(ref, token)
    if not body:
        raise HTTPException(404, "Complaint not found, expired, or the access link is wrong.")
    return body


@app.post("/api/complaints", status_code=201)
async def create_complaint(request: Request, c: cb.ComplaintIn):
    _rate_limit(_client_ip(request))
    store.purge_expired()
    # Re-derive the evidence on the server; never trust findings sent by the browser.
    if c.source == "apk":
        scan = store.get(c.sha256.lower())
        if not scan:
            raise HTTPException(404, "This app scan is no longer available. Please scan the file again, then report it.")
    elif c.source == "screenshot":
        scan = store.shot_get(c.sha256.lower())
        if not scan:
            raise HTTPException(404, "This screenshot check is no longer available. Please check the screenshot again, then report it.")
    elif c.source == "message":
        try:
            scan = analyze_message(c.payload)
        except ValueError as e:
            raise HTTPException(422, str(e))
    else:
        try:
            scan = analyze_payload(c.payload)
        except ValueError as e:
            raise HTTPException(422, str(e))
    ref, token = cb.new_ref(), cb.new_token()
    body = cb.build(ref, c.source, scan, c)
    store.complaint_put(body, token, cb.COUNTABLE)
    body = store.complaint_get(ref, token)
    return {**body, "token": token}


@app.get("/api/complaints/{ref}")
async def get_complaint(ref: str, token: str = ""):
    return _load_complaint(ref, token)


@app.get("/api/complaints/{ref}/pdf")
async def complaint_pdf(ref: str, token: str = ""):
    body = _load_complaint(ref, token)
    loop = asyncio.get_running_loop()
    pdf = await loop.run_in_executor(None, render_pdf, body)
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="PayGuard-{ref}.pdf"', "Cache-Control": "no-store"})


@app.delete("/api/complaints/{ref}")
async def delete_complaint(ref: str, token: str = ""):
    if not REF_RE.match(ref or "") or not store.complaint_delete(ref, token):
        raise HTTPException(404, "Complaint not found or the access link is wrong.")
    return {"deleted": ref}


@app.get("/api/indicators")
async def indicators(kind: str, value: str):
    if kind not in cb.COUNTABLE:
        raise HTTPException(400, "Unknown indicator kind.")
    v = cb.norm_phone(value) if kind == "phone" else value.strip().lower()
    return {"kind": kind, "value": v, "reports": store.indicator_count(kind, v)}


@app.get("/api/stats")
async def stats():
    return {**store.stats(), "complaints": store.complaint_stats()}


@app.get("/api/health")
async def health():
    from .screenshot.analyzer import HAS_OCR, OCR_ENGINE
    return {"ok": True, "engine": ENGINE_VERSION, "llm": bool(os.environ.get("ANTHROPIC_API_KEY")),
            "virustotal": bool(VT_KEY), "ocr": HAS_OCR, "ocr_engine": OCR_ENGINE, "android_apk": os.path.isfile(APK_PATH) or bool(APK_URL), "service": "payguard",
            "push_recent": [f"{h}:{st}" for h, st in family.PUSH_LOG[-5:]]}


# ------------------------------------------------------------------ trends (public)

@app.get("/api/trends")
async def get_trends():
    return JSONResponse(trends.build(), headers={"Cache-Control": "public, max-age=30"})


@app.get("/api/lookup")
async def lookup(request: Request, q: str = ""):
    _rate_limit(_client_ip(request))
    try:
        return trends.lookup(q[:200])
    except ValueError as e:
        raise HTTPException(422, str(e))


ADMIN_TOKEN = os.environ.get("APKXRAY_ADMIN_TOKEN", "")


def _admin(request: Request) -> None:
    import hmac as _hm
    tok = request.headers.get("x-admin-token", "")
    if not ADMIN_TOKEN or not _hm.compare_digest(tok, ADMIN_TOKEN):
        raise HTTPException(403, "Admin token required (set APKXRAY_ADMIN_TOKEN on the server).")


@app.get("/api/admin/review")
async def admin_review(request: Request):
    _admin(request)
    rows = store.reported_values(trends.PUBLIC_KINDS)
    for e in rows:
        e["public"] = trends.is_public(e)
    rows.sort(key=lambda e: (e["public"], -e["reports"]))
    return {"public_min": trends.PUBLIC_MIN, "entries": rows}


class Moderate(BaseModel):
    kind: str
    value: str
    status: str | None = None     # approved | hidden | cleared | None (reset)
    note: str = ""


@app.post("/api/admin/moderate")
async def admin_moderate(request: Request, m: Moderate):
    _admin(request)
    if m.kind not in trends.PUBLIC_KINDS or m.status not in (None, "approved", "hidden", "cleared"):
        raise HTTPException(422, "Unknown kind or status.")
    store.moderate(m.kind, m.value, m.status, m.note)
    trends.invalidate()
    return {"ok": True}


# ------------------------------------------------------------------ family guardian mode

def _dev(request: Request) -> str:
    did = family.authenticate(request.headers.get("x-pg-device"))
    if not did:
        raise HTTPException(401, "This phone isn't set up for family protection yet.")
    return did


def _fam(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except family.FamilyError as e:
        raise HTTPException(e.status, e.msg)


class DeviceIn(BaseModel):
    name: str | None = None
    phone: str | None = None
    platform: str | None = None
    lang: str | None = None


@app.post("/api/family/device", status_code=201)
async def fam_register(request: Request, d: DeviceIn):
    _rate_limit(_client_ip(request))
    return family.register(d.name, d.platform, d.lang)


@app.patch("/api/family/device")
async def fam_update(request: Request, d: DeviceIn):
    did = _dev(request)
    if d.phone and not family._clean_phone(d.phone):
        raise HTTPException(422, "Enter a 10-digit Indian mobile number, or leave it empty.")
    family.update_device(did, d.name, d.phone, d.lang)
    return family.me(did)


@app.delete("/api/family/device")
async def fam_forget(request: Request):
    family.delete_device(_dev(request))
    return {"deleted": True}


@app.get("/api/family/me")
async def fam_me(request: Request):
    return family.me(_dev(request))


class InviteIn(BaseModel):
    name: str | None = None


@app.post("/api/family/invite")
async def fam_invite(request: Request, i: InviteIn):
    did = _dev(request)
    _rate_limit(_client_ip(request))
    inv = family.create_invite(did, i.name)
    base = str(request.base_url).rstrip("/")
    proto = request.headers.get("x-forwarded-proto")
    if proto == "https" and base.startswith("http://"):
        base = "https://" + base[7:]
    inv["join_url"] = f"{base}/family?join={inv['code']}"
    return inv


class JoinIn(BaseModel):
    code: str
    name: str | None = None


@app.post("/api/family/join")
async def fam_join(request: Request, j: JoinIn):
    did = _dev(request)
    return _fam(family.join, did, j.code, j.name, _client_ip(request))


@app.delete("/api/family/link/{other_id}")
async def fam_unlink(request: Request, other_id: str):
    if not family.unlink(_dev(request), other_id[:64]):
        raise HTTPException(404, "You're not linked with that person.")
    return {"unlinked": True}


@app.get("/api/family/alerts")
async def fam_alerts(request: Request, since_id: int = 0, limit: int = 50):
    did = _dev(request)
    return {"alerts": family.alerts(did, max(0, since_id), max(1, limit)), "unread": family.me(did)["unread"]}


class SeenIn(BaseModel):
    up_to_id: int


@app.post("/api/family/alerts/seen")
async def fam_seen(request: Request, s_: SeenIn):
    family.mark_seen(_dev(request), s_.up_to_id)
    return {"ok": True}


class EventIn(BaseModel):
    type: str                     # "pay_anyway"
    kind: str = "qr"
    payload: str | None = None
    id: str | None = None


@app.post("/api/family/event")
async def fam_event(request: Request, e: EventIn):
    did = _dev(request)
    if e.type != "pay_anyway":
        raise HTTPException(422, "Unknown event.")
    rep = _scan_for(e.kind, e.id, e.payload)   # re-derived on the server
    if rep["verdict"]["level"] == "low":
        rep = apply_reports(rep)
    if rep["verdict"]["level"] == "low":
        return {"alerted": 0}
    return {"alerted": family.alert_for_scan(did, rep, event="pay_anyway")}


@app.get("/api/family/push-key")
async def fam_push_key():
    from .family import push
    return {"key": push.public_key()}


class PushIn(BaseModel):
    subscription: dict


@app.post("/api/family/push")
async def fam_push_sub(request: Request, p: PushIn):
    did = _dev(request)
    _fam(family.push_subscribe, did, p.subscription)
    return {"ok": True}


@app.delete("/api/family/push")
async def fam_push_unsub(request: Request, endpoint: str = ""):
    family.push_unsubscribe(_dev(request), endpoint or None)
    return {"ok": True}


@app.post("/api/family/test")
async def fam_test(request: Request):
    """Send a test alert to this (guardian) phone so people can confirm notifications work."""
    did = _dev(request)
    from .analyzer.rules import T as _T
    family._notify(did, did, "test", None, None, None, None,
                   _T("PayGuard alerts are working", "PayGuard अलर्ट काम कर रहे हैं", "PayGuard ಎಚ್ಚರಿಕೆಗಳು ಕೆಲಸ ಮಾಡುತ್ತಿವೆ"),
                   _T("This is how you'll be told if your family member runs into a scam.",
                      "अगर आपके परिजन किसी ठगी में फँसने वाले हों, तो आपको ऐसे बताया जाएगा।",
                      "ನಿಮ್ಮ ಕುಟುಂಬದವರು ವಂಚನೆಗೆ ಸಿಲುಕಿದರೆ ನಿಮಗೆ ಹೀಗೆ ತಿಳಿಸಲಾಗುತ್ತದೆ."), dedupe=None)
    return {"ok": True}


@app.exception_handler(RequestValidationError)
async def validation_err(_, exc: RequestValidationError):
    msgs = []
    for e in exc.errors():
        m = str(e.get("msg", "")).removeprefix("Value error, ")
        field = ".".join(str(x) for x in e.get("loc", [])[1:])
        msgs.append(m if "Value error" in str(e.get("msg", "")) or not field else f"{field}: {m}")
    return JSONResponse({"error": " ".join(msgs) or "Invalid input.", "fields": [".".join(map(str, e.get("loc", [])[1:])) for e in exc.errors()]},
                        status_code=422)


@app.exception_handler(HTTPException)
async def http_err(_, exc: HTTPException):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


@app.get("/s/{sha256}")
async def screenshot_page(sha256: str):
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/c/{ref}")
async def complaint_page(ref: str):
    return FileResponse(os.path.join(STATIC, "index.html"))


@app.get("/trends")
async def trends_page():
    return FileResponse(os.path.join(STATIC, "trends.html"))


@app.get("/family")
async def family_page():
    return FileResponse(os.path.join(STATIC, "family.html"))


@app.get("/r/{sha256}")
async def report_page(sha256: str):
    return FileResponse(os.path.join(STATIC, "index.html"))


app.mount("/", StaticFiles(directory=STATIC, html=True), name="static")
