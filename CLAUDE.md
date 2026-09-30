# APK X-Ray (PayGuard hackathon, Track 3 Cybersecurity)

Web app + Android app with three scanners, all giving a risk score + plain-language findings in English/Hindi/Kannada:
1. APK X-Ray: upload an Android .apk -> static analysis (never installed/run).
2. PayPause (QR / UPI): upload a QR image, scan with camera, or paste a link -> decodes UPI pay/collect/mandate links and URLs -> flags 'scan to receive money' lures, impersonation, fake bank domains, APK download links, SMS/USSD QR tricks.
3. Payment screenshot detector: `app/screenshot/analyzer.py` (metadata, per-field pixel forensics via OCR boxes, UTR/date/status logic, reuse check with perceptual hash). OCR: RapidOCR (default; scans in 1100 px strips so the server stays < 512 MB) with Tesseract as fallback (`OCR_ENGINE=tesseract`, results say 'reduced accuracy'); no OCR => TEXT_UNREADABLE, never 'low'. Screenshots are ALWAYS upscaled to 1080 px and the extra reading passes (`_extra_passes`) must never be skipped: that's what catches edited amounts. `tests/test_screenshot_pairs.py` runs every test once per installed engine with bundled fonts (tests/fonts). Samples in `samples/screenshots/` (genuine_* must be 'low').

## Commands
- Install: `pip install -r requirements.txt`
- Run: `uvicorn app.main:app --reload --port 8000` then open http://localhost:8000
- Test: `python -m pytest -q tests` (must stay green)
- Demo file: `samples/Courier_Delivery_Update.apk` (inert fixture we built; must score 100 / "danger")

## Layout
- `app/main.py` FastAPI: /api/scan, /api/report/{sha256}, /api/explain, /api/stats, /api/health; serves `static/`
- `app/analyzer/core.py` pipeline: zip checks -> androguard manifest -> dex scan -> cert -> facts dict
- `app/analyzer/dexscan.py` fast custom DEX reader (strings + method refs)
- `app/analyzer/rules.py` rules -> Finding(id, severity, points, title{en,hi,kn}, detail{en,hi,kn}, evidence); verdict thresholds
- `app/analyzer/knowledge.py` permission meanings, API signatures, lure keywords, bank package lists
- `app/store.py` SQLite cache keyed by SHA-256 (APK bytes are never stored)
- `app/explain.py` family WhatsApp message (template, or Claude if ANTHROPIC_API_KEY set)
- `app/qr/analyzer.py` QR decode (OpenCV) + UPI/URL/tel/sms payload rules; endpoints /api/qr/image and /api/qr/text
- `static/` vanilla JS frontend, no build step (`app.js` APK flow + shared rendering, `qr.js` QR mode + camera via BarcodeDetector/jsQR)
- `app/complaints/` one-tap complaint: `builder.py` (ComplaintIn validation, portal fields, 1930 call script en/hi/kn, checklist, suspects), `pdf.py` (reportlab evidence PDF), `community.py` ("already reported by N people" finding added to scans at response time). Endpoints: POST /api/complaints, GET /api/complaints/{ref}[/pdf]?token=, DELETE same, GET /api/indicators. Complaints are token-protected (only SHA-256 of token stored), auto-deleted after 30 days; the indicators table keeps only scammer identifiers. Frontend: `static/report.js`, page route /c/{ref}#t={token}.
- QR demo images: `samples/qr/` (genuine_* must be 'low', everything else 'danger')

- `android-upi-intercept/` Java Android app (no Kotlin, framework widgets, only dependency: play-services-code-scanner). Registers for upi:// links, checks via /api/qr/text, forwards safe payments to a real UPI app (never itself), passes results back to merchant apps. Built by `.github/workflows/android.yml`. Keep all strings in values/values-hi/values-kn.

- Community votes: `votes` table in store.py, POST /api/reports, `community_counts`/`apply_reports` in app/complaints/community.py; frontend `static/vote.js`. UPI hand-off: `static/pay.js` (intent:// on Android, app schemes on iOS, /api/qr/render.png on desktop). PWA: `static/manifest.webmanifest`, `static/sw.js` (never caches /api), `static/pwa.js`.

- Scam messages: `app/message/analyzer.py` (CATEGORIES topic+action rule; genuine OTP/bank messages must stay low; corpus in tests/test_message.py), POST /api/message, complaint source "message". Frontend `static/msg.js`; PWA share_target → `/?share_text=`.
- Trends: `app/trends.py` + store `events`/`moderation`; votes have `net` (salted network hash) and reason `not_scam` (dispute). Public only if >= APKXRAY_PUBLIC_MIN reports from as many networks and not disputed. `/trends`, `/admin.html`, `scripts/seed_demo.py`.
- Family: `app/family/__init__.py` (fam_* tables, X-PG-Device auth, alerts from `_after_check` in main.py), `app/family/push.py` (own Web Push; round-trip tested). Frontend `static/device.js` (loaded first on every page; wraps fetch), `static/family.js`. Android: `Family.java`, `AlertJobService.java`, `WebActivity.java` (JS bridge `PayGuardApp`).
- Every scan endpoint must return through `_after_check(request, rep)` (community reports + trends counter + family alerts).

- Memory budget (Render free, 512 MB): APK scans run in a short-lived spawn worker (`app/analyzer/worker.py`, max_tasks_per_child=1); screenshots are checked one at a time. Measured: idle 240 MB, worst case 474 MB. Re-measure after adding anything heavy.
- Read aloud: phone voice first, server fallback `/api/tts` = eSpeak NG (local, GPL program run as a subprocess). Never call unofficial web APIs.
- Licensing: MIT (`LICENSE`); credit every new dependency/asset in `THIRD_PARTY_NOTICES.md`. Git tag `pre-hackathon` marks what existed before the final hackathon.
- Android release signing: private key via GitHub secrets (ANDROID_KEYSTORE_*), demo key only as fallback.

- Accounts: `app/auth/` (db.py picks SQLite via store or Postgres via `DATABASE_URL`; service.py has all logic; api.py routes; mailer.py Brevo/Resend/SMTP/console; emails.py EN/HI/KN). Signed-in checks are saved by `_after_check` via `auth.record_check` (verdict + masked label only). Never store raw messages/images. State-changing auth endpoints must call `_same_site`. `tests/test_auth.py` runs on SQLite, and on Postgres when `DATABASE_URL` is set.
- Pages: `/` landing (`static/landing.*`, only when the query has no app params, see `APP_QUERY` in main.py), `/app` scanner (index.html), `/login`, `/account`. Theme: `cyber.css` (tokens/components) + `theme.css` (restyles style.css pages, load after it). `pgauth.js` adds the user menu to any `[data-usermenu]`. Landing effects are vanilla JS + Lenis (MIT); no GSAP. Respect `prefers-reduced-motion`.
- Hooded figure: `static/hood.js` (`PGHood.mount(el, {laptop})`, one SVG shared by landing + scanner). Scanner verdict "sentinel": `static/sentinel.js/.css`, called from app.js `show()` (progress → blue scanning) and `render()` (danger → red, suspicious/caution → yellow, low → green).
- APK AI analyst: `app/reasoning.py` (Gemini via REST generateContent, JSON schema output). Called in /api/scan next to VirusTotal; result in `rep["ai"]` (`status` ok|disabled|timeout|error). It never changes verdict/score; send only `build_facts()` output (no APK bytes, icon, hashes; tokens redacted); only `ok` results are cached. Frontend: `renderAI()` in app.js, `#aicard`. Tests: `tests/test_reasoning.py` (MockTransport).
- `HACKATHON.md` lists prior vs hackathon work; keep it updated.

## Conventions
- Every new rule needs en/hi/kn text for title and detail, plus a test in tests/test_analyzer.py.
- Rules must never crash a scan (evaluate() catches exceptions); keep benign samples at level "low".
- No real malware in the repo. Test real samples only inside a VM.
