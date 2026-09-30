# PayGuard — detailed feature reference

> The project overview, architecture and setup are in the main [README](../README.md). This page goes deeper into every scanner, rule and endpoint.

## APK X-Ray — see what an app can do to your phone *before* you tap Install

Upload the `.apk` someone sent you on WhatsApp. APK X-Ray unzips it (never installs or runs it), decodes the binary `AndroidManifest.xml`, scans the compiled code, checks who signed it, and matches **dangerous permission combinations** — the recognised fingerprint of banking trojans and OTP stealers. The verdict comes in plain English, हिंदी and ಕನ್ನಡ, with read-aloud and a one-tap "send to family on WhatsApp" message.

Part of **PayGuard** (Track 3 — Cybersecurity & Defense). The same app also contains the **PayPause QR / UPI scanner**:

## PayPause — QR code & UPI link scanner
Upload a QR screenshot (or paste it with Ctrl/Cmd+V), scan with the camera, or paste a link. The server decodes the QR with OpenCV and shows **who gets the money, how much, and that it leaves YOUR account**.

| Rule | Trigger |
|---|---|
| Receive-money lure (critical) | UPI note/name mentions refund, prize, cashback, KYC, security deposit… |
| AutoPay mandate (critical) | `upi://mandate` / recurring parameters |
| Collect request | `upi://collect` |
| Official-looking name, personal account | Payee name says SBI / customer care / police… but no merchant code |
| Fake bank/brand website (critical) | Domain uses sbi, hdfc, paytm, uidai… but isn't the real domain |
| APK download link, raw-IP host, punycode look-alike, `@` trick, link shortener, cheap TLD, bait words, no https | URL checks |
| SMS QR (SIM-binding), USSD `*21*` QR (call forwarding) | `sms:` / `tel:` payloads |

API: `POST /api/qr/image` (multipart `file`) · `POST /api/qr/text` (`{"text": "upi://pay?..."}`). Demo images in `samples/qr/`. Camera scanning needs `localhost` or https.


## Run it

```bash
pip install -r requirements.txt
uvicorn app.main:app --port 8000
# open http://localhost:8000 and drop samples/Courier_Delivery_Update.apk on it
```

Docker: `docker build -t apk-xray . && docker run -p 8000:8000 -v apkx:/data apk-xray`

Deploy for free on Render / Railway / Fly.io: point them at this folder; the Dockerfile respects `$PORT`. It is a single service (API + website), so there's no separate frontend deployment.

Tests: `python -m pytest -q tests` (120+ tests: APK, QR, screenshot, messages, complaints, trends, family, accounts). Each run uses its own temporary database. CI: `.github/workflows/backend.yml`.

Deploy: `render.yaml` (Render → New → Blueprint), or any Docker host.

### Optional environment variables
| Variable | Effect |
|---|---|
| `ANTHROPIC_API_KEY` | "Send to family" message is written by Claude in natural Hindi/Kannada/English (falls back to built-in templates without it) |
| `ANTHROPIC_MODEL` | default `claude-haiku-4-5-20251001` |
| `GEMINI_API_KEY` | Turns on the **AI analyst** for APK scans: Gemini explains the rule findings in plain words (summary, why it looks suspicious, innocent explanations, what to do). Only extracted facts are sent, never the APK; secrets such as bot tokens are redacted. The verdict and score still come only from PayGuard's rules; if Gemini is slow or down the scan works exactly as before |
| `GEMINI_MODEL` / `GEMINI_TIMEOUT` | default `gemini-3.8-flash` / 25 seconds for the whole explanation |
| `GEMINI_FALLBACK_MODELS` | tried in order when a model is busy or unavailable (HTTP 429/5xx/404); default `gemini-3.6-flash,gemini-3.5-flash-lite` |
| `GEMINI_SMS_TIMEOUT` | seconds for the SMS AI reading (default 12). The same `GEMINI_API_KEY` turns it on; it is only called for ambiguous messages |
| `SAFE_BROWSING_API_KEY` | Optional: Google Safe Browsing (Lookup API v4) reputation check for links in messages. Only link addresses are sent. Without it the checker says "not configured" and uses its own checks. The Lookup API is for non-commercial use; a commercial deployment should use Google Web Risk |
| `VT_API_KEY` | Adds a VirusTotal hash lookup (how many antivirus engines already flag the file) |
| `APKXRAY_MAX_MB` / `APKXRAY_TIMEOUT` / `APKXRAY_RATE_PER_MIN` / `APKXRAY_WORKERS` | 150 MB / 120 s / 12 scans per IP per minute / 1 worker process |
| `APKXRAY_DB` | SQLite path for the report cache (default `data/apkxray.db`) |
| `APKXRAY_ADMIN_TOKEN` | enables `/admin.html` report moderation |
| `APKXRAY_PUBLIC_MIN` | independent reports needed before something is listed on /trends (default 3) |
| `APKXRAY_VOTE_SALT` | salt for hashing reporter ids and networks — set a long random value in production |
| `APKXRAY_VAPID_PRIVATE` / `APKXRAY_VAPID_SUB` | Web Push key (PEM; auto-generated into `data/vapid_private.pem` if unset) and contact (`mailto:you@…`) |

## Website, sign-in and accounts
- `/` is the landing page (scroll story with an animated hooded figure, live numbers from `/api/trends`). The scanner is at `/app`;
  old links such as `/?check=…`, `/?share_text=…` and `/?source=pwa` still open the scanner.
- `/login` is the sign-in / register terminal, `/account` the account page. **Every scanner works without an account.**
- Sign-in is done by [Clerk](https://clerk.com): Google or email, with email verification and password recovery.
  ClerkJS is loaded with a script tag by `static/pgauth.js` (no build step); PayGuard never sees a password.
- Signed-in users get: their check history (verdicts only, scammer IDs masked; never messages, photos or files),
  an email on every new sign-in with a one-click "wasn't me" link that signs the account out everywhere, a list of
  signed-in devices they can sign out, and account deletion (type DELETE; also removes the Clerk user).
- How it fits together: the browser sends Clerk's short-lived session token with every `/api/` call
  (`Authorization: Bearer …`, or Clerk's `__session` cookie). `app/auth/clerk.py` verifies it with Clerk's Python SDK
  (`authenticate_request`; the token must have been issued for this site). `pg_users.clerk_user_id` links the Clerk
  user to the PayGuard account. **Accounts created before Clerk** are linked the first time their owner signs in
  through Clerk with the same *verified* email, so profile and history carry over; their old passwords are not used.
- Security: only verified emails can link or create an account; state-changing calls are JSON-only with an Origin
  check (CSRF); sessions ended from the account page are refused at once and revoked at Clerk; one-time links are
  stored hashed and expire. The old `/api/auth/login`, `signup`, `forgot`, `reset` and `password` endpoints answer 410.
- Sign-in alerts work without a Clerk webhook: the server sends one the first time it sees a new Clerk session, i.e.
  when that device first opens PayGuard after signing in. Alerting at the moment of sign-in (even if the site is
  never opened) would need Clerk's `session.created` webhook; that is not wired up yet.

### Accounts: environment variables
Without the two Clerk keys sign-in is switched off and every scanner still works. Without the rest, accounts are stored in the local SQLite file and emails are printed to the server log.
Run locally: put the keys in a `.env` file next to `requirements.txt` (it is gitignored and read at start-up; real environment variables win), then `uvicorn app.main:app --reload --port 8000` and open http://localhost:8000/login. If your `.env` also sets `PUBLIC_URL` to the deployed site, add `CLERK_AUTHORIZED_PARTIES=http://localhost:8000`, otherwise sign-ins made on localhost are refused.
| Variable | Effect |
|---|---|
| `CLERK_PUBLISHABLE_KEY` | Clerk Dashboard → API keys (`pk_test_…`). Public: the browser gets it from `/api/auth/config`. |
| `CLERK_SECRET_KEY` | `sk_test_…`. **Secret, server only**: never put it in the repo, `render.yaml` or any file under `static/`. |
| `CLERK_AUTHORIZED_PARTIES` | Optional, comma-separated extra origins whose session tokens are accepted, e.g. `http://localhost:8000` when `PUBLIC_URL` points at the deployed site but you are testing on your laptop. Not needed on Render. |
| `CLERK_JWT_KEY` | Optional. The instance's "JWKS Public Key" (PEM; `\n` for line breaks is fine). Session tokens are then verified without calling Clerk. |
| `DATABASE_URL` | Postgres for accounts, e.g. Supabase's **transaction pooler** string (`postgresql://postgres.<ref>:<password>@aws-0-<region>.pooler.supabase.com:6543/postgres`). Needed on Render, whose disk is wiped on every deploy. |
| `BREVO_API_KEY` or `RESEND_API_KEY` | Send emails through Brevo or Resend's HTTP API (Render's free plan blocks SMTP) |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` | Or send through SMTP (e.g. a Gmail app password) when running locally |
| `MAIL_FROM` / `MAIL_FROM_NAME` | Sender address (must be verified with Brevo/Resend) and name |
| `PUBLIC_URL` | This site's address, e.g. `https://<your-app>.onrender.com` (only the origin is used; a path is ignored). Used in email links, and Clerk session tokens are only accepted when issued for it. Unset, the address the request came to is used: fine locally, not in production. |

Set-up on Render (about 10 minutes):
1. **Supabase** (free): create a project → *Connect* → copy the *Transaction pooler* URI, put your database password in it → Render → Environment → `DATABASE_URL`. Tables are created automatically on first start.
2. **Brevo** (free, 300 emails/day): *Senders & IP* → add and verify your sender email → *SMTP & API* → create an API key → Render → `BREVO_API_KEY`, `MAIL_FROM`.
3. `PUBLIC_URL` = `https://<your-app>.onrender.com` (sign-in tokens are only accepted for this address).
4. **Clerk**: `CLERK_PUBLISHABLE_KEY`, `CLERK_SECRET_KEY` (and optionally `CLERK_JWT_KEY`) from the Clerk Dashboard. Redeploy, then open `/api/health`: it should show `"accounts_db": "postgres"`, `"accounts_db_ok": true`, `"email": "brevo"`, `"sign_in": "clerk"`.
   The Clerk *Development* instance works on any address but shows a development notice; a Production instance needs a domain you own.

Note: scan reports, community reports, trends and family links still use the local SQLite file, so on Render's free plan they reset when the service restarts.

## ML scam prediction for UPI QR codes (prototype)
For UPI payment QR codes and links, the verdict comes from a **machine-learning model** that returns a calibrated
estimated scam probability. PayGuard's rules still explain the result and act as a safety floor.

**Flow:** QR image / camera / typed link → existing decoder and UPI parser (`app/qr/analyzer.py`, incl. strict format check)
→ community reports and look-alike matching → `app/ml/features.py` (36 features) → gradient-boosted trees
(`app/ml/upi_model.json`) → isotonic/Platt calibration → `scam_probability` (0–1), `scam_probability_percent` (0–100),
`prediction` (Scam if ≥ 0.5, else Legitimate) → verdict. The API returns it as `ml` on `/api/qr/text` and `/api/qr/image`;
the old rule result is kept as `rule_verdict`.

- **Safety floor:** the model can't go below what hard evidence requires: a malformed UPI link, a critical rule finding
  (e.g. hidden AutoPay), real community reports, or a look-alike of a reported scam ID. The model's own estimate is always shown.
- **Prototype:** there isn't enough real labelled data yet, so it is trained on a documented **synthetic** dataset
  (`scripts/make_upi_dataset.py`, 18 legitimate/scam scenarios, hard cases and 2% label noise). Test-set results on that data:
  precision 0.976, recall 0.9569, F1 0.9663, ROC-AUC 0.9814, Brier 0.0227, ECE 0.0128.
  These show the model learned those scenarios, **not real-world accuracy**. Details: [`app/ml/MODEL_CARD.md`](../app/ml/MODEL_CARD.md).
- **Replace the data:** any CSV with `payload,label` (1 = scam, 0 = legitimate; optional `reports,got_me,disputes,lookalike`):
  `pip install -r requirements-ml.txt && python scripts/train_upi_model.py --no-synthetic --data my_labels.csv`.
- No extra runtime dependency or memory: scikit-learn is used only for training; serving adds < 1 MB and ~3 ms per QR.

## Fake payment screenshot detector
Third tab on the website (and in the Android app). Upload the "I've paid" screenshot someone showed you:
- **File evidence:** photo-editor software in EXIF/PNG/XMP, edit history, photo-of-a-screen, odd crops
- **Pixel forensics on the fields OCR finds** (amount, reference number, date, name): background patch behind the text vs. around it (paint-over edits), text style vs. same-size text (pasted-in numbers), error-level analysis for JPEGs
- **Content logic:** pending / failed / request status, missing or malformed 12-digit UPI reference (UTR), reference number's date vs. the date shown, future / stale dates, conflicting amounts, amount vs. what you expected, and the **same reference number on a different-looking screenshot** (recompressed WhatsApp copies of the same image are recognised and not counted)
- Result shows the screenshot with suspicious areas boxed in red, what was read, and findings in EN/HI/KN; it can go straight into a complaint

Text is read with RapidOCR (`rapidocr_onnxruntime`, installed by `pip install -r requirements.txt`, models included, works offline). Tesseract is used as a fallback if installed. If no OCR engine is available the page shows a warning and a screenshot can never be reported as "no signs of editing". Demo images: `samples/screenshots/` (regenerate with `make_samples.py`).

API: `POST /api/screenshot` (multipart `file`, optional `expected_amount`), `GET /api/screenshot/{sha256}`, page `/s/{sha256}`.

### Verification result: VERIFIED / SUSPICIOUS / UNVERIFIED
Every screenshot check also returns `verification` (shown as the "Payment verification" card and on the sentinel):
- **Extracted fields:** amount, UPI ID, payee, UTR / transaction ID, app transaction ID, date & time, status, and any **QR / UPI code on the image** (parsed with the same strict UPI parser as the QR scanner).
- **Extra consistency checks** (`app/screenshot/verify.py`): UPI ID format, impossible dates (31 Feb), a QR code on the image that is malformed or pays a **different UPI ID / amount** than the receipt claims. OCR noise read from QR squares is ignored.
- **Checks performed:** each check with pass / fail / warning / skipped and why (metadata, pixel forensics, OCR, required fields, status, amounts, UPI ID, reference, date, QR, PayGuard history, bank SMS, trusted source).
- **Status:** `SUSPICIOUS` when tampering or inconsistency indicators are found; `UNVERIFIED` when the screenshot is internally consistent but not independently confirmed; `VERIFIED` **only** when a trusted transaction source confirms the payment. No such source is connected (`verify.TRUSTED_SOURCES` is an empty hook for a real, authenticated bank / payment-gateway integration), so today a clean screenshot is always `UNVERIFIED`. PayGuard's own SQLite history (reused UTRs, earlier edited copies) can reveal fakes but is never treated as proof that a payment happened.

## Android app (UPI interceptor)
`android-upi-intercept/` — scan a shop's QR with PayGuard: safe payments open your UPI app pre-filled, scams stop on a warning screen. It can also become the phone's handler for all `upi://` links (camera, Google Lens, WhatsApp, merchant apps). See **android-upi-intercept/README-UPI-INTENT.md** for building (GitHub Actions builds the APK automatically), installing and the demo script.

Backend support: `GET /api/app/connect.png` (QR the app scans to learn this server's address), `GET /download/payguard.apk` (serves `downloads/payguard.apk` or redirects to `APKXRAY_APP_APK_URL`), `/?check=<payload>` (the app hands a scam to the website's report flow).

## Scam message checker (SMS / WhatsApp / email)
Paste a message (or on Android share it to PayGuard) → `POST /api/message`. `app/message/analyzer.py` recognises 13 Indian scam scripts in English, Hindi (Devanagari + Hinglish) and Kannada — electricity cut-off, KYC / account block, parcel / customs, refund / prize, part-time job, instant loan, investment, "digital arrest", SIM block, "hi mum new number", "sent by mistake", e-challan, FASTag — and what the message wants you to do: share an OTP/PIN, enter a PIN to "receive", install AnyDesk or an APK, call a personal mobile number, pay a fee, join a video call, keep it secret. A topic alone is only a hint ("your electricity bill is due" stays low); topic + action is the scam. Every link goes through the QR scanner's link checks, and UPI IDs / numbers / websites / the message template are counted by community reports. Genuine OTP and bank-debit messages stay "low" (see `tests/test_message.py`: 22 real-world scam scripts, 14 genuine messages). The message text is never stored.

### Layered SMS pipeline (what `/api/message` does now)
`message (+ optional sender, time) → extraction → rules → URL analysis → sender → Scam Memory → threat intel → risk engine → Gemini only if still ambiguous → final result`

- **Extraction** (`app/message/urlextract.py`): regex + `urllib.parse`, nothing is fetched. http/https/www/bare-domain and bare-IP links, several per message (deduplicated), defanged `hxxp://` / `site[.]com` and zero-width characters, trailing punctuation, look-alike Unicode hosts converted to punycode. Each link is split into host, registered domain, subdomains, port, path and query parameters.
- **URL analysis** (`urlcheck.py`): the existing link rules (fake brand domains, shorteners, throw-away TLDs, APK downloads, IP hosts, `@` tricks, punycode) plus typosquatting (edit distance + look-alike characters against official domains), IP written as one number, unusual ports, redirect parameters, heavy encoding, executable downloads, long hyphenated domains, obfuscation.
- **Sender** (`sender.py`): DLT headers (`VM-SBIINB-S`), personal mobile, foreign, short code; flags an organisation claim from a personal/foreign number or a header of a different company. Never proof (spoofing).
- **Scam Memory** (`memory.py`): sender, domains, numbers, UPI IDs and the wording template against complaints and community reports; disputed ones are shown but not counted.
- **Threat intel** (`threatintel.py`): Google Safe Browsing if `SAFE_BROWSING_API_KEY` is set; results cached; failures reported, never fatal.
- **Risk engine** (`risk.py`): weighted points with caps per layer (URL heuristics ≤ 35, sender ≤ 25); a critical rule finding or a Safe Browsing match sets a floor of 70. Levels HIGH ≥ 70, MEDIUM ≥ 35, LOW ≥ 15, else MINIMAL. The score is **not a probability**.
- **Gemini Flash** (`ai.py`): called only when the deterministic layers leave the message ambiguous (skipped for hard evidence, plain chat, genuine OTP/bank alerts from the matching header). It receives the message with phone numbers, UPI IDs, e-mails and long numbers masked and links reduced to their website name (≤ 700 chars), plus the sender type. Structured JSON (`risk_level`, `impersonation`, `credential_request`, `payment_request`, `social_engineering`, `tactics`, `reason`). It adds at most 25 points, never lowers a score and cannot make a message HIGH on its own. Identical masked messages are answered from a cache.
- **Result**: `risk` (level, score, factors with their layer, safe actions, status of every layer) shown in the web risk card and the Android result screen. Tests: `tests/test_sms_pipeline.py`.
- **Android**: the app has no SMS permission and doesn't need one: messages come from the share sheet or paste, with an optional sender field. The Gemini and Safe Browsing keys live only on the server.

## Scam trends page (`/trends`)
Anonymous counters (day, kind, verdict, scam type — no content, no IPs) feed a public page: checks and scams caught this week vs last, a 14-day chart, rising scam types, and the most-reported UPI IDs, numbers and websites. **Protection against false reports:** an identifier is listed only after `APKXRAY_PUBLIC_MIN` (default 3) people report it from that many *different networks*, and only while fewer than half as many people say "this is genuine"; UPI IDs and numbers are partly masked; one report only makes a scan "caution", not "danger". Moderators use `/admin.html` with `APKXRAY_ADMIN_TOKEN` to approve, hide or clear entries (clearing also removes the warning from scans). Anyone can look up the exact ID/number/website they were given. For a presentation: `python scripts/seed_demo.py` (clearly labelled demo data; `--remove` deletes it).

## Family guardian mode (`/family`)
A guardian (son/daughter) creates a 6-digit code on their phone; the parent types it on theirs and confirms what will be shared. From then on, whenever the parent's phone gets a **dangerous or suspicious result** (message, QR/link, screenshot, app) — or they tick "pay anyway" on a risky UPI QR — every guardian gets an alert, and the parent sees a "Talk to Rahul before you pay — 📞 Call" card. Alerts contain the scam type and a masked identifier, never the message or screenshot; they're deleted after 30 days; either side can unlink; "Forget this phone" erases everything. No accounts or passwords: each phone keeps a random device secret (server stores only its SHA-256) and sends it as `X-PG-Device`, so alerts are raised on the server. Delivery: in-page inbox + **Web Push** (VAPID + aes128gcm implemented in `app/family/push.py`; works in Chrome on Android and in the iPhone Home-Screen app on iOS 16.4+, needs https) + the Android app's own notifications (checks every 15 min and whenever it opens).

## Community reports ("It got me" / "It's fake")
After any QR, screenshot or APK check, one tap adds a report (`POST /api/reports`). The next person who checks the same UPI ID, domain, phone number, screenshot or APK sees **"Reported by N people"** and a raised risk score (3+ reports → critical). Reports are anonymous: each device sends a random id that is hashed with a server salt (`APKXRAY_VOTE_SALT`), so one phone counts once. Official bank/government sites can't be reported. "It got me" opens the pre-filled complaint.

## Pay safely: straight to your UPI app
When a UPI QR checks out clean, PayGuard counts down 3 seconds and opens your UPI app (the last one you picked), or you tap Google Pay / PhonePe / Paytm / BHIM / any UPI app. Android uses `intent://` links targeted at each app; iPhone uses `tez://`, `phonepe://`, `paytmmp://`; desktop shows the payment QR to scan with a phone. Risky QRs never auto-open — paying needs an explicit "I know this person" tick.

## Install on your phone (iPhone and Android)
- **iPhone:** open the https link in Safari → Share → **Add to Home Screen**. PayGuard runs full-screen with camera scanning (PWA).
- **Android:** Chrome → **Install app**, or install the native APK (`android-upi-intercept/`, built by GitHub Actions), which can also catch `upi://` links from other apps.
- Camera and install need **https** (use the tunnel link), not `http://192.168…`.

## One-tap complaint ("Report this scam")
After any risky scan, **Report this scam** opens a short form (money lost? amount, UTR, bank, when, how it arrived, sender). The server **re-derives the evidence from the original scan** (it never trusts findings sent by the browser) and returns:
- **Fields for cybercrime.gov.in** with a copy button each (category, sub-category, time, platform, amount, UTR, beneficiary, suspect identifiers, and a 200+ character description)
- **What to say on the 1930 call**, in English / Hindi / Kannada, filled with the amount, UTR, beneficiary and time
- **Next-step checklist**, urgent steps first (1930, block bank, uninstall app, portal, Chakshu, keep evidence)
- **Evidence PDF** (A4): summary, suspect identifiers, transaction, the regenerated QR / file hashes, findings with evidence, statement, evidence fingerprint
- A reference number (`PG-YYMMDD-XXXXXX`) and a private link `/c/<ref>#t=<token>` to come back

Privacy: the access token is shown once and only its SHA-256 is stored; complaints auto-delete after 30 days (`APKXRAY_COMPLAINT_TTL_DAYS`) and the user can delete immediately. Scammer identifiers (UPI ID, domain, phone, app hash) are kept separately with no victim data, so the **next person who scans the same UPI ID / site / app sees "Already reported by N people"**.

PayGuard cannot submit to the government portal for the user (there is no public filing API); it prepares everything so filing takes minutes.

## What it actually analyses

```
upload ─▶ zip safety checks (zip-bomb ratio, entry count, size) ─▶ unwrap .apks/.xapk split bundles
       ─▶ androguard: binary AndroidManifest.xml → permissions, services, receivers, intent filters, SDK levels
       ─▶ custom DEX reader: every string constant + every referenced API method, all classes*.dex (ms, not seconds)
       ─▶ resources.arsc strings + asset HTML/JS → fake CVV/PIN forms
       ─▶ signing cert: unsigned / debug key / key age;  native libs → packers;  assets → hidden APK/DEX payloads
       ─▶ 22 rules → score 0-100 → verdict + findings (en/hi/kn) ─▶ cached by SHA-256 (APK bytes are deleted)
```

**Key rules** (`app/analyzer/rules.py`):

| Rule | Trigger | Why it matters |
|---|---|---|
| Banking-trojan triad | SMS read/receive **+** Accessibility service **+** `SYSTEM_ALERT_WINDOW` | Read OTP, control screen, overlay fake login |
| OTP theft | SMS + internet, stronger if code calls `SmsMessage.createFromPdu` / queries `content://sms` | Classic Indian SMS-stealer |
| Telegram exfiltration | `api.telegram.org/bot…` or bot token in code | Most common exfil channel for Indian SMS stealers |
| Call forwarding | `CALL_PHONE` + `*21*`/`**21*`/`*401*` codes | Hijacks bank verification calls |
| Bank target list | ≥2 Indian bank app package names in code | Trojan decides when to show the overlay |
| Credential form | ≥3 of CVV / ATM PIN / card number / MPIN… in the app's text | Built-in phishing page |
| Scam lure mismatch | Name/file says courier, bill, KYC, challan, tax refund… but asks for SMS/accessibility | Real ones are never sent as APK files |
| Brand impersonation | Name says SBI/HDFC/PhonePe/WhatsApp… but package ID isn't the official one | |
| + Notification listener, device admin, hidden icon, dropper, default-SMS takeover, legacy targetSdk (<23 = no permission prompts), packer, raw-IP / throw-away-domain servers, debug / fresh / missing signature, persistence, screen recording | | |

Verdict: ≥70 **Do NOT install** · 40-69 **Very suspicious** · 15-39 **Be careful** · <15 **No known danger signs** (any critical finding forces ≥45).

## API

| Method | Path | |
|---|---|---|
| POST | `/api/scan` | multipart field `file` → full report JSON |
| GET | `/api/report/{sha256}` | cached report (also the shareable page `/r/{sha256}`) |
| POST | `/api/explain` | `{"sha256", "lang": "en|hi|kn"}` → WhatsApp-ready message |
| GET | `/api/stats` | files scanned, verdict counts, most-seen threats |
| POST | `/api/message` | `{"text"}` → scam message report |
| POST | `/api/reports` | `{"kind": "qr|msg|shot|apk", "payload"|"id", "reason": "got_me|fake|not_scam", "voter"}` |
| GET | `/api/trends` · `/api/lookup?q=` | public trends · has this UPI ID / number / website been reported? |
| POST/GET | `/api/family/*` | device, invite, join, me, alerts, event (pay_anyway), push, test — see `app/main.py` |
| GET | `/api/health` | |

"Seen N times" is real: if many people upload the same file hash, the report says the file is circulating.

## Honest limitations (say these to judges before they ask)
- Static analysis only. Code downloaded *after* install, or hidden inside commercial packers, is not visible — packers are flagged instead.
- Permission-combination analysis can flag genuine apps that need SMS/accessibility (e.g. an SMS app or a screen reader). That's why every finding shows its evidence, and why the UI says "low risk ≠ safe".
- The trojan in `samples/` is an inert fixture we built. For real-world validation, run the scanner on Android SMS-stealer samples from MalwareBazaar **inside a VM**.

## Project layout
```
app/main.py              FastAPI server, upload streaming, worker pool, rate limit, VirusTotal
app/store.py             SQLite report cache + "seen N times"
app/explain.py           Family message (template or Claude)
app/analyzer/core.py     Pipeline: zip → manifest → dex → cert → facts
app/analyzer/dexscan.py  Fast DEX string/method-reference reader
app/analyzer/rules.py    Rules, scoring, verdicts, EN/HI/KN text
app/analyzer/knowledge.py Permissions, API signatures, lure words, bank packages, packers
app/message/analyzer.py  Scam message checker (scripts, actions, pressure, entity extraction)
app/trends.py            Trends aggregation, public-listing rules, masking, lookup
app/family/              Family guardian mode (devices, codes, links, alerts) + push.py (Web Push, no extra deps)
scripts/seed_demo.py     Labelled demo data for the trends page
app/auth/                Accounts: clerk.py (Clerk session tokens + Backend API), db.py (SQLite or Postgres), service.py, api.py, mailer.py, emails.py (EN/HI/KN)
app/ml/                  UPI scam model: features.py, upi_model.py (runtime), upi_model.json (trained), MODEL_CARD.md, data/
scripts/make_upi_dataset.py, scripts/train_upi_model.py   Prototype dataset + training/evaluation/calibration
static/                  Web app (vanilla JS, mobile-first, EN/हिंदी/ಕನ್ನಡ, read-aloud); trends.html, family.html, admin.html
static/landing.*         Landing page (/): hooded-figure scroll story, warp canvas, live counters
static/login.*, account.*, pgauth.js   Sign-in terminal, account page, shared account helpers + user menu
static/cyber.css, theme.css            Black/red/green/blue theme (theme.css restyles the scanner pages without touching their logic)
tests/  samples/
```

## Hackathon: prior work vs. work done during the event
See [HACKATHON.md](../HACKATHON.md). Git tag `pre-hackathon` marks the code that existed before the final hackathon.

## License and credits
PayGuard is open source under the [MIT License](../LICENSE). Third-party libraries, programs, fonts and the three
open-source sample apps in `samples/` keep their own licenses and are credited in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). Parts of the code were written with an AI coding assistant
(Anthropic's Claude); the team reviewed, tested and is responsible for it.
