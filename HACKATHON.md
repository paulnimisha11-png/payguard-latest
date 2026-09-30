# Prior work and hackathon work

The judges asked us to separate what existed before the final hackathon from what we built during it.

## Before the hackathon (git tag `pre-hackathon`)
Everything reachable from the tag `pre-hackathon` (28 Sep 2026) is prior work, built during the earlier rounds:
APK X-Ray, the QR / UPI scanner, the payment-screenshot detector, the scam-message checker, community reports,
one-tap complaints, the trends page, family guardian mode and the Android UPI interceptor app.

`git log pre-hackathon..HEAD` lists every commit made during the final hackathon.

## During the final hackathon (30 Sep – 1 Oct 2026)
| Area | What we built | Where |
|---|---|---|
| Deployment fixes | Tesseract OCR on Render's free CPU, repository clean-up | `render.yaml`, `Dockerfile` |
| Accounts backend | Sign up, sign in that stays signed in for 30 days, sign out / sign out everywhere, email confirmation, sign-in alert emails with a "wasn't me" reset link, forgot / reset / change password, device list, per-user check history, account deletion. Runs on SQLite locally or Postgres (Supabase) in production. Brute-force limits, CSRF protection, scrypt hashing, hashed session and one-time tokens. | `app/auth/`, `tests/test_auth.py` |
| Clerk sign-in | Replaced the email + password sign-in with Clerk (Google or email, verification, recovery) using ClerkJS by script tag and Clerk's Python SDK to verify session tokens. Existing accounts are linked by verified email (`clerk_user_id`) and keep their history; sign-in alerts, the device list and account deletion work on Clerk sessions; the old password endpoints answer 410. | `app/auth/clerk.py`, `app/auth/`, `static/pgauth.js`, `static/login.*`, `static/account.*`, `tests/test_auth.py` |
| Landing page | Scroll story: an original SVG hooded figure whose rim light turns from blue to red and whose eyes open as you scroll, intercepted scam messages typing in, warp-speed light rays on a canvas, a scroll-driven scam-message demo, 3D feature cards, live counters | `static/landing.*` |
| Sign-in terminal | Red/black "authentication terminal" with matrix rain, login / register tabs, reset flow | `static/login.*`, `static/pgauth.js` |
| Account page | Profile, email alerts toggle, password, devices, history, delete | `static/account.*` |
| Verdict sentinel | The hooded figure appears on every scanner's result: blue with a scanning beam while checking, then red light rays and glowing eyes for a scam, yellow for suspicious, green for safe (APK, QR/UPI, screenshot and message checks) | `static/hood.js`, `static/sentinel.*` |
| APK AI analyst | After the rule-based APK analysis, Gemini (`gemini-3.8-flash`) gets the extracted facts + findings + score (never the file) and returns a structured explanation shown under the verdict. Rules stay the only source of the score; scans work unchanged if the AI is off or down | `app/reasoning.py`, `static/app.js`, `tests/test_reasoning.py` |
| UPI ML scam model (prototype) | Gradient-boosted trees on 36 features from the existing UPI parser, community history and look-alike matching; calibrated scam probability is the primary UPI QR verdict, with PayGuard's hard-evidence rules as a safety floor. Trained on a documented synthetic dataset (replaceable); honest model card | `app/ml/`, `scripts/make_upi_dataset.py`, `scripts/train_upi_model.py`, `tests/test_qr_ml.py` |
| Screenshot verification | Payment screenshots now end in VERIFIED / SUSPICIOUS / UNVERIFIED with extracted fields (incl. UPI ID and any QR on the image), every check performed and the reason. New checks: UPI ID format, impossible dates, QR payee/amount vs receipt. VERIFIED needs a trusted transaction source (none connected; SQLite history is never proof) | `app/screenshot/verify.py`, `static/shot.js`, `tests/test_screenshot_verify.py` |
| Layered SMS pipeline | Message checks now run extraction → rules → URL heuristics (typosquat, disguised IP, redirects, encoding, obfuscation) → sender check (DLT headers) → Scam Memory → optional Google Safe Browsing → risk engine → Gemini Flash only for ambiguous messages (masked text, structured output, cached, capped weight). Explainable risk card on web and Android; works when Gemini or Safe Browsing is down | `app/message/{urlextract,urlcheck,sender,memory,threatintel,ai,risk,pipeline}.py`, `static/msg.js`, `tests/test_sms_pipeline.py` |
| App theme | Black / red / green / blue theme for the scanner, radar, family and admin pages; user menu on every page | `static/cyber.css`, `static/theme.css` |

## How to check it
```bash
git log --oneline pre-hackathon..HEAD
git diff --stat pre-hackathon..HEAD
python -m pytest -q tests
```
