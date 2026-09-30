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
| Landing page | Scroll story: an original SVG hooded figure whose rim light turns from blue to red and whose eyes open as you scroll, intercepted scam messages typing in, warp-speed light rays on a canvas, a scroll-driven scam-message demo, 3D feature cards, live counters | `static/landing.*` |
| Sign-in terminal | Red/black "authentication terminal" with matrix rain, login / register tabs, reset flow | `static/login.*`, `static/pgauth.js` |
| Account page | Profile, email alerts toggle, password, devices, history, delete | `static/account.*` |
| Verdict sentinel | The hooded figure appears on every scanner's result: blue with a scanning beam while checking, then red light rays and glowing eyes for a scam, yellow for suspicious, green for safe (APK, QR/UPI, screenshot and message checks) | `static/hood.js`, `static/sentinel.*` |
| App theme | Black / red / green / blue theme for the scanner, radar, family and admin pages; user menu on every page | `static/cyber.css`, `static/theme.css` |

## How to check it
```bash
git log --oneline pre-hackathon..HEAD
git diff --stat pre-hackathon..HEAD
python -m pytest -q tests
```
