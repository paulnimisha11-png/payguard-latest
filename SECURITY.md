# Security policy

PayGuard protects people from payment fraud, so we take vulnerabilities in PayGuard itself seriously.

## Reporting a vulnerability (privately)

**Please do not open a public issue, pull request or discussion for a security problem.**

1. Go to **[Security → Report a vulnerability](https://github.com/paulnimisha11-png/payguard-latest/security/advisories/new)**
   on this repository (GitHub private vulnerability reporting). Only the maintainers can see the report.
2. Include:
   - what is affected (endpoint, page, Android screen, file) and the commit or deployed URL you tested;
   - steps to reproduce, or a minimal proof of concept;
   - the impact you expect (data exposure, bypass of a scam verdict, account takeover, denial of service…);
   - whether you'd like to be credited.
3. Please don't include real people's payment screenshots, messages, UPI IDs or phone numbers. Synthetic data is enough.

We aim to acknowledge a report within **72 hours** and to agree a fix and disclosure date with you within **14 days**.
Fixes are released on `main` and deployed; the advisory is published after the fix is live.

## Scope

In scope:
- the FastAPI server (`app/`) and every `/api/*` endpoint;
- the web app (`static/`), including sign-in, accounts, family alerts and complaint links;
- the Android app (`android-upi-intercept/`), including its handling of `upi://` links and shared text;
- verdict bypasses: an input that should clearly be flagged but is reported as safe because of a bug (not simply a
  new scam wording the rules don't know yet; those are welcome as normal issues with a synthetic example).

Out of scope: rate limits on the free demo deployment, findings that need a rooted/compromised phone, social-engineering
the maintainers, and third-party services (Google, Clerk, Render) themselves.

## Safe-harbour

We won't pursue or report anyone who, in good faith, tests within this scope, avoids privacy violations and service
disruption, and gives us reasonable time to fix the problem before disclosing it.

## How PayGuard handles secrets and data

- API keys (Gemini, Safe Browsing, VirusTotal, Clerk secret, e-mail) are read from server environment variables only.
  They are never in the repository, the Android app or the web page. `.env` is git-ignored; see `.env.example`.
- Uploaded APKs are analysed without being installed or run and are deleted after the scan; only the report is cached.
- Message text and screenshots are not stored. Community reports keep only scammer identifiers (UPI ID, domain,
  number, file hash) and a salted hash of the reporter's device.
- Gemini receives masked text only (phone numbers, UPI IDs, e-mail and long numbers replaced, links reduced to the
  website name). Safe Browsing receives link addresses only.
- Complaint links are protected by a random token; only its SHA-256 is stored, and complaints auto-delete after 30 days.
