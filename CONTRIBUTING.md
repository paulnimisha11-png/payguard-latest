# Contributing to PayGuard

Thanks for helping people pay safely. Bug reports, new scam patterns, translations and code are all welcome.

## Ground rules

- **Never commit real people's data.** Use synthetic screenshots, messages and UPI IDs (see `samples/` and the test
  helpers that draw receipts with the bundled Poppins font).
- **Never commit real malware.** The APK in `samples/` is an inert fixture we built. Test real samples only inside a VM.
- **Never commit secrets.** Keys live in environment variables (`.env.example` lists them).
- Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Workflow

1. Fork, then create a branch from `main` (`feature/…`, `fix/…`).
2. Set up the project (see *Installation* in the README) and make your change.
3. Run the checks below. CI runs the same ones on every push and pull request.
4. Open a pull request describing **what** changed, **why**, and **how you tested it**. Screenshots for UI changes.

```bash
ruff check app scripts tests                      # static analysis (must pass)
python -m pytest -q tests                         # 238 tests (must stay green)
python -m pytest -q --cov=app --cov-report=term   # coverage report
```

## Code style

- **Python 3.11**, type hints on public functions, small pure functions where possible. `ruff.toml` holds the lint
  rules (syntax errors, undefined names, unused imports/variables).
- **Every rule / finding** has an `id`, `severity`, `points`, a `title` and `detail` in **English, Hindi and Kannada**
  (`T(en, hi, kn)`), and `evidence` that shows the user *why*. Add a test for it.
- **Rules must never crash a scan.** Wrap risky parsing; an exception must degrade to "couldn't check", not an error.
- **Keep genuine samples genuine:** `samples/**/genuine_*` must stay at level `low`, and genuine OTP / bank messages
  in `tests/test_message.py` must not be flagged.
- **Honesty in results:** a score is never shown as a probability unless it is calibrated; a screenshot is never
  "verified" without a trusted transaction source; the prototype ML model is always labelled as such.
- **Every scan endpoint** returns through `_after_check()` in `app/main.py` (community reports, trends, family alerts).
- **Frontend:** vanilla JS, no build step. Respect `prefers-reduced-motion`, keep text readable at phone width.
- **Android:** Java, framework widgets, strings in `values/`, `values-hi/` and `values-kn/`.
- Credit every new dependency or asset in `THIRD_PARTY_NOTICES.md`.

## Adding a new scam pattern

1. Add a synthetic example to the relevant test file (`tests/test_message.py`, `tests/test_qr.py`, …) and watch it fail.
2. Add the rule with EN/HI/KN text and evidence.
3. Check that the genuine examples in the same file still pass.

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
