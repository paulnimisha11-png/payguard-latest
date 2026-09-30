import os
import tempfile

# Tests fire many scans from one client; don't let the per-IP rate limit get in the way.
os.environ.setdefault("APKXRAY_RATE_PER_MIN", "10000")
# Each test run gets its own fresh database, so runs never touch data/apkxray.db and stored
# rate limits (e.g. 10 sign-ups per hour per network) never carry over from an earlier run.
os.environ.setdefault("APKXRAY_DB", os.path.join(tempfile.mkdtemp(prefix="payguard-test-"), "test.db"))
