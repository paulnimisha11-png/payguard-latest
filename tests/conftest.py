import os

# Tests fire many scans from one client; don't let the per-IP rate limit get in the way.
os.environ.setdefault("APKXRAY_RATE_PER_MIN", "10000")
