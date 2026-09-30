"""Optional URL reputation: Google Safe Browsing (Lookup API v4, threatMatches:find).

Only the extracted link addresses are sent (never the message, the sender or the user's data). Turned on by
SAFE_BROWSING_API_KEY (server environment only; never shipped in the app or the web page). Any failure (no key, quota,
timeout, network) returns a status and the rest of the pipeline carries on with its own checks.

Google's Safe Browsing Lookup API is for non-commercial use; a commercial deployment should switch to Google Web Risk
(same idea, different endpoint). A "no match" answer only means Google hasn't listed the link (yet): brand-new
phishing sites are often unlisted for hours, so it never lowers PayGuard's own verdict.
"""
from __future__ import annotations

import hashlib
import os

import httpx

from .. import store

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SERVICE = "Google Safe Browsing"
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
TTL_CLEAN, TTL_MATCH = 30 * 60, 6 * 3600
_transport: httpx.AsyncBaseTransport | None = None      # tests swap in an httpx.MockTransport
LAST: dict = {}


def _key() -> str:
    return (os.environ.get("SAFE_BROWSING_API_KEY") or os.environ.get("GOOGLE_SAFE_BROWSING_KEY") or "").strip()


def enabled() -> bool:
    return bool(_key())


def _h(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


async def check_urls(urls: list[str]) -> dict:
    """{"service", "status": ok|disabled|timeout|error|not_needed, "checked", "matches": [{"url", "threat_type"}], "cached"}"""
    urls = list(dict.fromkeys(u for u in urls if u))[:10]
    res = {"service": SERVICE, "status": "not_needed" if not urls else "disabled", "checked": 0, "matches": [], "cached": 0}
    if not urls:
        return res
    key = _key()
    if not key:
        return res
    todo = []
    for u in urls:
        hit = store.cache_get("gsb", _h(u), TTL_MATCH)
        if hit is not None and (hit.get("threat_type") or store.cache_get("gsb", _h(u), TTL_CLEAN) is not None):
            res["cached"] += 1
            if hit.get("threat_type"):
                res["matches"].append({"url": u, "threat_type": hit["threat_type"]})
        else:
            todo.append(u)
    if todo:
        body = {"client": {"clientId": "payguard", "clientVersion": "1.0"},
                "threatInfo": {"threatTypes": THREAT_TYPES, "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                               "threatEntries": [{"url": u} for u in todo]}}
        try:
            timeout = float(os.environ.get("SAFE_BROWSING_TIMEOUT", "4"))
        except ValueError:
            timeout = 4.0
        try:
            async with httpx.AsyncClient(transport=_transport, timeout=timeout) as c:
                r = await c.post(ENDPOINT, json=body, headers={"x-goog-api-key": key})
            if r.status_code != 200:
                res.update(status="error", reason=f"http {r.status_code}")
                LAST.clear(); LAST.update(status="error", reason=f"http {r.status_code}")
                return res
            found = {}
            for m in (r.json() or {}).get("matches") or []:
                u = ((m.get("threat") or {}).get("url")) or ""
                if u in todo:
                    found[u] = m.get("threatType") or "THREAT"
            for u in todo:
                store.cache_put("gsb", _h(u), {"threat_type": found.get(u)})
                if u in found:
                    res["matches"].append({"url": u, "threat_type": found[u]})
        except httpx.TimeoutException:
            res.update(status="timeout")
            LAST.clear(); LAST.update(status="timeout")
            return res
        except Exception as e:
            res.update(status="error", reason=type(e).__name__)
            LAST.clear(); LAST.update(status="error", reason=type(e).__name__)
            return res
    res.update(status="ok", checked=len(urls))
    LAST.clear(); LAST.update(status="ok", checked=len(urls))
    return res
