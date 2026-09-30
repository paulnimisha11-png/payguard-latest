"""URL extraction for messages: find every link in the text and split it into parts. Nothing is fetched or opened.

Kept separate from URL verification (urlcheck.py): this module only answers "what links are in this text and what
are their parts?", with regular expressions and urllib.parse.

Handles
  - http://, https:// and www. links, and bare domains ("sbi-kyc.xyz/login");
  - several links in one message (deduplicated, at most MAX_URLS);
  - "defanged" / obfuscated writing that people and scammers use to dodge filters: hxxp://, example[.]com,
    example(dot)com, zero-width characters inside the link;
  - trailing punctuation and unbalanced brackets ("(see bit.ly/x)." -> bit.ly/x);
  - Unicode (look-alike letter) hosts: converted to their ASCII/punycode form (xn--...) so the checks see what the
    browser would really open.
"""
from __future__ import annotations

import re
import unicodedata
from urllib.parse import parse_qsl, urlsplit

from ..qr.analyzer import _host_is_ip, _registrable

MAX_URLS = 10
ZERO_WIDTH = "​‌‍⁠﻿­"

_TLDS = (r"com|in|net|org|co|io|me|ly|gd|gl|xyz|top|online|site|info|app|link|live|shop|store|club|vip|win|cc|pw|tk|ml|ga|"
         r"cf|gq|buzz|click|icu|sbs|rest|cyou|fun|work|support|help|bank|biz|us|uk|to|so|be|at|page|website|tech|cloud|"
         r"digital|pro|asia|sbi|ru|cn|su|monster|loan|zip|mov|lat|bond|today|cfd|ink")
URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>\"'`]+"
    r"|(?<![@\w.\-/])(?:[a-z0-9¡-￿](?:[a-z0-9¡-￿\-]{0,61}[a-z0-9¡-￿])?\.)+(?:" + _TLDS + r")"
    r"(?![a-z0-9\-])(?::\d{2,5})?(?:/[^\s<>\"'`]*)?"
    r"|(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:(?::\d{2,5})(?:/[^\s<>\"'`]*)?|/[^\s<>\"'`]*)", re.I)
# refanging: hxxp -> http, [.] (.) {.} [dot] (dot) -> ".", [:] -> ":", "h t t p" is too rare to bother with
_DEFANG = [
    (re.compile(r"\bhxxp(s?)(\[:\]|:)//", re.I), r"http\1://"),
    (re.compile(r"\s?[\[\(\{]\s?(?:\.|dot)\s?[\]\)\}]\s?", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
]


def _refang(text: str) -> tuple[str, bool]:
    out = text
    for rx, rep in _DEFANG:
        out = rx.sub(rep, out)
    return out, out != text


def _trim(u: str) -> str:
    u = u.rstrip(".,;:!?'\"")
    for o, c in (("(", ")"), ("[", "]"), ("{", "}")):
        while u.endswith(c) and u.count(c) > u.count(o):
            u = u[:-1].rstrip(".,;:!?'\"")
    return u


def _ascii_host(host: str) -> tuple[str, bool]:
    """IDNA/punycode form of a host (what the browser really opens), and whether it had non-ASCII letters."""
    if host.isascii():
        return host.lower(), False
    labels = []
    for label in host.split("."):
        if label.isascii():
            labels.append(label.lower())
            continue
        try:
            labels.append("xn--" + unicodedata.normalize("NFKC", label).lower().encode("punycode").decode("ascii"))
        except Exception:
            labels.append(label.lower())
    return ".".join(labels), True


_NUMERIC_IP = re.compile(r"^(0x[0-9a-f]+|\d{8,10})$", re.I)      # http://3232235777/ or http://0xC0A80001/


def parse_url(raw: str) -> dict | None:
    """Split one link into parts. None if it isn't a usable web address."""
    u = raw.strip()
    full = u if re.match(r"^[a-z][a-z0-9+.\-]*://", u, re.I) else "http://" + u
    try:
        sp = urlsplit(full)
        port = sp.port
    except ValueError:
        return None
    host_raw = (sp.hostname or "").strip(".")
    if not host_raw or ("." not in host_raw and not _NUMERIC_IP.match(host_raw) and ":" not in host_raw):
        return None
    host, idn = _ascii_host(host_raw)
    is_ip = _host_is_ip(host) or bool(_NUMERIC_IP.match(host))
    reg = host if is_ip else _registrable(host)
    sub = host[: -len(reg)].rstrip(".") if host.endswith(reg) and host != reg else ""
    try:
        params = parse_qsl(sp.query, keep_blank_values=True)
    except ValueError:
        params = []
    return {
        "raw": raw, "url": full if not idn else full.replace(host_raw, host, 1), "scheme": sp.scheme.lower(),
        "host": host, "host_display": host_raw.lower(), "registered_domain": reg, "subdomain": sub,
        "subdomain_levels": sub.count(".") + 1 if sub else 0, "port": port, "path": sp.path or "/", "query": sp.query,
        "params": [{"name": k[:60], "value": v[:200]} for k, v in params[:20]], "fragment": sp.fragment[:200],
        "is_ip": is_ip, "idn": idn, "has_userinfo": "@" in (sp.netloc or ""), "explicit_scheme": full is u or u.lower().startswith(("http://", "https://")),
    }


def extract_urls(text: str) -> list[dict]:
    """Every distinct link in the text, parsed. Order = order of appearance."""
    t = unicodedata.normalize("NFKC", text or "")
    zw = any(ch in t for ch in ZERO_WIDTH)
    t_clean = "".join(ch for ch in t if ch not in ZERO_WIDTH)
    refanged, defanged = _refang(t_clean)
    refanged_zw = _refang(t)[0] if zw else refanged
    out, seen = [], set()
    for m in URL_RE.finditer(refanged):
        raw = _trim(m.group(0))
        if len(raw) < 4:
            continue
        p = parse_url(raw)
        if not p:
            continue
        key = p["url"].lower().rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        obf = []
        if defanged and raw not in t_clean:
            obf.append("defanged")                      # written as hxxp:// or example[.]com to dodge filters
        if zw and raw not in refanged_zw:
            obf.append("zero_width")                    # invisible characters hidden inside the link
        p["obfuscation"] = obf
        out.append(p)
        if len(out) >= MAX_URLS:
            break
    return out
