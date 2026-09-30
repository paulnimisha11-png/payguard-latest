"""Web Push (RFC 8030) with VAPID (RFC 8292) and aes128gcm payload encryption (RFC 8291), using only `cryptography`
and `httpx`. Works with Chrome/Edge/Firefox on Android and desktop, and with iPhone home-screen web apps (iOS 16.4+).

The VAPID key pair is created once and kept in the data directory (or set APKXRAY_VAPID_PRIVATE to a PEM string)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import time
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .. import store

SUBJECT = os.environ.get("APKXRAY_VAPID_SUB", "mailto:payguard-alerts@example.com")
_KEY: ec.EllipticCurvePrivateKey | None = None


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _key() -> ec.EllipticCurvePrivateKey:
    global _KEY
    if _KEY:
        return _KEY
    pem = os.environ.get("APKXRAY_VAPID_PRIVATE")
    path = os.path.join(os.path.dirname(os.path.abspath(store.DB_PATH)), "vapid_private.pem")
    if pem:
        _KEY = serialization.load_pem_private_key(pem.encode(), None)
    elif os.path.exists(path):
        with open(path, "rb") as f:
            _KEY = serialization.load_pem_private_key(f.read(), None)
    else:
        _KEY = ec.generate_private_key(ec.SECP256R1())
        data = _KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    return _KEY


def public_key() -> str:
    """applicationServerKey for PushManager.subscribe()"""
    return b64u(_key().public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint))


def vapid_header(endpoint: str, now: float | None = None) -> str:
    sp = urlsplit(endpoint)
    claims = {"aud": f"{sp.scheme}://{sp.netloc}", "exp": int((now or time.time()) + 12 * 3600), "sub": SUBJECT}
    signing_input = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode()) + "." + \
        b64u(json.dumps(claims, separators=(",", ":")).encode())
    der = _key().sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    jwt = signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return f"vapid t={jwt}, k={public_key()}"


def _hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def encrypt(payload: bytes, p256dh: str, auth: str, salt: bytes | None = None,
            server_key: ec.EllipticCurvePrivateKey | None = None) -> bytes:
    """RFC 8291 aes128gcm body for one push message."""
    ua_public = unb64u(p256dh)
    auth_secret = unb64u(auth)
    salt = salt or os.urandom(16)
    as_private = server_key or ec.generate_private_key(ec.SECP256R1())
    as_public = as_private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    ua_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    ecdh_secret = as_private.exchange(ec.ECDH(), ua_key)
    ikm = _hkdf(auth_secret, ecdh_secret, b"WebPush: info\x00" + ua_public + as_public, 32)
    cek = _hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)
    ciphertext = AESGCM(cek).encrypt(nonce, payload + b"\x02", None)
    return salt + struct.pack("!I", 4096) + bytes([len(as_public)]) + as_public + ciphertext


def decrypt(body: bytes, ua_private: ec.EllipticCurvePrivateKey, auth: str) -> bytes:
    """Receiver side of RFC 8291 — used by the tests to prove `encrypt` is correct."""
    salt, idlen = body[:16], body[20]
    as_public = body[21:21 + idlen]
    ua_public = ua_private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    ecdh_secret = ua_private.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public))
    ikm = _hkdf(unb64u(auth), ecdh_secret, b"WebPush: info\x00" + ua_public + as_public, 32)
    cek = _hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)
    nonce = _hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12)
    plain = AESGCM(cek).decrypt(nonce, body[21 + idlen:], None)
    return plain.rstrip(b"\x00")[:-1]


def send(subscription: dict, data: dict, ttl: int = 86400) -> int:
    """Returns the push service's HTTP status (201 = accepted, 404/410 = subscription gone)."""
    import httpx
    endpoint = subscription["endpoint"]
    keys = subscription.get("keys") or {}
    body = encrypt(json.dumps(data, ensure_ascii=False).encode(), keys["p256dh"], keys["auth"])
    headers = {"Authorization": vapid_header(endpoint), "Content-Encoding": "aes128gcm",
               "Content-Type": "application/octet-stream", "TTL": str(ttl), "Urgency": "high"}
    r = httpx.post(endpoint, content=body, headers=headers, timeout=10)
    return r.status_code
