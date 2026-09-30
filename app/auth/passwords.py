"""Password hashing with scrypt (Python standard library, memory-hard, recommended by OWASP).

Stored format: scrypt$<n>$<r>$<p>$<salt b64>$<hash b64>, so parameters can be raised later without breaking old
hashes (needs_rehash tells the login code to upgrade a hash after a successful sign-in)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

N, R, P, DKLEN = 2 ** 14, 8, 1, 64   # ~16 MB and ~50 ms per hash

# The most common leaked passwords; a real service would also check haveibeenpwned (k-anonymity API).
COMMON = {"password", "password1", "password123", "12345678", "123456789", "1234567890", "qwerty123", "qwertyuiop",
          "iloveyou", "11111111", "00000000", "abcd1234", "admin123", "welcome1", "india123", "letmein1", "football",
          "baseball", "sunshine", "princess", "passw0rd", "1q2w3e4r", "zaq12wsx", "asdfghjkl", "payguard", "payguard1"}


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=N, r=R, p=P, dklen=DKLEN, maxmem=64 * 1024 * 1024)
    return f"scrypt${N}${R}${P}${base64.b64encode(salt).decode()}${base64.b64encode(h).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, h = stored.split("$")
        if algo != "scrypt":
            return False
        want = base64.b64decode(h)
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             dklen=len(want), maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(got, want)
    except Exception:
        return False


def needs_rehash(stored: str) -> bool:
    try:
        _, n, r, p, *_ = stored.split("$")
        return (int(n), int(r), int(p)) != (N, R, P)
    except Exception:
        return True


# A hash of a random password, verified against when the email doesn't exist, so a wrong email and a wrong
# password take the same time (no account enumeration by timing).
DUMMY_HASH = hash_password(os.urandom(16).hex())


def password_problem(password: str, email: str = "") -> str | None:
    """Reason a new password is too weak, or None."""
    if len(password) < 8:
        return "Use at least 8 characters."
    if len(password) > 200:
        return "That password is too long (max 200 characters)."
    low = password.lower()
    if low in COMMON or low.strip("0123456789!@#") in COMMON:
        return "That password is too common. Pick something harder to guess."
    if email and low == email.lower().split("@")[0]:
        return "Don't use your email name as your password."
    if len(set(password)) < 4:
        return "Use a mix of different characters."
    return None
