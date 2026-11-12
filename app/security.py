"""API key generation/hashing, sender-address policy and admin login throttling."""
from __future__ import annotations

import hashlib
import re
import unicodedata
import hmac
import secrets
import threading
import time

KEY_PREFIX = "erk_"


def generate_key() -> tuple[str, str, str]:
    """Return (full_key, display_prefix, hash). Only the hash is stored."""
    full = KEY_PREFIX + secrets.token_urlsafe(32)
    return full, full[: len(KEY_PREFIX) + 6], hash_key(full)


_SPECIAL = {"ß": "ss", "æ": "ae", "œ": "oe", "ø": "o", "đ": "d", "ð": "d", "þ": "th", "ł": "l", "ı": "i"}


def slugify_username(name: str, max_len: int = 32) -> str:
    """Lowercase ASCII username: accents folded, anything else collapsed to single hyphens.

    "Café Ünïcode App!" -> "cafe-unicode-app"; empty/symbol-only input -> "app".
    """
    s = name.casefold()
    s = "".join(_SPECIAL.get(ch, ch) for ch in s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = re.sub(r"[^a-z0-9]+", "-", s.encode("ascii", "ignore").decode()).strip("-")
    return s[:max_len].strip("-") or "app"


def clean_username(raw: str | None, max_len: int = 100) -> str | None:
    """Make a client-supplied login name safe to store and display (control characters out, bounded length)."""
    if raw is None:
        return None
    s = "".join(ch for ch in raw if ch.isprintable())[:max_len].strip()
    return s or None


def hash_key(full_key: str) -> str:
    # Keys carry 256 bits of randomness, so a fast hash is appropriate (no need for bcrypt/argon2).
    return hashlib.sha256(full_key.encode()).hexdigest()


def extract_key(authorization: str | None, x_api_key: str | None) -> str | None:
    if x_api_key:
        return x_api_key.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def address_matches(addr: str, patterns: list[str]) -> bool:
    addr = addr.lower()
    domain = addr.rsplit("@", 1)[-1]
    for p in patterns:
        p = p.lower()
        if p == addr or (p.startswith("*@") and p[2:] == domain):
            return True
    return False


def check_password(given: str, expected: str) -> bool:
    return bool(expected) and hmac.compare_digest(given.encode(), expected.encode())


class LoginThrottle:
    """Lock an IP out for a while after repeated bad admin passwords."""

    def __init__(self, max_failures: int = 10, window: int = 900):
        self.max_failures, self.window = max_failures, window
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def blocked(self, ip: str) -> bool:
        with self._lock:
            now = time.time()
            recent = [t for t in self._fails.get(ip, []) if now - t < self.window]
            self._fails[ip] = recent
            return len(recent) >= self.max_failures

    def fail(self, ip: str) -> None:
        with self._lock:
            self._fails.setdefault(ip, []).append(time.time())

    def reset(self, ip: str) -> None:
        with self._lock:
            self._fails.pop(ip, None)
