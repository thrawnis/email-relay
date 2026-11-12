"""Admission rules shared by both ingress paths (HTTP API and SMTP submission).

Every attempt — accepted or rejected — goes through here so it lands in the log
with the same checks applied: key validity, allowed senders, recipient cap and
per-key rate limits.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from .config import Settings
from .db import Database
from .security import address_matches, hash_key


@dataclass
class Admission:
    ok: bool
    message_id: str
    status_code: int = 202      # HTTP status for the API path
    error: str | None = None
    retry_after: int | None = None


class Relay:
    def __init__(self, db: Database, settings: Settings, notify: Callable[[], None]):
        self.db, self.settings = db, settings
        self._notify = notify  # must be safe to call from any thread

    # ------------------------------------------------------------------ keys
    def authenticate(self, raw: str | None) -> tuple[dict | None, str | None]:
        """Return (key, error). key is set with an error only when it exists but is revoked."""
        if not raw:
            return None, "Missing API key"
        key = self.db.get_key_by_hash(hash_key(raw))
        if not key:
            return None, f"Invalid API key ({raw[:10]}…)"
        if key["revoked_at"]:
            return key, f"API key '{key['name']}' has been revoked"
        self.db.touch_key(key["id"])
        return key, None

    # ------------------------------------------------------------- logging
    def reject(self, error: str, *, status_code: int, source: str, key: dict | None = None,
               app_name: str | None = None, from_addr: str | None = None, recipients: dict | None = None,
               subject: str | None = None, client_ip: str | None = None, retry_after: int | None = None,
               username: str | None = None) -> Admission:
        if status_code == 429 and key:
            bumped = self.db.bump_throttled(key["id"], error)
            if bumped:  # same limit hit again within a minute: count it instead of adding another row
                return Admission(False, bumped, status_code, error, retry_after)
        msg_id = self.db.insert_message(
            key_id=key["id"] if key else None,
            app_name=app_name or (key["name"] if key else "(unauthenticated)"),
            from_addr=from_addr, recipients=recipients, subject=subject, status="rejected", error=error,
            client_ip=client_ip, source=source, username=username or (key["username"] if key else None))
        return Admission(False, msg_id, status_code, error, retry_after)

    # ----------------------------------------------------------- rate limits
    def effective_limits(self, key: dict) -> tuple[int, int]:
        """(per minute, per day) for a key: its own setting, else the relay default. 0 = unlimited."""
        s = self.settings
        pm = s.default_rate_per_minute if key["rate_per_minute"] is None else key["rate_per_minute"]
        pd = s.default_rate_per_day if key["rate_per_day"] is None else key["rate_per_day"]
        return pm, pd

    def limits(self, key: dict) -> list[tuple[int | None, int, int, str]]:
        """Checked in order: (key_id or None for all keys, window seconds, limit, message when exceeded)."""
        pm, pd = self.effective_limits(key)
        out = []
        if pm:
            burst = max(10, -(-pm // 3))  # a third of the minute's allowance may arrive within 10 seconds
            if burst < pm:
                out.append((key["id"], 10, burst, f"Rate limit exceeded: more than {burst} messages in 10 seconds"))
            out.append((key["id"], 60, pm, f"Rate limit exceeded: {pm} messages/minute"))
        if pd:
            out.append((key["id"], 86400, pd, f"Quota exceeded: {pd} messages/24h"))
        g = self.settings.global_rate_per_minute
        if g:
            out.append((None, 60, g, f"Relay-wide rate limit exceeded: {g} messages/minute across all apps"))
        return out

    # ------------------------------------------------------------ admission
    def admit(self, *, key: dict, source: str, from_addr: str, recipients: dict, subject: str, payload: dict,
              has_html: bool, attachment_count: int, size_bytes: int, client_ip: str | None,
              username: str | None = None) -> Admission:
        s = self.settings
        ctx = dict(source=source, key=key, from_addr=from_addr, recipients=recipients, subject=subject,
                   client_ip=client_ip, username=username)

        n_rcpt = sum(len(v or []) for v in recipients.values())
        if n_rcpt == 0:
            return self.reject("No recipients", status_code=422, **ctx)
        if n_rcpt > s.max_recipients:
            return self.reject(f"Too many recipients (max {s.max_recipients})", status_code=422, **ctx)
        if not address_matches(from_addr, s.mail_allowed_from):
            return self.reject(f"Sender {from_addr} is not allowed by the relay", status_code=403, **ctx)
        if key["allowed_from"] and not address_matches(from_addr, key["allowed_from"]):
            return self.reject(f"Sender {from_addr} is not allowed for this API key", status_code=403, **ctx)

        with self.db.tx():  # limit checks + insert are atomic
            now = time.time()
            limit_err, retry_after = None, 0
            for key_id, window, limit, text in self.limits(key):
                count, wait = self.db.window_state(key_id, window, limit, now)
                if count >= limit and wait >= retry_after:  # report the limit that takes longest to clear
                    limit_err, retry_after = text, wait
            if not limit_err:
                msg_id = self.db.insert_message(
                    key_id=key["id"], app_name=key["name"], from_addr=from_addr, recipients=recipients,
                    subject=subject, has_html=has_html, attachment_count=attachment_count, size_bytes=size_bytes,
                    status="queued", client_ip=client_ip, payload=payload, source=source,
                    username=username or key["username"])
        if limit_err:
            return self.reject(limit_err, status_code=429, retry_after=retry_after, **ctx)
        self._notify()
        return Admission(True, msg_id)
