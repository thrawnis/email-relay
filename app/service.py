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
               subject: str | None = None, client_ip: str | None = None, retry_after: int | None = None) -> Admission:
        msg_id = self.db.insert_message(
            key_id=key["id"] if key else None,
            app_name=app_name or (key["name"] if key else "(unauthenticated)"),
            from_addr=from_addr, recipients=recipients, subject=subject, status="rejected", error=error,
            client_ip=client_ip, source=source)
        return Admission(False, msg_id, status_code, error, retry_after)

    # ------------------------------------------------------------ admission
    def admit(self, *, key: dict, source: str, from_addr: str, recipients: dict, subject: str, payload: dict,
              has_html: bool, attachment_count: int, size_bytes: int, client_ip: str | None) -> Admission:
        s = self.settings
        ctx = dict(source=source, key=key, from_addr=from_addr, recipients=recipients, subject=subject,
                   client_ip=client_ip)

        n_rcpt = sum(len(v or []) for v in recipients.values())
        if n_rcpt == 0:
            return self.reject("No recipients", status_code=422, **ctx)
        if n_rcpt > s.max_recipients:
            return self.reject(f"Too many recipients (max {s.max_recipients})", status_code=422, **ctx)
        if not address_matches(from_addr, s.mail_allowed_from):
            return self.reject(f"Sender {from_addr} is not allowed by the relay", status_code=403, **ctx)
        if key["allowed_from"] and not address_matches(from_addr, key["allowed_from"]):
            return self.reject(f"Sender {from_addr} is not allowed for this API key", status_code=403, **ctx)

        with self.db.tx():  # quota check + insert are atomic
            now = time.time()
            if key["rate_per_minute"] and self.db.count_accepted_since(key["id"], now - 60) >= key["rate_per_minute"]:
                limit_err = f"Rate limit exceeded: {key['rate_per_minute']} messages/minute"
            elif key["rate_per_day"] and self.db.count_accepted_since(key["id"], now - 86400) >= key["rate_per_day"]:
                limit_err = f"Quota exceeded: {key['rate_per_day']} messages/24h"
            else:
                limit_err = None
                msg_id = self.db.insert_message(
                    key_id=key["id"], app_name=key["name"], from_addr=from_addr, recipients=recipients,
                    subject=subject, has_html=has_html, attachment_count=attachment_count, size_bytes=size_bytes,
                    status="queued", client_ip=client_ip, payload=payload, source=source)
        if limit_err:
            return self.reject(limit_err, status_code=429, retry_after=60, **ctx)
        self._notify()
        return Admission(True, msg_id)
