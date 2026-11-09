"""Delivery backend interface.

A backend takes a validated, normalized payload (see ``app.schemas.SendRequest``)
plus the resolved sender, and delivers it. It must raise:

* ``TransientError`` for failures worth retrying (network errors, timeouts,
  SMTP 4xx, provider 429/5xx, bad credentials that an admin may fix), or
* ``PermanentError`` for failures that will never succeed (SMTP 5xx on the
  message, provider 4xx validation errors).

To add a provider API backend (Postmark, Resend, SES, ...): subclass ``Backend``,
implement ``send`` by POSTing the payload to the provider, map its error codes
to the two exceptions above, and register it in ``app.backends.get_backend``.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, make_msgid


class TransientError(Exception):
    """Delivery failed but may succeed if retried."""


class PermanentError(Exception):
    """Delivery failed and will not succeed on retry."""


@dataclass
class SendResult:
    provider_id: str | None = None
    detail: str | None = None


class Backend:
    name = "base"

    def send(self, payload: dict, from_addr: str, from_name: str | None) -> SendResult:  # pragma: no cover
        raise NotImplementedError

    def describe(self) -> str:
        return self.name


def build_mime(payload: dict, from_addr: str, from_name: str | None) -> EmailMessage:
    """Build a RFC 5322 message: text, optional HTML alternative, attachments."""
    msg = EmailMessage()
    msg["From"] = formataddr((from_name, from_addr)) if from_name else from_addr
    msg["To"] = ", ".join(payload["to"])
    if payload.get("cc"):
        msg["Cc"] = ", ".join(payload["cc"])
    if payload.get("reply_to"):
        msg["Reply-To"] = payload["reply_to"]
    msg["Subject"] = payload["subject"]
    msg["Message-ID"] = make_msgid(domain=from_addr.rsplit("@", 1)[-1])
    # Bcc is intentionally not written to headers; it is only used for the envelope.

    text = payload.get("text") or ""
    html = payload.get("html")
    msg.set_content(text or " ")
    if html:
        msg.add_alternative(html, subtype="html")

    for att in payload.get("attachments") or []:
        data = base64.b64decode(att["content"])
        ctype = att.get("content_type") or "application/octet-stream"
        maintype, _, subtype = ctype.partition("/")
        msg.add_attachment(data, maintype=maintype or "application", subtype=subtype or "octet-stream",
                           filename=att["filename"])
    return msg


def envelope_recipients(payload: dict) -> list[str]:
    seen, out = set(), []
    for addr in (payload.get("to") or []) + (payload.get("cc") or []) + (payload.get("bcc") or []):
        if addr.lower() not in seen:
            seen.add(addr.lower())
            out.append(addr)
    return out
