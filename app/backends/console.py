"""Development backend: prints the message to stdout instead of sending it."""
from __future__ import annotations

import logging

from .base import Backend, SendResult, build_mime, envelope_recipients

log = logging.getLogger("relay.console")


class ConsoleBackend(Backend):
    name = "console"

    def __init__(self):
        self.sent: list[dict] = []  # handy for tests

    def send(self, payload: dict, from_addr: str, from_name: str | None) -> SendResult:
        msg = build_mime(payload, from_addr, from_name)
        self.sent.append({"payload": payload, "from": from_addr, "mime": msg})
        log.info("[console backend] envelope from=%s to=%s\n%s", from_addr, envelope_recipients(payload),
                 msg.as_string()[:4000])
        return SendResult(provider_id=msg["Message-ID"], detail="console backend: not actually sent")
