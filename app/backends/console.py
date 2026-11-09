"""Development backend: prints the message to stdout instead of sending it."""
from __future__ import annotations

import logging

from .base import Backend, SendResult, prepare

log = logging.getLogger("relay.console")


class ConsoleBackend(Backend):
    name = "console"

    def __init__(self):
        self.sent: list[dict] = []  # handy for tests

    def send(self, payload: dict, from_addr: str, from_name: str | None) -> SendResult:
        msg, rcpts, message_id = prepare(payload, from_addr, from_name)
        text = msg.decode(errors="replace") if isinstance(msg, bytes) else msg.as_string()
        self.sent.append({"payload": payload, "from": from_addr, "mime": msg})
        log.info("[console backend] envelope from=%s to=%s\n%s", from_addr, rcpts, text[:4000])
        return SendResult(provider_id=message_id, detail="console backend: not actually sent")
