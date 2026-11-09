from __future__ import annotations

from ..config import Settings
from .base import Backend, PermanentError, SendResult, TransientError
from .console import ConsoleBackend
from .smtp import SMTPBackend

__all__ = ["Backend", "PermanentError", "SendResult", "TransientError", "get_backend"]


def get_backend(settings: Settings) -> Backend:
    if settings.mail_backend == "smtp":
        return SMTPBackend(settings.smtp_host, settings.smtp_port, settings.smtp_username,
                           settings.smtp_password, settings.smtp_security, settings.smtp_timeout)
    if settings.mail_backend == "console":
        return ConsoleBackend()
    raise ValueError(f"Unknown MAIL_BACKEND {settings.mail_backend!r} (expected smtp or console)")
