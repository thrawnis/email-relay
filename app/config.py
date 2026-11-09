"""Configuration loaded from environment variables (see .env.example)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _int(name: str, default: int) -> int:
    raw = _env(name)
    return int(raw) if raw else default


def _bool(name: str, default: bool) -> bool:
    raw = _env(name).lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _list(name: str) -> list[str]:
    return [p.strip() for p in _env(name).split(",") if p.strip()]


@dataclass
class Settings:
    # Admin UI
    admin_password: str = ""
    secret_key: str = ""
    cookie_secure: bool = False

    # Storage
    db_path: str = "/data/relay.db"
    log_retention_days: int = 90

    # Sender identity
    mail_from: str = ""
    mail_from_name: str = ""
    mail_allowed_from: list[str] = field(default_factory=list)

    # Delivery backend
    mail_backend: str = "smtp"  # smtp | console
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_security: str = "starttls"  # starttls | ssl | none
    smtp_timeout: int = 30

    # Queue / retries
    max_attempts: int = 5
    send_concurrency: int = 2
    retry_schedule: list[int] = field(default_factory=lambda: [30, 120, 600, 1800, 3600])

    # Request limits
    max_recipients: int = 50
    max_attachment_bytes: int = 10 * 1024 * 1024

    # Trust X-Forwarded-For for client IPs (only behind a reverse proxy you control)
    trust_proxy: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        mail_from = _env("MAIL_FROM")
        allowed = _list("MAIL_ALLOWED_FROM") or ([mail_from] if mail_from else [])
        schedule = [int(x) for x in _list("RETRY_SCHEDULE_SECONDS")] or [30, 120, 600, 1800, 3600]
        return cls(
            admin_password=_env("ADMIN_PASSWORD"),
            secret_key=_env("SECRET_KEY"),
            cookie_secure=_bool("COOKIE_SECURE", False),
            db_path=_env("DB_PATH", "/data/relay.db"),
            log_retention_days=_int("LOG_RETENTION_DAYS", 90),
            mail_from=mail_from,
            mail_from_name=_env("MAIL_FROM_NAME"),
            mail_allowed_from=allowed,
            mail_backend=_env("MAIL_BACKEND", "smtp").lower(),
            smtp_host=_env("SMTP_HOST"),
            smtp_port=_int("SMTP_PORT", 587),
            smtp_username=_env("SMTP_USERNAME"),
            smtp_password=os.environ.get("SMTP_PASSWORD", ""),
            smtp_security=_env("SMTP_SECURITY", "starttls").lower(),
            smtp_timeout=_int("SMTP_TIMEOUT", 30),
            max_attempts=max(1, _int("MAX_ATTEMPTS", 5)),
            send_concurrency=max(1, _int("SEND_CONCURRENCY", 2)),
            retry_schedule=schedule,
            max_recipients=_int("MAX_RECIPIENTS", 50),
            max_attachment_bytes=_int("MAX_ATTACHMENT_BYTES", 10 * 1024 * 1024),
            trust_proxy=_bool("TRUST_PROXY", False),
        )

    def validate(self) -> list[str]:
        problems = []
        if not self.admin_password:
            problems.append("ADMIN_PASSWORD is not set")
        if len(self.secret_key) < 32:
            problems.append("SECRET_KEY must be set (at least 32 characters)")
        if not self.mail_from:
            problems.append("MAIL_FROM is not set")
        if self.mail_backend == "smtp" and not self.smtp_host:
            problems.append("SMTP_HOST is not set (MAIL_BACKEND=smtp)")
        if self.smtp_security not in ("starttls", "ssl", "none"):
            problems.append("SMTP_SECURITY must be starttls, ssl or none")
        return problems

    def public_summary(self) -> dict:
        """Non-secret config, shown in the admin UI."""
        return {
            "mail_backend": self.mail_backend,
            "mail_from": self.mail_from,
            "mail_from_name": self.mail_from_name,
            "mail_allowed_from": self.mail_allowed_from,
            "smtp_host": self.smtp_host,
            "smtp_port": self.smtp_port,
            "smtp_security": self.smtp_security,
            "smtp_username": self.smtp_username,
            "max_attempts": self.max_attempts,
            "retry_schedule_seconds": self.retry_schedule,
            "max_recipients": self.max_recipients,
            "max_attachment_bytes": self.max_attachment_bytes,
            "log_retention_days": self.log_retention_days,
        }
