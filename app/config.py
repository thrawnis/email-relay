"""Configuration loaded from environment variables (see .env.example)."""
from __future__ import annotations

import ipaddress
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
    log_retention_days: int = 0  # 0 = keep forever

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

    # Reverse proxy / transport security
    trust_proxy: bool = False        # read client IP + scheme from proxy headers (NPM, Cloudflare Tunnel)
    trusted_proxies: list[str] = field(default_factory=list)  # IPs/CIDRs allowed to set those headers; empty = any
    require_https: bool = False      # reject requests that did not arrive over HTTPS at the proxy
    block_api_via_cloudflare: bool = True  # /api/* is LAN-only: refuse requests carrying Cloudflare headers
    smtp_ca_file: str = ""           # extra CA bundle for a self-signed SMTP server

    # Hostname apps use for the HTTPS API (via NPM), and for SMTP submission (straight to the relay host)
    public_hostname: str = "email-relay"
    submission_hostname: str = ""

    # TLS for the relay's own listeners (HTTPS port and SMTP submission)
    http_tls: bool = False               # serve the HTTP port over HTTPS (set by app/serve.py)
    tls_cert: str = ""                   # PEM fullchain; empty = auto-generated self-signed cert in /data/tls
    tls_key: str = ""

    # SMTP submission ingress (for apps that can only speak SMTP)
    submission_enabled: bool = False
    submission_bind: str = "0.0.0.0"
    submission_starttls_port: int = 587  # 0 = disabled
    submission_tls_port: int = 465       # 0 = disabled

    def __post_init__(self) -> None:
        if not self.submission_hostname:
            self.submission_hostname = self.public_hostname

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
            log_retention_days=_int("LOG_RETENTION_DAYS", 0),
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
            trusted_proxies=_list("TRUSTED_PROXIES"),
            require_https=_bool("REQUIRE_HTTPS", False),
            block_api_via_cloudflare=_bool("BLOCK_API_VIA_CLOUDFLARE", True),
            smtp_ca_file=_env("SMTP_CA_FILE"),
            public_hostname=_env("PUBLIC_HOSTNAME", "email-relay"),
            submission_hostname=_env("SUBMISSION_HOSTNAME") or _env("PUBLIC_HOSTNAME", "email-relay"),
            http_tls=_bool("HTTP_TLS", True),
            tls_cert=_env("TLS_CERT"),
            tls_key=_env("TLS_KEY"),
            submission_enabled=_bool("SUBMISSION_ENABLED", True),
            submission_bind=_env("SUBMISSION_BIND_ADDRESS", "0.0.0.0"),
            submission_starttls_port=_int("SUBMISSION_STARTTLS_PORT", 587),
            submission_tls_port=_int("SUBMISSION_TLS_PORT", 465),
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
        if self.require_https and not (self.trust_proxy or self.http_tls):
            problems.append("REQUIRE_HTTPS=true needs TRUST_PROXY=true or HTTP_TLS=true")
        for p in self.trusted_proxies:
            try:
                ipaddress.ip_network(p, strict=False)
            except ValueError:
                problems.append(f"TRUSTED_PROXIES entry {p!r} is not an IP address or CIDR")
        if self.smtp_ca_file and not os.path.isfile(self.smtp_ca_file):
            problems.append(f"SMTP_CA_FILE {self.smtp_ca_file} does not exist")
        if bool(self.tls_cert) != bool(self.tls_key):
            problems.append("Set both TLS_CERT and TLS_KEY (or neither for a self-signed cert)")
        for f in (self.tls_cert, self.tls_key):
            if f and not os.path.isfile(f):
                problems.append(f"{f} does not exist")
        if self.submission_enabled and not (self.submission_starttls_port or self.submission_tls_port):
            problems.append("SUBMISSION_ENABLED=true but both submission ports are 0")
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
            "require_https": self.require_https,
            "http_tls": self.http_tls,
            "public_hostname": self.public_hostname,
            "submission_hostname": self.submission_hostname,
            "trusted_proxies": self.trusted_proxies,
            "block_api_via_cloudflare": self.block_api_via_cloudflare,
        }
