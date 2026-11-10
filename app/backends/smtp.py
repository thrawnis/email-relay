"""SMTP delivery backend (STARTTLS, implicit SSL, or plain)."""
from __future__ import annotations

import smtplib
import socket
import ssl

from .base import Backend, PermanentError, SendResult, TransientError, prepare


class SMTPBackend(Backend):
    name = "smtp"

    def __init__(self, host: str, port: int, username: str, password: str, security: str, timeout: int,
                 ca_file: str = ""):
        self.host, self.port = host, port
        self.ca_file = ca_file
        self.username, self.password = username, password
        self.security, self.timeout = security, timeout

    def describe(self) -> str:
        return f"smtp://{self.host}:{self.port} ({self.security})"

    def _connect(self) -> smtplib.SMTP:
        # Certificates are always verified; SMTP_CA_FILE adds a private CA for a self-signed server.
        ctx = ssl.create_default_context(cafile=self.ca_file or None)
        if self.security == "ssl":
            conn = smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=ctx)
        else:
            conn = smtplib.SMTP(self.host, self.port, timeout=self.timeout)
            conn.ehlo()
            if self.security == "starttls":
                conn.starttls(context=ctx)
                conn.ehlo()
        if self.username:
            conn.login(self.username, self.password)
        return conn

    def send(self, payload: dict, from_addr: str, from_name: str | None) -> SendResult:
        msg, rcpts, message_id = prepare(payload, from_addr, from_name)
        try:
            conn = self._connect()
            try:
                if isinstance(msg, bytes):
                    refused = conn.sendmail(from_addr, rcpts, msg)
                else:
                    refused = conn.send_message(msg, from_addr=from_addr, to_addrs=rcpts)
            finally:
                try:
                    conn.quit()
                except Exception:
                    pass
        except smtplib.SMTPAuthenticationError as e:
            # Treated as transient: the message is fine, the relay config is not. An admin can fix creds.
            raise TransientError(f"SMTP authentication failed ({e.smtp_code}): {_decode(e.smtp_error)}") from e
        except smtplib.SMTPRecipientsRefused as e:
            codes = [code for code, _ in e.recipients.values()]
            detail = "; ".join(f"{r}: {c} {_decode(m)}" for r, (c, m) in e.recipients.items())
            if codes and all(500 <= c < 600 for c in codes):
                raise PermanentError(f"All recipients refused: {detail}") from e
            raise TransientError(f"Recipients refused: {detail}") from e
        except smtplib.SMTPResponseException as e:
            text = f"SMTP {e.smtp_code}: {_decode(e.smtp_error)}"
            if 500 <= e.smtp_code < 600:
                raise PermanentError(text) from e
            raise TransientError(text) from e
        except (smtplib.SMTPException, OSError, socket.timeout, ssl.SSLError) as e:
            raise TransientError(f"{type(e).__name__}: {e}") from e

        if refused:
            err = (f"Delivered to {len(rcpts) - len(refused)} of {len(rcpts)} recipients; refused: "
                   + "; ".join(f"{r}: {c} {_decode(m)}" for r, (c, m) in refused.items()))
            return SendResult(provider_id=message_id, detail=err, partial_error=err)
        return SendResult(provider_id=message_id, detail="Accepted by the upstream SMTP server")


def _decode(v) -> str:
    return v.decode(errors="replace") if isinstance(v, (bytes, bytearray)) else str(v)
