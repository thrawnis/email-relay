"""SMTP submission ingress for apps that can only send mail over SMTP.

Apps authenticate with AUTH PLAIN/LOGIN: the username is informational (use the
app's name) and the password is the app's relay key. TLS is mandatory: STARTTLS
on the submission port (587) and/or implicit TLS on 465. AUTH is refused before
TLS, and MAIL is refused before AUTH.

Accepted messages go through exactly the same admission rules as the HTTP API
(allowed senders, recipient cap, rate limits), are logged, and are queued for
delivery with the original MIME preserved (inline images, headers, etc).
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import ssl
import threading
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, make_msgid, parseaddr

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, AuthResult, LoginPassword

from .config import Settings
from .security import clean_username
from .service import Relay
from .tls import describe_cert, resolve_tls_files

log = logging.getLogger("relay.smtp")


# ----------------------------------------------------------------- handler
def _addresses(msg, header: str) -> list[str]:
    return [a for _, a in getaddresses(msg.get_all(header, [])) if a]


class SubmissionHandler:
    def __init__(self, relay: Relay):
        self.relay = relay

    @staticmethod
    def _peer(session) -> str | None:
        return session.peer[0] if isinstance(session.peer, tuple) else str(session.peer)

    def authenticate(self, server, session, envelope, mechanism, auth_data) -> AuthResult:
        if not isinstance(auth_data, LoginPassword):
            return AuthResult(success=False, handled=False)
        username = clean_username(auth_data.login.decode(errors="replace")) or "(empty)"
        key, err = self.relay.authenticate(auth_data.password.decode(errors="replace"))
        if err:
            # Clients retry the same credentials with another mechanism (PLAIN, then LOGIN): log it once.
            fingerprint = (username, hashlib.sha256(auth_data.password).hexdigest())
            if getattr(session, "relay_last_failed", None) != fingerprint:
                session.relay_last_failed = fingerprint
                # Logged as a rejected attempt carrying the username that was typed.
                self.relay.reject(f"SMTP login failed: {err}", status_code=401, source="smtp", key=key,
                                  client_ip=self._peer(session), username=username)
                log.warning("SMTP AUTH failed from %s user=%r: %s", self._peer(session), username, err)
            return AuthResult(success=False, handled=False)
        session.relay_username = username  # remembered for every message sent on this connection
        return AuthResult(success=True, auth_data=key)

    async def handle_DATA(self, server, session, envelope) -> str:
        key = session.auth_data
        raw: bytes = envelope.content if isinstance(envelope.content, bytes) else envelope.content.encode()
        msg = BytesParser(policy=policy.SMTP).parsebytes(raw)

        from_addr = parseaddr(str(msg.get("From", "")))[1] or (envelope.mail_from or "")
        rcpts = list(dict.fromkeys(envelope.rcpt_tos))
        lower = {r.lower() for r in rcpts}
        to_hdr = [a for a in _addresses(msg, "To") if a.lower() in lower]
        cc_hdr = [a for a in _addresses(msg, "Cc") if a.lower() in lower]
        shown = {a.lower() for a in to_hdr + cc_hdr}
        recipients = {"to": to_hdr, "cc": cc_hdr, "bcc": [r for r in rcpts if r.lower() not in shown]}
        subject = str(msg.get("Subject", ""))[:998]

        # Never forward a Bcc header; make sure there is a Message-ID.
        if msg.get("Bcc") is not None:
            del msg["Bcc"]
            raw = msg.as_bytes(policy=policy.SMTP)
        if msg.get("Message-ID") is None:
            domain = from_addr.rsplit("@", 1)[-1] or "email-relay"
            raw = f"Message-ID: {make_msgid(domain=domain)}\r\n".encode() + raw

        payload = {"raw": base64.b64encode(raw).decode(), "envelope_to": rcpts, "subject": subject,
                   **recipients}
        adm = self.relay.admit(
            key=key, source="smtp", from_addr=from_addr, recipients=recipients, subject=subject,
            payload=payload,
            has_html=any(p.get_content_type() == "text/html" for p in msg.walk()),
            attachment_count=sum(1 for p in msg.walk() if p.get_content_disposition() == "attachment"),
            size_bytes=len(raw), client_ip=self._peer(session),
            username=getattr(session, "relay_username", None))
        if adm.ok:
            return f"250 2.0.0 OK queued as {adm.message_id}"
        if adm.status_code == 429:
            return f"451 4.7.1 {adm.error}"
        if adm.status_code == 403:
            return f"553 5.7.1 {adm.error}"
        return f"554 5.6.0 {adm.error}"


# ------------------------------------------------------------------ server
class _ImplicitTLSSMTP(SMTP):
    """aiosmtpd only tracks TLS negotiated via STARTTLS, so on an implicit-TLS port (465) it would
    refuse AUTH as 'not encrypted'. Mark sessions on an SSL transport as already encrypted."""

    def connection_made(self, transport) -> None:
        super().connection_made(transport)
        if transport.get_extra_info("ssl_object") is not None:
            self._tls_protocol = transport  # truthy marker: the session is encrypted
            self.session.ssl = {"ssl_object": transport.get_extra_info("ssl_object")}


class _ImplicitTLSController(Controller):
    def factory(self):
        return _ImplicitTLSSMTP(self.handler, **self.SMTP_kwargs)


class SubmissionServer:
    def __init__(self, relay: Relay, settings: Settings):
        self.relay, self.settings = relay, settings
        self.controllers: list[Controller] = []
        self.cert_path = self.key_path = ""
        self.ctx: ssl.SSLContext | None = None
        self._mtime = 0.0
        self._stop = threading.Event()

    def _load_cert(self) -> None:
        self.ctx.load_cert_chain(self.cert_path, self.key_path)
        self._mtime = max(os.path.getmtime(self.cert_path), os.path.getmtime(self.key_path))

    def _watch_cert(self) -> None:
        """Pick up renewed certificates (e.g. NPM's Let's Encrypt renewals) without a restart."""
        while not self._stop.wait(300):
            try:
                m = max(os.path.getmtime(self.cert_path), os.path.getmtime(self.key_path))
                if m != self._mtime:
                    self._load_cert()
                    log.info("Reloaded submission TLS certificate %s", self.cert_path)
            except Exception:
                log.exception("Could not reload submission TLS certificate")

    def start(self) -> None:
        s = self.settings
        if not s.submission_enabled:
            return
        self.cert_path, self.key_path = resolve_tls_files(s)
        self.ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self._load_cert()

        handler = SubmissionHandler(self.relay)
        common = dict(
            handler=handler, hostname=s.submission_bind, server_hostname=s.submission_hostname,
            ident="email-relay", authenticator=handler.authenticate, auth_required=True, auth_require_tls=True,
            data_size_limit=int(s.max_attachment_bytes * 1.4) + 2 * 1024 * 1024,
        )
        if s.submission_starttls_port:
            c = Controller(port=s.submission_starttls_port, tls_context=self.ctx, require_starttls=True, **common)
            c.start()
            self.controllers.append(c)
            log.info("SMTP submission (STARTTLS) listening on %s:%d", s.submission_bind, s.submission_starttls_port)
        if s.submission_tls_port:
            c = _ImplicitTLSController(port=s.submission_tls_port, ssl_context=self.ctx, **common)
            c.start()
            self.controllers.append(c)
            log.info("SMTP submission (implicit TLS) listening on %s:%d", s.submission_bind, s.submission_tls_port)
        threading.Thread(target=self._watch_cert, name="cert-watch", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        for c in self.controllers:
            try:
                c.stop()
            except Exception:
                log.exception("Error stopping SMTP controller")
        self.controllers.clear()

    def status(self) -> dict:
        s = self.settings
        out = {"enabled": s.submission_enabled, "starttls_port": s.submission_starttls_port or None,
               "tls_port": s.submission_tls_port or None, "running": bool(self.controllers)}
        if self.cert_path:
            out["certificate"] = {"path": self.cert_path, **describe_cert(self.cert_path)}
        return out
