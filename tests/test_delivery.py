"""End-to-end delivery outcomes against a real (local) upstream SMTP server."""
import asyncio
import socket

import pytest
from aiosmtpd.controller import Controller

from app.backends.smtp import SMTPBackend
from app.config import Settings
from app.db import Database
from app.worker import Worker


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Upstream:
    def __init__(self, mode):
        self.mode = mode

    async def handle_RCPT(self, server, session, envelope, address, opts):
        if self.mode == "rcpt550" or (self.mode == "partial" and address.startswith("bad")):
            return "550 5.1.1 no such user"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        return {"data451": "451 4.3.0 try later", "data554": "554 5.7.1 rejected"}.get(self.mode, "250 OK")


def deliver(mode, to):
    port = free_port()
    ctl = None
    if mode != "refused":
        ctl = Controller(Upstream(mode), hostname="127.0.0.1", port=port)
        ctl.start()
    try:
        db = Database(":memory:")
        s = Settings(db_path=":memory:", mail_from="n@example.com", retry_schedule=[0], max_attempts=3)
        w = Worker(db, SMTPBackend("127.0.0.1", port, "", "", "none", 5), s)
        mid = db.insert_message(key_id=1, app_name="t", from_addr="n@example.com", recipients={"to": to},
                                subject="s", status="queued",
                                payload={"to": to, "cc": [], "bcc": [], "subject": "s", "text": "t"})

        async def run():
            for _ in range(5):
                await w.drain()
        asyncio.run(run())
        return db.get_message(mid), [e["event"] for e in db.get_events(mid)]
    finally:
        if ctl:
            ctl.stop()


@pytest.mark.parametrize("mode,status,attempts,err", [
    ("ok", "sent", 1, None),
    ("refused", "failed", 3, "Gave up after 3 attempts"),
    ("data451", "failed", 3, "451"),
    ("data554", "failed", 1, "554"),
    ("rcpt550", "failed", 1, "All recipients refused"),
])
def test_outcomes(mode, status, attempts, err):
    m, events = deliver(mode, ["a@x.com"])
    assert (m["status"], m["attempts"]) == (status, attempts)
    if err:
        assert err in m["error"]
    else:
        assert m["error"] is None
    assert events[-1] == status


def test_partial_recipient_refusal_is_not_reported_as_sent():
    m, events = deliver("partial", ["a@x.com", "bad@x.com"])
    assert m["status"] == "partial"
    assert "1 of 2" in m["error"] and "bad@x.com" in m["error"] and "550" in m["error"]
    assert events[-1] == "partial"
