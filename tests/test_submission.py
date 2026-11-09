import base64
import smtplib
import socket
import ssl
import time
from email.message import EmailMessage

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.test_relay import PASSWORD, FakeBackend


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def smtp_env(tmp_path):
    settings = Settings(admin_password=PASSWORD, secret_key="x" * 40, db_path=str(tmp_path / "s.db"),
                        mail_from="notify@thetruesource.com", mail_allowed_from=["notify@thetruesource.com"],
                        mail_backend="console", retry_schedule=[0], public_hostname="localhost",
                        submission_enabled=True, submission_bind="127.0.0.1",
                        submission_starttls_port=free_port(), submission_tls_port=free_port())
    backend = FakeBackend()
    app = create_app(settings, backend)
    with TestClient(app, base_url="https://testserver") as client:
        client.post("/admin/api/login", json={"password": PASSWORD})
        key = client.post("/admin/api/keys", json={"name": "gitea", "rate_per_minute": 2}).json()["api_key"]
        yield client, backend, app, settings, key


def tls_ctx(settings):
    ctx = ssl.create_default_context(cafile=str(settings.db_path).rsplit("/", 1)[0] + "/tls/selfsigned.crt")
    return ctx  # hostname 'localhost' is in the self-signed cert's SANs, so full verification works


def make_msg(**kw):
    m = EmailMessage()
    m["From"] = kw.get("frm", "Gitea <notify@thetruesource.com>")
    m["To"] = "alice@example.com"
    m["Cc"] = "carol@example.com"
    m["Bcc"] = "secret@example.com"
    m["Subject"] = kw.get("subject", "Build passed")
    m.set_content("plain body")
    m.add_alternative("<p>html body</p>", subtype="html")
    m.add_attachment(b"log data", maintype="text", subtype="plain", filename="build.log")
    return m


def wait_until(fn, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return
        time.sleep(0.05)
    raise AssertionError("condition not met")


def test_starttls_submission_delivers_original_mime(smtp_env):
    client, backend, app, settings, key = smtp_env
    with smtplib.SMTP("localhost", settings.submission_starttls_port, timeout=5) as s:
        s.ehlo()
        with pytest.raises(smtplib.SMTPException):  # AUTH not offered before TLS
            s.login("gitea", key)
        s.starttls(context=tls_ctx(settings))
        s.ehlo()
        s.login("gitea", key)
        s.send_message(make_msg())
    wait_until(lambda: backend.sent)
    payload, from_addr, _ = backend.sent[0]
    raw = base64.b64decode(payload["raw"])
    assert from_addr == "notify@thetruesource.com"
    assert sorted(payload["envelope_to"]) == ["alice@example.com", "carol@example.com", "secret@example.com"]
    assert b"Bcc:" not in raw and b"secret@example.com" not in raw
    assert b"build.log" in raw and b"Message-ID" in raw.split(b"\r\n\r\n")[0]

    items = client.get("/admin/api/messages").json()["items"]
    m = items[0]
    assert m["source"] == "smtp" and m["app_name"] == "gitea" and m["has_html"] and m["attachment_count"] == 1
    assert m["recipients"] == {"to": ["alice@example.com"], "cc": ["carol@example.com"],
                               "bcc": ["secret@example.com"]}
    wait_until(lambda: client.get(f"/admin/api/messages/{m['id']}").json()["status"] == "sent")


def test_implicit_tls_port(smtp_env):
    client, backend, app, settings, key = smtp_env
    with smtplib.SMTP_SSL("localhost", settings.submission_tls_port, timeout=5,
                          context=tls_ctx(settings)) as s:
        s.login("gitea", key)
        s.send_message(make_msg())
    wait_until(lambda: backend.sent)


def test_auth_required_and_bad_key_logged(smtp_env):
    client, backend, app, settings, key = smtp_env
    with smtplib.SMTP("localhost", settings.submission_starttls_port, timeout=5) as s:
        s.starttls(context=tls_ctx(settings))
        s.ehlo()
        code, _ = s.mail("notify@thetruesource.com")
        assert code == 530  # MAIL before AUTH
        with pytest.raises(smtplib.SMTPAuthenticationError):
            s.login("gitea", "erk_wrong")
    rejected = client.get("/admin/api/messages?status=rejected").json()["items"]
    assert rejected and "SMTP AUTH failed" in rejected[0]["error"] and rejected[0]["source"] == "smtp"


def test_disallowed_from_and_rate_limit(smtp_env):
    client, backend, app, settings, key = smtp_env
    with smtplib.SMTP_SSL("localhost", settings.submission_tls_port, timeout=5, context=tls_ctx(settings)) as s:
        s.login("gitea", key)
        with pytest.raises(smtplib.SMTPDataError) as e:
            s.send_message(make_msg(frm="someone@gmail.com"))
        assert e.value.smtp_code == 553
        s.send_message(make_msg())
        s.send_message(make_msg())
        with pytest.raises(smtplib.SMTPDataError) as e:  # rate_per_minute=2
            s.send_message(make_msg())
        assert e.value.smtp_code == 451


def test_connect_info(smtp_env):
    client, _, _, settings, _ = smtp_env
    info = client.get("/admin/api/connect-info").json()
    assert info["api"]["send_url"] == "https://localhost/api/send"
    assert info["smtp"]["running"] and info["smtp"]["starttls_port"] == settings.submission_starttls_port
    assert info["smtp"]["certificate"]["self_signed"]
    assert "smtp_password" not in str(info).lower()


def test_smtp_backend_forwards_raw_bytes(monkeypatch):
    from app.backends.smtp import SMTPBackend

    calls = {}

    class FakeConn:
        def sendmail(self, frm, rcpts, data):
            calls.update(frm=frm, rcpts=rcpts, data=data)
            return {}

        def quit(self):
            pass

    monkeypatch.setattr(SMTPBackend, "_connect", lambda self: FakeConn())
    raw = b"Message-ID: <abc@x>\r\nFrom: notify@thetruesource.com\r\nTo: a@x.com\r\nSubject: s\r\n\r\nbody\r\n"
    res = SMTPBackend("h", 587, "", "", "starttls", 5).send(
        {"raw": base64.b64encode(raw).decode(), "envelope_to": ["a@x.com", "hidden@x.com"]},
        "notify@thetruesource.com", None)
    assert calls == {"frm": "notify@thetruesource.com", "rcpts": ["a@x.com", "hidden@x.com"], "data": raw}
    assert res.provider_id == "<abc@x>"
