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
                        mail_from="notify@example.com", mail_allowed_from=["notify@example.com"],
                        mail_backend="console", retry_schedule=[0], public_hostname="localhost",
                        submission_enabled=True, submission_bind="127.0.0.1",
                        submission_starttls_port=free_port(), submission_tls_port=free_port(),
                        submission_plain_port=free_port())
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
    m["From"] = kw.get("frm", "Gitea <notify@example.com>")
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
    assert from_addr == "notify@example.com"
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
        code, _ = s.mail("notify@example.com")
        assert code == 530  # MAIL before AUTH
        with pytest.raises(smtplib.SMTPAuthenticationError):
            s.login("gitea", "erk_wrong")
    rejected = client.get("/admin/api/messages?status=rejected").json()["items"]
    assert rejected and "SMTP login failed" in rejected[0]["error"] and rejected[0]["source"] == "smtp"


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
    raw = b"Message-ID: <abc@x>\r\nFrom: notify@example.com\r\nTo: a@x.com\r\nSubject: s\r\n\r\nbody\r\n"
    res = SMTPBackend("h", 587, "", "", "starttls", 5).send(
        {"raw": base64.b64encode(raw).decode(), "envelope_to": ["a@x.com", "hidden@x.com"]},
        "notify@example.com", None)
    assert calls == {"frm": "notify@example.com", "rcpts": ["a@x.com", "hidden@x.com"], "data": raw}
    assert res.provider_id == "<abc@x>"


def _log(client, **q):
    from urllib.parse import urlencode
    return client.get("/admin/api/messages?" + urlencode(q)).json()["items"]


def test_failed_smtp_logins_record_the_attempted_username(smtp_env):
    client, backend, app, settings, key = smtp_env
    with smtplib.SMTP("localhost", settings.submission_starttls_port, timeout=5) as s:
        s.starttls(context=tls_ctx(settings))
        s.ehlo()
        for user in ("Hacker@Example.com", "root", "adm\x07in"):
            with pytest.raises(smtplib.SMTPAuthenticationError):
                s.login(user, "erk_wrong")
            s.ehlo()
    rows = _log(client, status="rejected")
    assert sorted(r["username"] for r in rows) == ["Hacker@Example.com", "admin", "root"]  # once each; control chars stripped
    assert all(r["source"] == "smtp" and r["app_name"] == "(unauthenticated)" and "SMTP login failed" in r["error"]
               and r["client_ip"] for r in rows)
    assert [r["username"] for r in _log(client, q="hacker")] == ["Hacker@Example.com"]  # searchable

    # a revoked key is attributed to its app, still with the typed username
    k = client.get("/admin/api/keys").json()[0]
    client.post(f"/admin/api/keys/{k['id']}/revoke")
    with smtplib.SMTP("localhost", settings.submission_starttls_port, timeout=5) as s:
        s.starttls(context=tls_ctx(settings))
        s.ehlo()
        with pytest.raises(smtplib.SMTPAuthenticationError):
            s.login("old-gitea-name", key)
    row = _log(client, q="old-gitea-name")[0]
    assert row["app_name"] == "gitea" and row["username"] == "old-gitea-name" and "revoked" in row["error"]


def test_username_recorded_on_accepted_and_rejected_sends(smtp_env):
    client, backend, app, settings, key = smtp_env
    with smtplib.SMTP_SSL("localhost", settings.submission_tls_port, timeout=5, context=tls_ctx(settings)) as s:
        s.login("Typed-By-App", key)
        s.send_message(make_msg())
        with pytest.raises(smtplib.SMTPDataError):
            s.send_message(make_msg(frm="someone@gmail.com"))
    rows = _log(client)
    assert len(rows) == 2 and {r["username"] for r in rows} == {"Typed-By-App"}
    assert {r["status"] for r in rows} == {"queued", "rejected"} or {r["status"] for r in rows} == {"sent", "rejected"}


def test_api_attempts_carry_the_key_username(smtp_env):
    client, backend, app, settings, key = smtp_env
    client.post("/api/send", json={"to": "a@b.com", "subject": "s", "text": "t", "from": "evil@gmail.com"},
                headers={"Authorization": f"Bearer {key}"})
    client.post("/api/send", json={"to": "a@b.com"}, headers={"Authorization": "Bearer erk_nope"})
    by_app = {r["app_name"]: r["username"] for r in _log(client, status="rejected")}
    assert by_app == {"gitea": "gitea", "(unauthenticated)": None}
    detail = client.get(f"/admin/api/messages/{_log(client, q='gitea')[0]['id']}").json()
    assert detail["username"] == "gitea"


def _smtp_plain(settings):
    return smtplib.SMTP("localhost", settings.submission_plain_port, timeout=5)


def test_plain_port_refuses_keys_that_are_not_allowed(smtp_env):
    client, backend, app, settings, key = smtp_env
    with _smtp_plain(settings) as s:
        s.ehlo()
        assert "starttls" not in s.esmtp_features  # no encryption offered at all
        with pytest.raises(smtplib.SMTPAuthenticationError) as e:
            s.login("gitea", key)  # valid key, but unencrypted SMTP is off for it (the default)
        assert e.value.smtp_code == 535
    rows = _log(client, status="rejected")
    assert len(rows) == 1 and rows[0]["source"] == "smtp-plain" and rows[0]["username"] == "gitea"
    assert rows[0]["app_name"] == "gitea" and "not allowed to connect without encryption" in rows[0]["error"]
    assert not backend.sent


def test_key_setting_defaults_to_false_and_enables_plain_login(smtp_env):
    client, backend, app, settings, key = smtp_env
    k = client.get("/admin/api/keys").json()[0]
    assert k["allow_plaintext_smtp"] is False
    r = client.patch(f"/admin/api/keys/{k['id']}", json={"allow_plaintext_smtp": True}).json()
    assert r["allow_plaintext_smtp"] is True

    with _smtp_plain(settings) as s:
        s.login("Gitea", key)
        s.send_message(make_msg())
    wait_until(lambda: backend.sent)
    m = _log(client, status="queued,sent")[0]
    assert m["source"] == "smtp-plain" and m["username"] == "Gitea" and m["app_name"] == "gitea"

    # a wrong key is still refused on the plain port
    with _smtp_plain(settings) as s:
        with pytest.raises(smtplib.SMTPAuthenticationError):
            s.login("gitea", "erk_wrong")

    # turning it off again takes effect immediately; the encrypted ports keep working either way
    client.patch(f"/admin/api/keys/{k['id']}", json={"allow_plaintext_smtp": False})
    with _smtp_plain(settings) as s:
        with pytest.raises(smtplib.SMTPAuthenticationError):
            s.login("gitea", key)
    with smtplib.SMTP_SSL("localhost", settings.submission_tls_port, timeout=5, context=tls_ctx(settings)) as s:
        s.login("gitea", key)


def test_renaming_a_key_does_not_change_the_plaintext_setting(smtp_env):
    client, _, _, _, _ = smtp_env
    k = client.post("/admin/api/keys", json={"name": "legacy", "allow_plaintext_smtp": True}).json()
    assert k["allow_plaintext_smtp"] is True
    r = client.patch(f"/admin/api/keys/{k['id']}", json={"name": "legacy 2"}).json()
    assert r["allow_plaintext_smtp"] is True


def test_connect_info_and_port_validation(smtp_env, tmp_path):
    client, _, _, settings, _ = smtp_env
    assert client.get("/admin/api/connect-info").json()["smtp"]["plain_port"] == settings.submission_plain_port
    with pytest.raises(RuntimeError, match="must differ"):
        create_app(Settings(admin_password="p", secret_key="x" * 40, mail_from="a@b.com", mail_backend="console",
                            db_path=str(tmp_path / "d.db"), submission_starttls_port=2525, submission_plain_port=2525),
                   FakeBackend())
