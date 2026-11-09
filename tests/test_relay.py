import base64
import smtplib
import time

import pytest
from fastapi.testclient import TestClient

from app.backends import PermanentError, SendResult, TransientError
from app.backends.base import Backend, build_mime
from app.backends.smtp import SMTPBackend
from app.config import Settings
from app.main import create_app

PASSWORD = "test-admin-pw"


class FakeBackend(Backend):
    name = "fake"

    def __init__(self):
        self.sent = []
        self.fail_with = []  # exceptions to raise on successive calls

    def send(self, payload, from_addr, from_name):
        if self.fail_with:
            raise self.fail_with.pop(0)
        self.sent.append((payload, from_addr, from_name))
        return SendResult(provider_id=f"<fake-{len(self.sent)}@x>")


@pytest.fixture
def env(tmp_path):
    settings = Settings(admin_password=PASSWORD, secret_key="x" * 40, db_path=str(tmp_path / "t.db"),
                        mail_from="notify@thetruesource.com", mail_from_name="TTS",
                        mail_allowed_from=["notify@thetruesource.com", "*@apps.thetruesource.com"],
                        mail_backend="console", retry_schedule=[0], max_attempts=3)
    backend = FakeBackend()
    app = create_app(settings, backend)
    with TestClient(app) as client:
        yield client, backend, app


def login(client):
    assert client.post("/admin/api/login", json={"password": PASSWORD}).status_code == 200


def make_key(client, **kw):
    login(client)
    r = client.post("/admin/api/keys", json={"name": "billing", **kw})
    assert r.status_code == 201, r.text
    return r.json()


def wait_status(client, key, mid, want, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/messages/{mid}", headers={"Authorization": f"Bearer {key}"})
        if r.json()["status"] in want:
            return r.json()
        time.sleep(0.05)
    raise AssertionError(f"status never reached {want}: {r.json()}")


def send(client, key, **body):
    body = {"to": "a@example.com", "subject": "Hi", "text": "hello", **body}
    return client.post("/api/send", json=body, headers={"Authorization": f"Bearer {key}"})


def test_admin_requires_login(env):
    client, _, _ = env
    assert client.get("/admin/api/keys").status_code == 401
    assert client.post("/admin/api/login", json={"password": "nope"}).status_code == 401
    login(client)
    assert client.get("/admin/api/keys").status_code == 200


def test_key_shown_once_and_stored_hashed(env):
    client, _, app = env
    k = make_key(client)
    assert k["api_key"].startswith("erk_")
    listed = client.get("/admin/api/keys").json()
    assert "api_key" not in listed[0] and "key_hash" not in listed[0]
    row = app.state.db.query_one("SELECT key_hash FROM api_keys")
    assert k["api_key"] not in row["key_hash"] and len(row["key_hash"]) == 64


def test_send_happy_path(env):
    client, backend, _ = env
    key = make_key(client)["api_key"]
    r = send(client, key, cc=["c@example.com"], bcc="b@example.com", html="<b>hi</b>")
    assert r.status_code == 202, r.text
    st = wait_status(client, key, r.json()["id"], {"sent"})
    assert st["provider_id"] == "<fake-1@x>"
    payload, from_addr, from_name = backend.sent[0]
    assert from_addr == "notify@thetruesource.com" and from_name == "TTS"
    assert payload["bcc"] == ["b@example.com"]
    # payload (body) is dropped after delivery, metadata stays
    m = client.get(f"/admin/api/messages/{r.json()['id']}").json()
    assert m["payload"] is None and m["subject"] == "Hi" and m["recipients"]["cc"] == ["c@example.com"]
    assert [e["event"] for e in m["events"]] == ["queued", "attempt", "sent"]


def test_invalid_and_revoked_keys_rejected_and_logged(env):
    client, _, _ = env
    assert send(client, "erk_bogus").status_code == 401
    k = make_key(client)
    client.post(f"/admin/api/keys/{k['id']}/revoke")
    assert send(client, k["api_key"]).status_code == 403
    items = client.get("/admin/api/messages?status=rejected").json()["items"]
    assert len(items) == 2
    assert {i["app_name"] for i in items} == {"(unauthenticated)", "billing"}


def test_validation_errors_logged(env):
    client, _, _ = env
    key = make_key(client)["api_key"]
    r = client.post("/api/send", json={"to": "not-an-email", "subject": "x", "text": "y"},
                    headers={"X-API-Key": key})
    assert r.status_code == 422 and "to" in r.json()["error"]
    r = send(client, key, text=None)
    assert r.status_code == 422
    items = client.get("/admin/api/messages?app=billing").json()["items"]
    assert all(i["status"] == "rejected" for i in items) and len(items) == 2


def test_from_restrictions(env):
    client, _, _ = env
    key = make_key(client, allowed_from=["*@apps.thetruesource.com"])["api_key"]
    assert send(client, key, **{"from": "evil@gmail.com"}).status_code == 403
    assert send(client, key).status_code == 403  # default sender isn't in this key's list
    assert send(client, key, **{"from": "billing@apps.thetruesource.com"}).status_code == 202


def test_rate_limit(env):
    client, _, _ = env
    key = make_key(client, rate_per_minute=2)["api_key"]
    assert send(client, key).status_code == 202
    assert send(client, key).status_code == 202
    r = send(client, key)
    assert r.status_code == 429 and r.headers["retry-after"] == "60"


def test_attachments(env):
    client, backend, _ = env
    key = make_key(client)["api_key"]
    content = base64.b64encode(b"%PDF-1.4 fake").decode()
    r = send(client, key, attachments=[{"filename": "a.pdf", "content": content, "content_type": "application/pdf"}])
    assert r.status_code == 202
    wait_status(client, key, r.json()["id"], {"sent"})
    mime = build_mime(backend.sent[0][0], "notify@thetruesource.com", None)
    atts = list(mime.iter_attachments())
    assert atts[0].get_filename() == "a.pdf" and atts[0].get_content() == b"%PDF-1.4 fake"
    assert send(client, key, attachments=[{"filename": "x", "content": "!!!"}]).status_code == 422


def test_transient_retry_then_success(env):
    client, backend, _ = env
    key = make_key(client)["api_key"]
    backend.fail_with = [TransientError("421 try later")]
    r = send(client, key)
    st = wait_status(client, key, r.json()["id"], {"sent"})
    assert st["attempts"] == 2


def test_gives_up_after_max_attempts_and_admin_retry(env):
    client, backend, _ = env
    key = make_key(client)["api_key"]
    backend.fail_with = [TransientError("down")] * 3
    mid = send(client, key).json()["id"]
    st = wait_status(client, key, mid, {"failed"})
    assert st["attempts"] == 3 and "Gave up" in st["error"]
    assert client.get(f"/admin/api/messages/{mid}").json()["retryable"]
    assert client.post(f"/admin/api/messages/{mid}/retry").status_code == 200
    wait_status(client, key, mid, {"sent"})


def test_permanent_failure_not_retried(env):
    client, backend, _ = env
    key = make_key(client)["api_key"]
    backend.fail_with = [PermanentError("550 no such user")]
    st = wait_status(client, key, send(client, key).json()["id"], {"failed"})
    assert st["attempts"] == 1 and "550" in st["error"]


def test_status_endpoint_scoped_to_own_key(env):
    client, _, _ = env
    a = make_key(client)["api_key"]
    b = client.post("/admin/api/keys", json={"name": "other"}).json()["api_key"]
    mid = send(client, a).json()["id"]
    assert client.get(f"/api/messages/{mid}", headers={"X-API-Key": b}).status_code == 404


def test_log_search(env):
    client, _, _ = env
    key = make_key(client)["api_key"]
    send(client, key, subject="Invoice 42", to="alice@example.com")
    send(client, key, subject="Welcome", to="bob@example.com")
    assert client.get("/admin/api/messages?q=invoice").json()["total"] == 1
    assert client.get("/admin/api/messages?q=bob@").json()["total"] == 1
    assert client.get("/admin/api/messages?status=queued,sending,sent").json()["total"] == 2


def test_rename_key(env):
    client, _, _ = env
    k = make_key(client)
    r = client.patch(f"/admin/api/keys/{k['id']}", json={"name": "billing-v2", "rate_per_day": 100})
    assert r.json()["name"] == "billing-v2" and r.json()["rate_per_day"] == 100


def test_header_injection_blocked(env):
    client, _, _ = env
    key = make_key(client)["api_key"]
    assert send(client, key, subject="Hi\r\nBcc: x@evil.com").status_code == 422


def test_smtp_error_classification(monkeypatch):
    b = SMTPBackend("h", 25, "", "", "none", 5)
    payload = {"to": ["a@x.com"], "cc": [], "bcc": [], "subject": "s", "text": "t"}

    def boom(exc):
        def _c(self):
            raise exc
        return _c

    monkeypatch.setattr(SMTPBackend, "_connect", boom(smtplib.SMTPResponseException(550, b"nope")))
    with pytest.raises(PermanentError):
        b.send(payload, "n@x.com", None)
    monkeypatch.setattr(SMTPBackend, "_connect", boom(smtplib.SMTPResponseException(451, b"later")))
    with pytest.raises(TransientError):
        b.send(payload, "n@x.com", None)
    monkeypatch.setattr(SMTPBackend, "_connect", boom(ConnectionRefusedError("refused")))
    with pytest.raises(TransientError):
        b.send(payload, "n@x.com", None)
    monkeypatch.setattr(SMTPBackend, "_connect", boom(smtplib.SMTPAuthenticationError(535, b"bad creds")))
    with pytest.raises(TransientError):
        b.send(payload, "n@x.com", None)


@pytest.fixture
def proxied(tmp_path):
    settings = Settings(admin_password=PASSWORD, secret_key="x" * 40, db_path=str(tmp_path / "p.db"),
                        mail_from="notify@thetruesource.com", mail_allowed_from=["notify@thetruesource.com"],
                        mail_backend="console", trust_proxy=True, require_https=True, cookie_secure=True)
    app = create_app(settings, FakeBackend())
    with TestClient(app, base_url="http://relay") as client:
        yield client, app


HTTPS = {"X-Forwarded-Proto": "https", "X-Real-IP": "10.0.0.5"}
TUNNEL = {**HTTPS, "CF-Connecting-IP": "203.0.113.9", "CF-Ray": "abc"}


def test_require_https_rejects_plain_http(proxied):
    client, app = proxied
    assert client.get("/admin").status_code == 403
    assert client.get("/admin", headers={"X-Forwarded-Proto": "http"}).status_code == 403
    r = client.post("/api/send", json={}, headers={"X-Forwarded-Proto": "http"})
    assert r.status_code == 403
    assert app.state.db.query_one("SELECT error FROM messages")["error"].startswith("HTTPS required")
    assert client.get("/healthz").status_code == 200  # healthcheck stays reachable
    r = client.get("/admin", headers=HTTPS)
    assert r.status_code == 200 and "max-age" in r.headers["strict-transport-security"]


def test_https_via_proxy_send_and_client_ip(proxied):
    client, app = proxied
    client.post("/admin/api/login", json={"password": PASSWORD}, headers=HTTPS)
    # Secure cookie: the TestClient (plain http base_url) won't resend it, so pass it explicitly
    cookie = client.cookies.get("relay_admin")
    key = client.post("/admin/api/keys", json={"name": "svc"}, headers=HTTPS,
                      cookies={"relay_admin": cookie}).json()["api_key"]
    r = client.post("/api/send", json={"to": "a@b.com", "subject": "s", "text": "t"},
                    headers={**HTTPS, "Authorization": f"Bearer {key}"})
    assert r.status_code == 202
    assert app.state.db.get_message(r.json()["id"])["client_ip"] == "10.0.0.5"


def test_api_blocked_through_cloudflare_tunnel(proxied):
    client, app = proxied
    r = client.post("/api/send", json={"to": "a@b.com"}, headers={**TUNNEL, "Authorization": "Bearer x"})
    assert r.status_code == 403
    row = app.state.db.query_one("SELECT app_name, client_ip FROM messages")
    assert row == {"app_name": "(via Cloudflare)", "client_ip": "203.0.113.9"}
    assert client.get("/api/messages/x", headers=TUNNEL).status_code == 403
    # admin UI is still reachable through the tunnel
    assert client.get("/admin", headers=TUNNEL).status_code == 200
    assert client.post("/admin/api/login", json={"password": PASSWORD}, headers=TUNNEL).status_code == 200


def test_require_https_needs_trust_proxy(tmp_path):
    s = Settings(admin_password="p", secret_key="x" * 40, mail_from="a@b.com", mail_backend="console",
                 db_path=str(tmp_path / "x.db"), require_https=True)
    with pytest.raises(RuntimeError, match="TRUST_PROXY"):
        create_app(s, FakeBackend())


def test_trusted_proxies_only(tmp_path):
    # TestClient's peer address is "testclient", which is not in TRUSTED_PROXIES -> headers ignored
    s = Settings(admin_password=PASSWORD, secret_key="x" * 40, db_path=str(tmp_path / "tp.db"),
                 mail_from="notify@thetruesource.com", mail_backend="console", trust_proxy=True,
                 require_https=True, trusted_proxies=["192.168.1.10"])
    with TestClient(create_app(s, FakeBackend())) as client:
        # spoofed X-Forwarded-Proto from an untrusted peer does not count as HTTPS
        assert client.get("/admin", headers={"X-Forwarded-Proto": "https"}).status_code == 403
    with TestClient(create_app(s, FakeBackend()), base_url="https://relay") as client:
        assert client.get("/admin").status_code == 200  # real TLS to the relay itself is fine


def test_self_signed_covers_both_hostnames(tmp_path):
    from app.tls import describe_cert, resolve_tls_files
    s = Settings(db_path=str(tmp_path / "x.db"), public_hostname="relay.example.com",
                 submission_hostname="smtp.example.com")
    cert, _ = resolve_tls_files(s)
    assert {"relay.example.com", "smtp.example.com"} <= set(describe_cert(cert)["names"])
    s.submission_hostname = "smtp2.example.com"  # hostname change -> regenerated
    cert, _ = resolve_tls_files(s)
    assert "smtp2.example.com" in describe_cert(cert)["names"]
