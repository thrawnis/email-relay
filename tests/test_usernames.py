import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import Database
from app.main import create_app
from app.security import slugify_username
from tests.test_relay import PASSWORD, FakeBackend


@pytest.mark.parametrize("name,expected", [
    ("Billing", "billing"),
    ("Café Ünïcode App!", "cafe-unicode-app"),
    ("  My   Cool_App  ", "my-cool-app"),
    ("Straße Œuvre Ørsted Łódź", "strasse-oeuvre-orsted-lodz"),
    ("São Paulo — Relatórios", "sao-paulo-relatorios"),
    ("ＡＢＣ　１２３", "abc-123"),                      # full-width characters
    ("日本語", "app"),                                  # nothing ASCII left
    ("!!!", "app"),
    ("a" * 80, "a" * 32),
    ("x-" * 30, "x-x-x-x-x-x-x-x-x-x-x-x-x-x-x-x"),  # truncated without a trailing hyphen
])
def test_slugify(name, expected):
    out = slugify_username(name)
    assert out == expected
    assert out.isascii() and out == out.lower() and " " not in out


@pytest.fixture
def client(tmp_path):
    s = Settings(admin_password=PASSWORD, secret_key="x" * 40, db_path=str(tmp_path / "u.db"),
                 mail_from="notify@example.com", mail_backend="console")
    with TestClient(create_app(s, FakeBackend()), base_url="https://testserver") as c:
        c.post("/admin/api/login", json={"password": PASSWORD})
        yield c


def test_username_derived_unique_and_follows_rename(client):
    a = client.post("/admin/api/keys", json={"name": "Café Ünï"}).json()
    b = client.post("/admin/api/keys", json={"name": "cafe uni"}).json()
    assert a["username"] == "cafe-uni" and b["username"] == "cafe-uni-2"
    assert a["name"] == "Café Ünï"  # display name is kept as typed
    r = client.patch(f"/admin/api/keys/{b['id']}", json={"name": "Reporting Tool"}).json()
    assert r["username"] == "reporting-tool"
    # renaming a key to its own slug does not collide with itself
    r = client.patch(f"/admin/api/keys/{a['id']}", json={"name": "CAFE UNI"}).json()
    assert r["username"] == "cafe-uni"


def test_existing_keys_get_backfilled_usernames(tmp_path):
    import sqlite3
    path = str(tmp_path / "old.db")
    c = sqlite3.connect(path)
    c.executescript("""CREATE TABLE api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
        key_prefix TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, created_at REAL NOT NULL, revoked_at REAL,
        last_used_at REAL, rate_per_minute INTEGER, rate_per_day INTEGER, allowed_from TEXT, notes TEXT);
        INSERT INTO api_keys (name,key_prefix,key_hash,created_at) VALUES ('Grafana Alerts','erk_a','h1',0),
          ('grafana  alerts','erk_b','h2',0),('Wiki','erk_c','h3',0);""")
    c.commit(); c.close()
    db = Database(path)
    by_id = {k["id"]: k["username"] for k in db.list_keys()}
    assert by_id == {1: "grafana-alerts", 2: "grafana-alerts-2", 3: "wiki"}  # oldest key keeps the plain name


def test_timeseries_endpoint(client):
    import time
    a = client.post("/admin/api/keys", json={"name": "alpha"}).json()
    b = client.post("/admin/api/keys", json={"name": "beta"}).json()
    db = client.app.state.db
    now = time.time()
    for key, status, age_days in [(a, "sent", 0), (a, "sent", 0), (a, "failed", 1), (b, "partial", 1),
                                  (b, "sent", 3), (b, "rejected", 0), (b, "queued", 0)]:
        mid = db.insert_message(key_id=key["id"], app_name=key["name"], from_addr="n@example.com",
                                recipients={"to": ["x@example.com"]}, subject="s", status=status)
        db.query_one("SELECT 1")  # keep the helper simple: backdate directly
        with db.tx() as c:
            c.execute("UPDATE messages SET created_at = ? WHERE id = ?", (now - age_days * 86400, mid))
    r = client.get(f"/admin/api/stats/timeseries?since={now - 5 * 86400}&until={now + 60}").json()
    ok = sum(x["ok"] for x in r["buckets"])
    bad = sum(x["bad"] for x in r["buckets"])
    assert (ok, bad) == (3, 2)  # rejected and queued are excluded
    assert [k["username"] for k in r["keys"]] == ["alpha", "beta"]
    assert client.get("/admin/api/stats/timeseries?since=10&until=5").status_code == 422
    assert client.get("/admin/api/stats/timeseries?since=0&until=999999999").status_code == 422


def test_assets_are_versioned_and_revalidated(client):
    import re
    html = client.get("/admin").text
    versions = re.findall(r'/static/(?:style\.css|charts\.js|app\.js)\?v=([0-9a-f]{12})', html)
    assert len(versions) == 3 and len(set(versions)) == 1 and "{{v}}" not in html
    assert 'data-tab="charts"' not in html and 'id="charts-section"' in html
    assert client.get("/admin").headers["cache-control"] == "no-store"
    r = client.get(f"/static/app.js?v={versions[0]}")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-cache"
    assert "etag" in r.headers


def test_log_filter_by_key_id(client):
    a = client.post("/admin/api/keys", json={"name": "alpha"}).json()
    b = client.post("/admin/api/keys", json={"name": "beta"}).json()
    quiet = client.post("/admin/api/keys", json={"name": "quiet"}).json()  # never sent anything
    db = client.app.state.db
    for key, n in ((a, 3), (b, 2)):
        for _ in range(n):
            db.insert_message(key_id=key["id"], app_name=key["name"], from_addr="n@example.com",
                              recipients={"to": ["x@example.com"]}, subject="s", status="sent")
    db.insert_message(key_id=None, app_name="(unauthenticated)", from_addr=None, recipients={}, subject=None,
                      status="rejected", error="bad key")

    def get(**q):
        from urllib.parse import urlencode
        return client.get("/admin/api/messages?" + urlencode(q)).json()

    assert get(key_id=a["id"])["total"] == 3 and {m["app_name"] for m in get(key_id=a["id"])["items"]} == {"alpha"}
    assert get(key_id=b["id"])["total"] == 2
    assert get(key_id=quiet["id"])["total"] == 0          # a key with no entries shows nothing, not everything
    assert get(key_id="none")["total"] == 1               # unknown-key attempts
    assert get(key_id="")["total"] == 6                   # no filter
    # renaming a key must not detach its history from the filter
    client.patch(f"/admin/api/keys/{a['id']}", json={"name": "alpha renamed"})
    assert get(key_id=a["id"])["total"] == 3
    assert client.get("/admin/api/messages?key_id=abc").status_code == 422
