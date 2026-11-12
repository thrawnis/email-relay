import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.test_relay import PASSWORD, FakeBackend


def make(tmp_path, **kw):
    s = Settings(admin_password=PASSWORD, secret_key="x" * 40, db_path=str(tmp_path / "r.db"),
                 mail_from="n@example.com", mail_allowed_from=["n@example.com"], mail_backend="console", **kw)
    return TestClient(create_app(s, FakeBackend()), base_url="https://testserver")


def key(client, **body):
    client.post("/admin/api/login", json={"password": PASSWORD})
    return client.post("/admin/api/keys", json={"name": body.pop("name", "app"), **body}).json()


def send(client, k, n=1):
    out = []
    for _ in range(n):
        out.append(client.post("/api/send", json={"to": "a@b.com", "subject": "s", "text": "t"},
                               headers={"Authorization": f"Bearer {k['api_key']}"}))
    return out


def backdate(client, key_id, seconds):
    with client.app.state.db.tx() as c:
        c.execute("UPDATE messages SET created_at = created_at - ? WHERE key_id = ?", (seconds, key_id))


def test_new_keys_are_limited_by_the_relay_default(tmp_path):
    with make(tmp_path, default_rate_per_minute=5, default_rate_per_day=1000, global_rate_per_minute=0) as c:
        k = key(c)  # no limits set on the key at all
        assert k["rate_per_minute"] is None
        codes = [r.status_code for r in send(c, k, 7)]
        assert codes == [202] * 5 + [429] * 2


def test_zero_means_unlimited_and_overrides_win(tmp_path):
    with make(tmp_path, default_rate_per_minute=2, default_rate_per_day=2, global_rate_per_minute=0) as c:
        unlimited = key(c, name="unlimited", rate_per_minute=0, rate_per_day=0)
        assert all(r.status_code == 202 for r in send(c, unlimited, 15))
        higher = key(c, name="higher", rate_per_minute=20, rate_per_day=20)
        assert all(r.status_code == 202 for r in send(c, higher, 6))


def test_burst_limit_stops_a_spike_inside_the_minute_quota(tmp_path):
    with make(tmp_path, default_rate_per_minute=60, global_rate_per_minute=0) as c:
        k = key(c, rate_per_minute=60)           # burst = 20 per 10 seconds
        codes = [r.status_code for r in send(c, k, 25)]
        assert codes == [202] * 20 + [429] * 5
        err = send(c, k)[0]
        assert "20 messages in 10 seconds" in err.json()["error"] and 1 <= int(err.headers["retry-after"]) <= 11
        backdate(c, k["id"], 11)                  # the spike is now outside the 10-second window
        assert send(c, k)[0].status_code == 202   # ...and the minute quota (60) still has room


def test_retry_after_reports_when_room_frees_up(tmp_path):
    with make(tmp_path, default_rate_per_minute=2, global_rate_per_minute=0) as c:
        k = key(c)
        send(c, k, 2)
        backdate(c, k["id"], 40)                  # both messages are 40s old: room again in ~20s
        r = send(c, k)[0]
        assert r.status_code == 429 and 18 <= int(r.headers["retry-after"]) <= 22


def test_daily_quota_and_longest_wait_is_reported(tmp_path):
    with make(tmp_path, default_rate_per_minute=0, default_rate_per_day=3, global_rate_per_minute=0) as c:
        k = key(c)
        assert [r.status_code for r in send(c, k, 4)] == [202, 202, 202, 429]
        r = send(c, k)[0]
        assert "3 messages/24h" in r.json()["error"] and int(r.headers["retry-after"]) > 3600


def test_global_cap_protects_the_whole_relay(tmp_path):
    with make(tmp_path, default_rate_per_minute=0, default_rate_per_day=0, global_rate_per_minute=4) as c:
        a, b = key(c, name="a"), key(c, name="b")
        assert [r.status_code for r in send(c, a, 3)] == [202] * 3
        r = send(c, b, 3)
        assert [x.status_code for x in r] == [202, 429, 429]       # a and b share the global budget
        assert "Relay-wide" in r[1].json()["error"]


def test_flood_of_rejections_is_one_log_row(tmp_path):
    with make(tmp_path, default_rate_per_minute=3, global_rate_per_minute=0) as c:
        k = key(c)
        send(c, k, 3)
        send(c, k, 200)                           # a flood of over-limit requests
        rows = c.get(f"/admin/api/messages?key_id={k['id']}&status=rejected").json()["items"]
        assert len(rows) == 1 and rows[0]["repeats"] == 199 and "3 messages/minute" in rows[0]["error"]
        # rejected requests never count toward the limit themselves
        assert c.get(f"/admin/api/messages?key_id={k['id']}&status=queued,sent").json()["total"] == 3


def test_connect_info_exposes_defaults_and_validation(tmp_path):
    with make(tmp_path, default_rate_per_minute=7, default_rate_per_day=70, global_rate_per_minute=9) as c:
        c.post("/admin/api/login", json={"password": PASSWORD})
        assert c.get("/admin/api/connect-info").json()["limits"] == {
            "default_rate_per_minute": 7, "default_rate_per_day": 70, "global_rate_per_minute": 9}
        assert c.post("/admin/api/keys", json={"name": "x", "rate_per_minute": -1}).status_code == 422
