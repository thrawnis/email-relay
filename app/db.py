"""SQLite persistence for API keys, the message log and per-message events.

A single connection guarded by a lock is plenty for this workload (tens of apps,
thousands of messages/day). WAL mode keeps reads from blocking the writer.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterator

from .security import slugify_username

SCHEMA = """
CREATE TABLE IF NOT EXISTS api_keys (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL,
    key_prefix       TEXT    NOT NULL,
    key_hash         TEXT    NOT NULL UNIQUE,
    created_at       REAL    NOT NULL,
    revoked_at       REAL,
    last_used_at     REAL,
    rate_per_minute  INTEGER,
    rate_per_day     INTEGER,
    allowed_from     TEXT,              -- JSON list of addresses / *@domain patterns, NULL = global list
    notes            TEXT,
    allow_plaintext_smtp  INTEGER NOT NULL DEFAULT 0   -- may log in on the unencrypted SMTP port
);

CREATE TABLE IF NOT EXISTS messages (
    id                TEXT PRIMARY KEY,
    created_at        REAL    NOT NULL,
    updated_at        REAL    NOT NULL,
    key_id            INTEGER,
    app_name          TEXT,
    from_addr         TEXT,
    recipients        TEXT,             -- JSON {"to": [...], "cc": [...], "bcc": [...]}
    recipients_search TEXT,             -- flattened lowercase, for LIKE search
    subject           TEXT,
    has_html          INTEGER NOT NULL DEFAULT 0,
    attachment_count  INTEGER NOT NULL DEFAULT 0,
    size_bytes        INTEGER NOT NULL DEFAULT 0,
    status            TEXT    NOT NULL, -- queued | sending | retrying | sent | partial | failed | rejected
    attempts          INTEGER NOT NULL DEFAULT 0,
    next_attempt_at   REAL,
    error             TEXT,
    provider_id       TEXT,
    client_ip         TEXT,
    source            TEXT,             -- api | smtp | admin
    username          TEXT,             -- SMTP login name as typed (even when auth failed); API: the key's username
    repeats           INTEGER NOT NULL DEFAULT 0,  -- identical rate-limit rejections folded into this row
    payload           TEXT              -- full request JSON; cleared once delivered
);
CREATE INDEX IF NOT EXISTS ix_messages_created ON messages(created_at);
CREATE INDEX IF NOT EXISTS ix_messages_due     ON messages(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS ix_messages_key     ON messages(key_id, created_at);

CREATE TABLE IF NOT EXISTS message_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id  TEXT NOT NULL,
    ts          REAL NOT NULL,
    event       TEXT NOT NULL,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_msg ON message_events(message_id, ts);
"""

PENDING_STATUSES = ("queued", "retrying")
FINAL_STATUSES = ("sent", "partial", "failed", "rejected")


def _row(r: sqlite3.Row | None) -> dict | None:
    return dict(r) if r is not None else None


class Database:
    def __init__(self, path: str):
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(messages)").fetchall()}
        if "source" not in cols:
            self._conn.execute("ALTER TABLE messages ADD COLUMN source TEXT")
        if "username" not in cols:
            self._conn.execute("ALTER TABLE messages ADD COLUMN username TEXT")
        if "repeats" not in cols:
            self._conn.execute("ALTER TABLE messages ADD COLUMN repeats INTEGER NOT NULL DEFAULT 0")
        key_cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(api_keys)").fetchall()}
        if "allow_plaintext_smtp" not in key_cols:
            self._conn.execute("ALTER TABLE api_keys ADD COLUMN allow_plaintext_smtp INTEGER NOT NULL DEFAULT 0")
        if "username" not in key_cols:
            self._conn.execute("ALTER TABLE api_keys ADD COLUMN username TEXT")
        for r in self._conn.execute("SELECT id, name FROM api_keys WHERE username IS NULL ORDER BY id").fetchall():
            self._conn.execute("UPDATE api_keys SET username = ? WHERE id = ?",
                               (self._unique_username(r["name"], r["id"]), r["id"]))
        self._conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_api_keys_username ON api_keys(username)")

    def _unique_username(self, name: str, exclude_id: int | None = None) -> str:
        base = slugify_username(name)
        taken = {r["username"] for r in self._conn.execute(
            "SELECT username FROM api_keys WHERE username IS NOT NULL AND id IS NOT ?", (exclude_id,)).fetchall()}
        candidate, n = base, 1
        while candidate in taken:
            n += 1
            suffix = f"-{n}"
            candidate = base[: 32 - len(suffix)].rstrip("-") + suffix
        return candidate

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Serialized transaction. Re-entrant within one thread."""
        with self._lock:
            if self._conn.in_transaction:
                yield self._conn
                return
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def query(self, sql: str, params: Any = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def query_one(self, sql: str, params: Any = ()) -> dict | None:
        with self._lock:
            return _row(self._conn.execute(sql, params).fetchone())

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ keys
    def create_key(self, *, name: str, key_prefix: str, key_hash: str, rate_per_minute: int | None,
                   rate_per_day: int | None, allowed_from: list[str] | None, notes: str | None,
                   allow_plaintext_smtp: bool = False) -> dict:
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO api_keys (name, username, key_prefix, key_hash, created_at, rate_per_minute,"
                " rate_per_day, allowed_from, notes, allow_plaintext_smtp) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (name, self._unique_username(name), key_prefix, key_hash, time.time(), rate_per_minute,
                 rate_per_day, json.dumps(allowed_from) if allowed_from else None, notes, int(allow_plaintext_smtp)),
            )
            return self.get_key(cur.lastrowid)

    def get_key(self, key_id: int) -> dict | None:
        return _decode_key(self.query_one("SELECT * FROM api_keys WHERE id = ?", (key_id,)))

    def get_key_by_hash(self, key_hash: str) -> dict | None:
        return _decode_key(self.query_one("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)))

    def list_keys(self) -> list[dict]:
        now = time.time()
        rows = self.query(
            """
            SELECT k.*,
              (SELECT COUNT(*) FROM messages m WHERE m.key_id = k.id AND m.status = 'sent'
                 AND m.created_at >= ?) AS sent_24h,
              (SELECT COUNT(*) FROM messages m WHERE m.key_id = k.id AND m.status IN ('failed','rejected','partial')
                 AND m.created_at >= ?) AS failed_24h,
              (SELECT COUNT(*) FROM messages m WHERE m.key_id = k.id) AS total
            FROM api_keys k ORDER BY k.revoked_at IS NOT NULL, k.name COLLATE NOCASE
            """,
            (now - 86400, now - 86400),
        )
        return [_decode_key(r) for r in rows]

    def update_key(self, key_id: int, fields: dict) -> dict | None:
        allowed = {"name", "rate_per_minute", "rate_per_day", "allowed_from", "notes", "allow_plaintext_smtp"}
        sets, params = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            if k == "allowed_from":
                v = json.dumps(v) if v else None
            if k == "allow_plaintext_smtp":
                v = int(bool(v))
            sets.append(f"{k} = ?")
            params.append(v)
        if "name" in fields:  # the derived username follows the name
            sets.append("username = ?")
            params.append(self._unique_username(fields["name"], key_id))
        if sets:
            with self.tx() as c:
                c.execute(f"UPDATE api_keys SET {', '.join(sets)} WHERE id = ?", (*params, key_id))
        return self.get_key(key_id)

    def revoke_key(self, key_id: int) -> dict | None:
        with self.tx() as c:
            c.execute("UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                      (time.time(), key_id))
        return self.get_key(key_id)

    def touch_key(self, key_id: int) -> None:
        with self.tx() as c:
            c.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (time.time(), key_id))

    def count_accepted_since(self, key_id: int | None, since: float) -> int:
        """Messages that count toward quota: everything accepted (i.e. not rejected). key_id None = all keys."""
        where, params = ("key_id = ? AND ", [key_id]) if key_id is not None else ("", [])
        r = self.query_one(
            f"SELECT COUNT(*) AS n FROM messages WHERE {where}created_at >= ? AND status != 'rejected'",
            (*params, since))
        return r["n"] if r else 0

    def window_state(self, key_id: int | None, window: int, limit: int, now: float) -> tuple[int, int]:
        """(messages in the last `window` seconds, seconds until one more may be accepted)."""
        since = now - window
        count = self.count_accepted_since(key_id, since)
        if count < limit:
            return count, 0
        where, params = ("key_id = ? AND ", [key_id]) if key_id is not None else ("", [])
        # the message that must age out of the window before there is room again
        r = self.query_one(
            f"SELECT created_at FROM messages WHERE {where}created_at >= ? AND status != 'rejected'"
            " ORDER BY created_at LIMIT 1 OFFSET ?", (*params, since, count - limit))
        wait = (r["created_at"] + window - now) if r else window
        return count, max(1, int(wait) + 1)

    def bump_throttled(self, key_id: int, error: str, window: int = 60) -> str | None:
        """Collapse a flood of identical rate-limit rejections into one log row (counts the repeats)."""
        with self.tx() as c:
            r = c.execute(
                "SELECT id FROM messages WHERE key_id = ? AND status = 'rejected' AND error = ? AND created_at >= ?"
                " ORDER BY created_at DESC LIMIT 1", (key_id, error, time.time() - window)).fetchone()
            if not r:
                return None
            c.execute("UPDATE messages SET repeats = repeats + 1, updated_at = ? WHERE id = ?", (time.time(), r["id"]))
            return r["id"]

    # -------------------------------------------------------------- messages
    def insert_message(self, *, key_id: int | None, app_name: str, from_addr: str | None,
                       recipients: dict | None, subject: str | None, has_html: bool = False,
                       attachment_count: int = 0, size_bytes: int = 0, status: str,
                       error: str | None = None, client_ip: str | None = None,
                       payload: dict | None = None, source: str | None = None,
                       username: str | None = None) -> str:
        msg_id = uuid.uuid4().hex
        now = time.time()
        recipients = recipients or {}
        search = " ".join(a.lower() for lst in recipients.values() for a in (lst or []))
        with self.tx() as c:
            c.execute(
                "INSERT INTO messages (id, created_at, updated_at, key_id, app_name, from_addr, recipients,"
                " recipients_search, subject, has_html, attachment_count, size_bytes, status, attempts,"
                " next_attempt_at, error, client_ip, payload, source, username) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?,?,?,?)",
                (msg_id, now, now, key_id, app_name, from_addr, json.dumps(recipients), search,
                 (subject or "")[:998], int(has_html), attachment_count, size_bytes, status,
                 now if status in PENDING_STATUSES else None, error, client_ip,
                 json.dumps(payload) if payload is not None else None, source, username),
            )
            self._event(c, msg_id, status, error)
        return msg_id

    def add_event(self, message_id: str, event: str, detail: str | None = None) -> None:
        with self.tx() as c:
            self._event(c, message_id, event, detail)

    @staticmethod
    def _event(c: sqlite3.Connection, message_id: str, event: str, detail: str | None) -> None:
        c.execute("INSERT INTO message_events (message_id, ts, event, detail) VALUES (?,?,?,?)",
                  (message_id, time.time(), event, detail))

    def claim_due(self, limit: int) -> list[dict]:
        """Atomically move up to `limit` due messages to 'sending' and return them."""
        if limit <= 0:
            return []
        now = time.time()
        with self.tx() as c:
            rows = c.execute(
                "SELECT * FROM messages WHERE status IN ('queued','retrying') AND next_attempt_at <= ?"
                " ORDER BY next_attempt_at LIMIT ?", (now, limit)).fetchall()
            out = []
            for r in rows:
                c.execute("UPDATE messages SET status='sending', attempts=attempts+1, updated_at=? WHERE id=?",
                          (now, r["id"]))
                d = dict(r)
                d["attempts"] += 1
                d["status"] = "sending"
                out.append(d)
            return out

    def mark_sent(self, message_id: str, provider_id: str | None, detail: str | None = None,
                  partial_error: str | None = None) -> None:
        """'sent', or 'partial' when some recipients were refused (error lists which)."""
        status = "partial" if partial_error else "sent"
        with self.tx() as c:
            c.execute("UPDATE messages SET status=?, provider_id=?, error=?, next_attempt_at=NULL,"
                      " payload=NULL, updated_at=? WHERE id=?",
                      (status, provider_id, partial_error, time.time(), message_id))
            self._event(c, message_id, status, detail)

    def mark_retry(self, message_id: str, error: str, next_at: float) -> None:
        with self.tx() as c:
            c.execute("UPDATE messages SET status='retrying', error=?, next_attempt_at=?, updated_at=? WHERE id=?",
                      (error, next_at, time.time(), message_id))
            self._event(c, message_id, "retry_scheduled", error)

    def mark_failed(self, message_id: str, error: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE messages SET status='failed', error=?, next_attempt_at=NULL, updated_at=? WHERE id=?",
                      (error, time.time(), message_id))
            self._event(c, message_id, "failed", error)

    def requeue(self, message_id: str, reason: str) -> bool:
        with self.tx() as c:
            cur = c.execute(
                "UPDATE messages SET status='queued', attempts=0, next_attempt_at=?, updated_at=?"
                " WHERE id=? AND status='failed' AND payload IS NOT NULL",
                (time.time(), time.time(), message_id))
            if cur.rowcount:
                self._event(c, message_id, "requeued", reason)
            return bool(cur.rowcount)

    def recover_inflight(self) -> int:
        """After a crash/restart, anything stuck in 'sending' goes back on the queue."""
        with self.tx() as c:
            ids = [r["id"] for r in c.execute("SELECT id FROM messages WHERE status='sending'").fetchall()]
            for mid in ids:
                c.execute("UPDATE messages SET status='retrying', next_attempt_at=?, updated_at=? WHERE id=?",
                          (time.time(), time.time(), mid))
                self._event(c, mid, "recovered", "Relay restarted while message was in flight")
            return len(ids)

    def get_message(self, message_id: str) -> dict | None:
        return self.query_one("SELECT * FROM messages WHERE id = ?", (message_id,))

    def get_events(self, message_id: str) -> list[dict]:
        return self.query("SELECT ts, event, detail FROM message_events WHERE message_id = ? ORDER BY id",
                          (message_id,))

    def search_messages(self, *, q: str | None = None, key_id: int | str | None = None, app: str | None = None,
                        status: str | None = None, since: float | None = None, until: float | None = None,
                        limit: int = 50, offset: int = 0) -> tuple[list[dict], int]:
        where, params = [], []
        if q:
            like = f"%{q.lower()}%"
            where.append("(LOWER(subject) LIKE ? OR recipients_search LIKE ? OR LOWER(error) LIKE ?"
                         " OR id = ? OR LOWER(from_addr) LIKE ? OR LOWER(username) LIKE ?)")
            params += [like, like, like, q.strip(), like, like]
        if key_id == "none":  # attempts not tied to any key: unknown keys, admin test sends
            where.append("key_id IS NULL")
        elif key_id is not None:
            where.append("key_id = ?")
            params.append(key_id)
        if app:
            where.append("app_name = ?")
            params.append(app)
        if status:
            statuses = [s for s in status.split(",") if s]
            where.append(f"status IN ({','.join('?' * len(statuses))})")
            params += statuses
        if since is not None:
            where.append("created_at >= ?")
            params.append(since)
        if until is not None:
            where.append("created_at < ?")
            params.append(until)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        total = self.query_one(f"SELECT COUNT(*) AS n FROM messages {clause}", params)["n"]
        rows = self.query(
            f"SELECT id, created_at, updated_at, key_id, app_name, from_addr, recipients, subject, has_html,"
            f" attachment_count, size_bytes, status, attempts, next_attempt_at, error, provider_id, client_ip, source, username, repeats"
            f" FROM messages {clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (*params, limit, offset))
        for r in rows:
            r["recipients"] = json.loads(r["recipients"] or "{}")
        return rows, total

    def stats(self) -> dict:
        now = time.time()
        by_status = {}
        for window, since in (("24h", now - 86400), ("7d", now - 7 * 86400)):
            rows = self.query("SELECT status, COUNT(*) AS n FROM messages WHERE created_at >= ? GROUP BY status",
                              (since,))
            by_status[window] = {r["status"]: r["n"] for r in rows}
        pending = self.query_one(
            "SELECT COUNT(*) AS n FROM messages WHERE status IN ('queued','retrying','sending')")["n"]
        per_app = self.query(
            "SELECT app_name, SUM(status='sent') AS sent, SUM(status IN ('failed','rejected','partial')) AS failed,"
            " COUNT(*) AS total FROM messages WHERE created_at >= ? GROUP BY app_name ORDER BY total DESC",
            (now - 86400,))
        return {"by_status": by_status, "pending": pending, "per_app_24h": per_app}

    def timeseries(self, since: float, until: float) -> dict:
        """Hourly (UTC) counts per key for charting; the browser folds hours into its own local days.

        ok = delivered ('sent'); bad = 'partial' or 'failed'. Rejected and still-pending messages are not counted.
        """
        rows = self.query(
            "SELECT CAST(created_at / 3600 AS INTEGER) * 3600 AS h, key_id,"
            " SUM(status = 'sent') AS ok, SUM(status IN ('partial','failed')) AS bad"
            " FROM messages WHERE created_at >= ? AND created_at < ? AND status IN ('sent','partial','failed')"
            " GROUP BY h, key_id", (since, until))
        keys = self.query("SELECT id, name, username, revoked_at FROM api_keys ORDER BY id")
        return {"buckets": rows, "keys": keys}

    def distinct_apps(self) -> list[str]:
        return [r["app_name"] for r in self.query(
            "SELECT DISTINCT app_name FROM messages WHERE app_name IS NOT NULL ORDER BY app_name")]

    def purge_older_than(self, cutoff: float) -> int:
        with self.tx() as c:
            c.execute("DELETE FROM message_events WHERE message_id IN"
                      " (SELECT id FROM messages WHERE created_at < ? AND status IN ('sent','partial','failed','rejected'))",
                      (cutoff,))
            cur = c.execute("DELETE FROM messages WHERE created_at < ? AND status IN ('sent','partial','failed','rejected')",
                            (cutoff,))
            return cur.rowcount


def _decode_key(row: dict | None) -> dict | None:
    if row is None:
        return None
    row["allowed_from"] = json.loads(row["allowed_from"]) if row.get("allowed_from") else []
    row["allow_plaintext_smtp"] = bool(row.get("allow_plaintext_smtp"))
    row.pop("key_hash", None)
    return row
