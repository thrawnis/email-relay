"""Background delivery worker.

Messages are persisted as 'queued' by the API, then picked up here. The queue
lives in SQLite, so nothing is lost across restarts: on startup any message
left in 'sending' is put back on the queue.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

from .backends import Backend, PermanentError, TransientError
from .config import Settings
from .db import Database

log = logging.getLogger("relay.worker")


class Worker:
    def __init__(self, db: Database, backend: Backend, settings: Settings):
        self.db, self.backend, self.settings = db, backend, settings
        self._wake = asyncio.Event()
        self._stop = False
        self._inflight: set[asyncio.Task] = set()
        self._last_purge = 0.0

    def notify(self) -> None:
        self._wake.set()

    async def run(self) -> None:
        n = self.db.recover_inflight()
        if n:
            log.warning("Recovered %d in-flight message(s) after restart", n)
        while not self._stop:
            try:
                await self.tick()
            except Exception:  # never let the loop die
                log.exception("Worker tick failed")
            try:
                await asyncio.wait_for(self._wake.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()

    async def tick(self) -> None:
        self._maybe_purge()
        free = self.settings.send_concurrency - len(self._inflight)
        for msg in self.db.claim_due(free):
            task = asyncio.create_task(self._deliver(msg))
            self._inflight.add(task)
            task.add_done_callback(self._inflight.discard)

    async def drain(self) -> None:
        """Process until nothing is due or in flight (used by tests)."""
        while True:
            await self.tick()
            if not self._inflight:
                return
            await asyncio.gather(*list(self._inflight))

    async def stop(self) -> None:
        self._stop = True
        self._wake.set()
        if self._inflight:
            await asyncio.gather(*list(self._inflight), return_exceptions=True)

    async def _deliver(self, msg: dict) -> None:
        mid, attempt = msg["id"], msg["attempts"]
        self.db.add_event(mid, "attempt", f"Attempt {attempt} via {self.backend.describe()}")
        try:
            payload = json.loads(msg["payload"])
            result = await asyncio.to_thread(self.backend.send, payload, msg["from_addr"],
                                             payload.get("from_name") or self.settings.mail_from_name or None)
        except PermanentError as e:
            log.warning("Message %s failed permanently: %s", mid, e)
            self.db.mark_failed(mid, str(e))
            return
        except Exception as e:  # TransientError and anything unexpected are retried
            err = str(e) if isinstance(e, TransientError) else f"{type(e).__name__}: {e}"
            if attempt >= self.settings.max_attempts:
                log.warning("Message %s failed after %d attempts: %s", mid, attempt, err)
                self.db.mark_failed(mid, f"Gave up after {attempt} attempts. Last error: {err}")
            else:
                sched = self.settings.retry_schedule
                delay = sched[min(attempt - 1, len(sched) - 1)]
                log.info("Message %s attempt %d failed (%s); retrying in %ds", mid, attempt, err, delay)
                self.db.mark_retry(mid, err, time.time() + delay)
            return
        if result.partial_error:
            log.warning("Message %s only partially delivered: %s", mid, result.partial_error)
            self.db.mark_sent(mid, result.provider_id, result.detail, partial_error=result.partial_error)
            return
        self.db.mark_sent(mid, result.provider_id, result.detail)
        log.info("Message %s sent (%s)", mid, result.provider_id)

    def _maybe_purge(self) -> None:
        days = self.settings.log_retention_days
        if days <= 0 or time.time() - self._last_purge < 3600:
            return
        self._last_purge = time.time()
        n = self.db.purge_older_than(time.time() - days * 86400)
        if n:
            log.info("Purged %d log entries older than %d days", n, days)
