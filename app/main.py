"""Email relay: FastAPI app with the public send API and the admin API/UI."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from starlette.middleware.sessions import SessionMiddleware

from .backends import Backend, get_backend
from .config import Settings
from .db import Database
from .schemas import KeyCreate, KeyUpdate, SendRequest
from .security import (LoginThrottle, address_matches, check_password, extract_key, generate_key,
                       hash_key)
from .worker import Worker

log = logging.getLogger("relay")
STATIC_DIR = Path(__file__).parent / "static"


def _validation_message(e: ValidationError) -> str:
    parts = []
    for err in e.errors():
        loc = ".".join(str(x) for x in err["loc"] if x != "body")
        parts.append(f"{loc}: {err['msg']}" if loc else err["msg"])
    return "; ".join(parts)


def create_app(settings: Settings | None = None, backend: Backend | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    problems = settings.validate()
    if problems:
        raise RuntimeError("Invalid configuration:\n  - " + "\n  - ".join(problems))

    db = Database(settings.db_path)
    backend = backend or get_backend(settings)
    worker = Worker(db, backend, settings)
    throttle = LoginThrottle()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        task = asyncio.create_task(worker.run())
        log.info("Email relay started: backend=%s from=%s", backend.describe(), settings.mail_from)
        try:
            yield
        finally:
            await worker.stop()
            task.cancel()
            db.close()

    app = FastAPI(title="Email Relay", lifespan=lifespan, docs_url="/api/docs", redoc_url=None,
                  openapi_url="/api/openapi.json")
    app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, session_cookie="relay_admin",
                       max_age=12 * 3600, same_site="strict", https_only=settings.cookie_secure)
    app.state.db, app.state.worker, app.state.settings, app.state.backend = db, worker, settings, backend

    def client_ip(request: Request) -> str | None:
        if settings.trust_proxy:
            fwd = request.headers.get("x-forwarded-for")
            if fwd:
                return fwd.split(",")[0].strip()
        return request.client.host if request.client else None

    # ------------------------------------------------------------ public API
    def reject(status: int, error: str, *, request: Request, key: dict | None = None,
               body: dict | None = None, app_name: str | None = None) -> JSONResponse:
        """Log a rejected send attempt and return the error response."""
        body = body if isinstance(body, dict) else {}
        recips = {k: [str(a) for a in v] if isinstance(v, list) else ([str(v)] if v else [])
                  for k, v in ((f, body.get(f)) for f in ("to", "cc", "bcc"))}
        subject = body.get("subject") if isinstance(body.get("subject"), str) else None
        msg_id = db.insert_message(
            key_id=key["id"] if key else None, app_name=app_name or (key["name"] if key else "(unauthenticated)"),
            from_addr=str(body.get("from")) if body.get("from") else None, recipients=recips, subject=subject,
            status="rejected", error=error, client_ip=client_ip(request))
        return JSONResponse({"id": msg_id, "status": "rejected", "error": error}, status_code=status)

    def authenticate(request: Request) -> tuple[dict | None, str | None]:
        raw = extract_key(request.headers.get("authorization"), request.headers.get("x-api-key"))
        if not raw:
            return None, "Missing API key (use 'Authorization: Bearer <key>' or 'X-API-Key')"
        key = db.get_key_by_hash(hash_key(raw))
        if not key:
            return None, f"Invalid API key ({raw[:10]}…)"
        if key["revoked_at"]:
            return key, f"API key '{key['name']}' has been revoked"
        return key, None

    @app.post("/api/send", status_code=202)
    async def send(request: Request):
        """Queue an email for delivery. Returns 202 with the message id."""
        max_body = int(settings.max_attachment_bytes * 1.4) + 2 * 1024 * 1024
        if int(request.headers.get("content-length") or 0) > max_body:
            return reject(413, "Request body too large", request=request)

        key, auth_err = authenticate(request)
        try:
            body = json.loads(await request.body() or b"null")
        except ValueError:
            body = None
        if auth_err:  # key is set only when it exists but is revoked
            return reject(403 if key else 401, auth_err, request=request, key=key, body=body)
        db.touch_key(key["id"])

        if not isinstance(body, dict):
            return reject(400, "Request body must be a JSON object", request=request, key=key)
        try:
            req = SendRequest.model_validate(body)
        except ValidationError as e:
            return reject(422, _validation_message(e), request=request, key=key, body=body)

        if len(req.all_recipients()) > settings.max_recipients:
            return reject(422, f"Too many recipients (max {settings.max_recipients})",
                          request=request, key=key, body=body)
        try:
            att_size = sum(a.decoded_size() for a in req.attachments)
        except ValueError as e:
            return reject(422, str(e), request=request, key=key, body=body)
        if att_size > settings.max_attachment_bytes:
            return reject(413, f"Attachments total {att_size} bytes; max is {settings.max_attachment_bytes}",
                          request=request, key=key, body=body)

        from_addr = str(req.from_ or settings.mail_from)
        if not address_matches(from_addr, settings.mail_allowed_from):
            return reject(403, f"Sender {from_addr} is not allowed by the relay", request=request, key=key, body=body)
        if key["allowed_from"] and not address_matches(from_addr, key["allowed_from"]):
            return reject(403, f"Sender {from_addr} is not allowed for this API key",
                          request=request, key=key, body=body)

        size = len(req.text or "") + len(req.html or "") + att_size
        with db.tx():  # quota check + insert are atomic
            now = time.time()
            if key["rate_per_minute"] and db.count_accepted_since(key["id"], now - 60) >= key["rate_per_minute"]:
                limit_err = f"Rate limit exceeded: {key['rate_per_minute']} messages/minute"
            elif key["rate_per_day"] and db.count_accepted_since(key["id"], now - 86400) >= key["rate_per_day"]:
                limit_err = f"Quota exceeded: {key['rate_per_day']} messages/24h"
            else:
                limit_err = None
                msg_id = db.insert_message(
                    key_id=key["id"], app_name=key["name"], from_addr=from_addr,
                    recipients={"to": req.to, "cc": req.cc, "bcc": req.bcc}, subject=req.subject,
                    has_html=bool(req.html), attachment_count=len(req.attachments), size_bytes=size,
                    status="queued", client_ip=client_ip(request), payload=req.to_payload())
        if limit_err:
            resp = reject(429, limit_err, request=request, key=key, body=body)
            resp.headers["Retry-After"] = "60"
            return resp

        worker.notify()
        return {"id": msg_id, "status": "queued"}

    @app.get("/api/messages/{message_id}")
    async def message_status(message_id: str, request: Request):
        """Let an app check the delivery status of a message it sent."""
        key, auth_err = authenticate(request)
        if auth_err:
            raise HTTPException(403 if key else 401, auth_err)
        m = db.get_message(message_id)
        if not m or m["key_id"] != key["id"]:
            raise HTTPException(404, "Message not found")
        return {k: m[k] for k in ("id", "status", "attempts", "error", "created_at", "updated_at",
                                  "next_attempt_at", "provider_id")}

    @app.get("/healthz")
    async def healthz():
        db.query_one("SELECT 1")
        return {"ok": True}

    # ------------------------------------------------------------- admin API
    def require_admin(request: Request) -> None:
        if not request.session.get("admin"):
            raise HTTPException(401, "Not logged in")

    @app.post("/admin/api/login")
    async def login(request: Request):
        ip = client_ip(request) or "?"
        if throttle.blocked(ip):
            raise HTTPException(429, "Too many failed attempts; try again later")
        data = await request.json()
        if not check_password(str(data.get("password", "")), settings.admin_password):
            throttle.fail(ip)
            await asyncio.sleep(0.5)
            log.warning("Failed admin login from %s", ip)
            raise HTTPException(401, "Wrong password")
        throttle.reset(ip)
        request.session["admin"] = True
        return {"ok": True}

    @app.post("/admin/api/logout")
    async def logout(request: Request):
        request.session.clear()
        return {"ok": True}

    @app.get("/admin/api/me")
    async def me(request: Request):
        return {"admin": bool(request.session.get("admin"))}

    @app.get("/admin/api/config")
    async def config(request: Request):
        require_admin(request)
        return {**settings.public_summary(), "backend": backend.describe()}

    @app.get("/admin/api/keys")
    async def list_keys(request: Request):
        require_admin(request)
        return db.list_keys()

    @app.post("/admin/api/keys", status_code=201)
    async def create_key(body: KeyCreate, request: Request):
        require_admin(request)
        full, prefix, digest = generate_key()
        key = db.create_key(name=body.name.strip(), key_prefix=prefix, key_hash=digest,
                            rate_per_minute=body.rate_per_minute, rate_per_day=body.rate_per_day,
                            allowed_from=body.allowed_from, notes=body.notes)
        log.info("Created API key %s (%s)", key["id"], key["name"])
        return {**key, "api_key": full}

    @app.patch("/admin/api/keys/{key_id}")
    async def update_key(key_id: int, body: KeyUpdate, request: Request):
        require_admin(request)
        if not db.get_key(key_id):
            raise HTTPException(404, "Key not found")
        fields = body.model_dump(exclude_unset=True)
        if "name" in fields:
            if not fields["name"]:
                raise HTTPException(422, "name cannot be empty")
            fields["name"] = fields["name"].strip()
        return db.update_key(key_id, fields)

    @app.post("/admin/api/keys/{key_id}/revoke")
    async def revoke_key(key_id: int, request: Request):
        require_admin(request)
        if not db.get_key(key_id):
            raise HTTPException(404, "Key not found")
        log.info("Revoked API key %s", key_id)
        return db.revoke_key(key_id)

    @app.get("/admin/api/messages")
    async def list_messages(request: Request, q: str | None = None, key_id: int | None = None,
                            app: str | None = None, status: str | None = None, since: float | None = None,
                            until: float | None = None, limit: int = 50, offset: int = 0):
        require_admin(request)
        rows, total = db.search_messages(q=q, key_id=key_id, app=app, status=status, since=since, until=until,
                                         limit=max(1, min(limit, 500)), offset=max(0, offset))
        return {"items": rows, "total": total}

    @app.get("/admin/api/messages/{message_id}")
    async def message_detail(message_id: str, request: Request):
        require_admin(request)
        m = db.get_message(message_id)
        if not m:
            raise HTTPException(404, "Message not found")
        m["recipients"] = json.loads(m["recipients"] or "{}")
        payload = json.loads(m.pop("payload")) if m.get("payload") else None
        if payload:
            for a in payload.get("attachments") or []:
                a["content"] = f"<{len(a['content'])} base64 chars>"
        m["payload"] = payload
        m["retryable"] = m["status"] == "failed" and payload is not None
        m["events"] = db.get_events(message_id)
        return m

    @app.post("/admin/api/messages/{message_id}/retry")
    async def retry_message(message_id: str, request: Request):
        require_admin(request)
        if not db.requeue(message_id, "Manually re-queued by admin"):
            raise HTTPException(409, "Only failed messages with a retained payload can be retried")
        worker.notify()
        return {"ok": True}

    @app.get("/admin/api/stats")
    async def stats(request: Request):
        require_admin(request)
        return {**db.stats(), "apps": db.distinct_apps()}

    @app.post("/admin/api/test-send", status_code=202)
    async def test_send(request: Request):
        require_admin(request)
        data = await request.json()
        try:
            req = SendRequest.model_validate({
                "to": data.get("to"),
                "subject": data.get("subject") or "Email relay test",
                "text": data.get("text") or "This is a test message sent from the email relay admin UI.",
            })
        except ValidationError as e:
            raise HTTPException(422, _validation_message(e))
        msg_id = db.insert_message(
            key_id=None, app_name="(admin test)", from_addr=settings.mail_from,
            recipients={"to": req.to, "cc": [], "bcc": []}, subject=req.subject, size_bytes=len(req.text or ""),
            status="queued", client_ip=client_ip(request), payload=req.to_payload())
        worker.notify()
        return {"id": msg_id, "status": "queued"}

    # --------------------------------------------------------------- admin UI
    @app.get("/", include_in_schema=False)
    async def root():
        return RedirectResponse("/admin")

    @app.get("/admin", include_in_schema=False)
    async def admin_page():
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-store"})

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app


def _default_app() -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    return create_app()
