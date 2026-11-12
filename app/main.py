"""Email relay: FastAPI app with the public send API and the admin API/UI."""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import logging
from contextlib import asynccontextmanager
from email import policy as email_policy
from email.parser import BytesParser
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
from .security import LoginThrottle, check_password, extract_key, generate_key
from .service import Relay
from .submission import SubmissionServer
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
    loop_ref: dict = {}

    def notify_worker() -> None:  # callable from the SMTP server thread too
        loop = loop_ref.get("loop")
        if loop is not None:
            loop.call_soon_threadsafe(worker.notify)
        else:
            worker.notify()

    relay = Relay(db, settings, notify_worker)
    submission = SubmissionServer(relay, settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        loop_ref["loop"] = asyncio.get_running_loop()
        task = asyncio.create_task(worker.run())
        submission.start()
        log.info("Email relay started: backend=%s from=%s", backend.describe(), settings.mail_from)
        try:
            yield
        finally:
            submission.stop()
            await worker.stop()
            task.cancel()
            db.close()

    app = FastAPI(title="Email Relay", lifespan=lifespan, docs_url="/api/docs", redoc_url=None,
                  openapi_url="/api/openapi.json")
    app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, session_cookie="relay_admin",
                       max_age=12 * 3600, same_site="strict", https_only=True)
    app.state.db, app.state.worker, app.state.settings, app.state.backend = db, worker, settings, backend
    app.state.relay, app.state.submission = relay, submission

    proxy_nets = [ipaddress.ip_network(p, strict=False) for p in settings.trusted_proxies]

    def from_trusted_proxy(request: Request) -> bool:
        """Proxy headers are only believed when TRUST_PROXY is on and the peer is a listed proxy (if any are listed)."""
        if not settings.trust_proxy:
            return False
        if not proxy_nets:
            return True
        try:
            peer = ipaddress.ip_address(request.client.host if request.client else "")
        except ValueError:
            return False
        return any(peer in n for n in proxy_nets)

    def client_ip(request: Request) -> str | None:
        if from_trusted_proxy(request):
            h = request.headers
            # Cloudflare Tunnel sets CF-Connecting-IP; Nginx Proxy Manager sets X-Real-IP to the peer address.
            for name in ("cf-connecting-ip", "x-real-ip"):
                if h.get(name):
                    return h[name].strip()
            if h.get("x-forwarded-for"):
                return h["x-forwarded-for"].split(",")[-1].strip()  # entry added by the nearest proxy
        return request.client.host if request.client else None

    def via_cloudflare(request: Request) -> bool:
        return "cf-connecting-ip" in request.headers or "cf-ray" in request.headers

    def is_https(request: Request) -> bool:
        if from_trusted_proxy(request) and request.headers.get("x-forwarded-proto"):
            return request.headers["x-forwarded-proto"].split(",")[0].strip().lower() == "https"
        return request.url.scheme == "https"

    @app.middleware("http")
    async def transport_policy(request: Request, call_next):
        path = request.url.path
        # HTTPS only. The listener itself is TLS-only (app/serve.py); behind NPM/cloudflared the
        # client's original scheme comes from X-Forwarded-Proto, which must also be https.
        if not is_https(request):
            log.warning("Refused plain-HTTP request %s %s from %s", request.method, path, client_ip(request))
            if request.method == "POST" and path == "/api/send":
                db.insert_message(key_id=None, app_name="(plain HTTP)", from_addr=None, recipients=None,
                                  subject=None, status="rejected", client_ip=client_ip(request),
                                  error="HTTPS required; request arrived over plain HTTP")
            return JSONResponse({"error": "HTTPS required"}, status_code=403)
        if settings.block_api_via_cloudflare and path.startswith("/api/") and via_cloudflare(request):
            log.warning("Refused %s %s via Cloudflare from %s", request.method, path, client_ip(request))
            if request.method == "POST" and path == "/api/send":
                db.insert_message(key_id=None, app_name="(via Cloudflare)", from_addr=None, recipients=None,
                                  subject=None, status="rejected", client_ip=client_ip(request),
                                  error="The send API is only reachable from the internal network")
            return JSONResponse({"error": "The API is only available on the internal network"}, status_code=403)
        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    # ------------------------------------------------------------ public API
    def reject(status: int, error: str, *, request: Request, key: dict | None = None,
               body: dict | None = None) -> JSONResponse:
        """Log a rejected HTTP send attempt and return the error response."""
        body = body if isinstance(body, dict) else {}
        recips = {k: [str(a) for a in v] if isinstance(v, list) else ([str(v)] if v else [])
                  for k, v in ((f, body.get(f)) for f in ("to", "cc", "bcc"))}
        subject = body.get("subject") if isinstance(body.get("subject"), str) else None
        adm = relay.reject(error, status_code=status, source="api", key=key, recipients=recips, subject=subject,
                           from_addr=str(body.get("from")) if body.get("from") else None,
                           client_ip=client_ip(request))
        return admission_response(adm)

    def admission_response(adm) -> JSONResponse:
        if adm.ok:
            return JSONResponse({"id": adm.message_id, "status": "queued"}, status_code=202)
        resp = JSONResponse({"id": adm.message_id, "status": "rejected", "error": adm.error},
                            status_code=adm.status_code)
        if adm.retry_after:
            resp.headers["Retry-After"] = str(adm.retry_after)
        return resp

    def authenticate(request: Request) -> tuple[dict | None, str | None]:
        raw = extract_key(request.headers.get("authorization"), request.headers.get("x-api-key"))
        if not raw:
            return None, "Missing API key (use 'Authorization: Bearer <key>' or 'X-API-Key')"
        return relay.authenticate(raw)

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

        if not isinstance(body, dict):
            return reject(400, "Request body must be a JSON object", request=request, key=key)
        try:
            req = SendRequest.model_validate(body)
        except ValidationError as e:
            return reject(422, _validation_message(e), request=request, key=key, body=body)
        try:
            att_size = sum(a.decoded_size() for a in req.attachments)
        except ValueError as e:
            return reject(422, str(e), request=request, key=key, body=body)
        if att_size > settings.max_attachment_bytes:
            return reject(413, f"Attachments total {att_size} bytes; max is {settings.max_attachment_bytes}",
                          request=request, key=key, body=body)

        adm = relay.admit(
            key=key, source="api", from_addr=str(req.from_ or settings.mail_from),
            recipients={"to": req.to, "cc": req.cc, "bcc": req.bcc}, subject=req.subject,
            payload=req.to_payload(), has_html=bool(req.html), attachment_count=len(req.attachments),
            size_bytes=len(req.text or "") + len(req.html or "") + att_size, client_ip=client_ip(request))
        return admission_response(adm)

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
        return {**settings.public_summary(), "backend": backend.describe(), "submission": submission.status()}

    @app.get("/admin/api/connect-info")
    async def connect_info(request: Request):
        """What an app needs to connect (never includes the relay's upstream credentials)."""
        require_admin(request)
        host = settings.public_hostname
        return {
            "api": {"send_url": f"https://{host}/api/send", "status_url": f"https://{host}/api/messages/{{id}}",
                    "docs_url": f"https://{host}/api/docs"},
            "smtp": submission.status() | {"host": settings.submission_hostname},
            "default_from": settings.mail_from,
            "default_from_name": settings.mail_from_name,
            "allowed_from": settings.mail_allowed_from,
            "max_recipients": settings.max_recipients,
            "max_attachment_bytes": settings.max_attachment_bytes,
        }

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
            if payload.get("raw"):  # SMTP submission: show the readable parts of the original MIME
                raw = base64.b64decode(payload.pop("raw"))
                parsed = BytesParser(policy=email_policy.default).parsebytes(raw)
                for kind in ("plain", "html"):
                    part = parsed.get_body(preferencelist=(kind,))
                    if part is not None:
                        try:
                            payload["text" if kind == "plain" else "html"] = part.get_content()
                        except Exception:
                            pass
                payload["raw_size"] = len(raw)
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

    @app.get("/admin/api/stats/timeseries")
    async def timeseries(request: Request, since: float, until: float):
        require_admin(request)
        if until <= since or until - since > 400 * 86400:
            raise HTTPException(422, "Range must be positive and at most 400 days")
        return db.timeseries(since, until)

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
            status="queued", client_ip=client_ip(request), payload=req.to_payload(), source="admin")
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
