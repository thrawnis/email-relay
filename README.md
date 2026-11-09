# Email Relay

A small, self-hosted outbound email relay for internal apps — a lightweight alternative to SendGrid/Mailgun.

The relay holds the **one real set of sending credentials** (for `notify@thetruesource.com`) and gives each app
its **own virtual key**. Apps either call `POST /api/send` with their key, or, if they only support SMTP,
log in to the relay's own SMTP submission port with the key as the password. The relay queues the message,
delivers it through the real backend with retry/backoff, and logs every attempt.

```
 app A ──HTTPS API, key A──┐
 app B ──SMTP 587, key B───┼──▶  Email Relay  ──(real SMTP creds)──▶  mail provider ──▶ recipients
 app C ──SMTP 465, key C───┘     ├─ per-key quotas / allowed senders
                      ├─ SQLite: keys (hashed) + send log + events
                      └─ admin UI (password-gated)
```

## Features

- **Per-app API keys**: create, rename, edit and revoke them in the admin UI. A key is shown in full **once**, when it is created. Only its SHA-256 hash is stored.
- **`POST /api/send`** accepts to/cc/bcc, subject, text and/or HTML, reply-to and base64 attachments.
- **SMTP submission** for apps that only have "SMTP settings" (Gitea, Grafana, Vaultwarden, …): STARTTLS on 587 and/or implicit TLS on 465, with AUTH required. The username is the app name; the password is the app's key. The original MIME is forwarded unchanged (minus any `Bcc` header), and the same limits, sender rules and logging apply.
- **Connection details per app**: when a key is created, the dialog shows everything the app needs: SMTP host, ports, security, username and password, the HTTP endpoint, ready-to-paste curl and Python examples, and that app's limits. A **Connect** button on each key reopens this later, without the key. The relay's own upstream SMTP credentials are never shown.
- **Persistent queue**: each request is saved to SQLite before the API returns `202`, and a background worker delivers it. Messages survive restarts, and anything that was in flight during a crash is re-queued.
- **Retry with backoff** on transient failures: network errors, SMTP 4xx, auth problems. The default schedule is 30s, 2m, 10m, 30m, 1h, with up to 5 attempts. Permanent failures (SMTP 5xx) are not retried. An admin can re-queue a failed message.
- **Every attempt is logged**, including rejected ones: bad or revoked key, validation error, quota exceeded, sender not allowed. Each log entry records the timestamp, app, recipients, subject, status, attempts, error, Message-ID and client IP, plus a per-message event timeline.
- **Log search and filter**: free text (subject, recipient, error, id), app, status and date range.
- **Optional per-key limits**: max messages per minute and/or per 24h. Leave them blank for no limit.
- **Optional per-key sender restriction**: a list of allowed `from` addresses or `*@domain` patterns, checked on top of the relay-wide `MAIL_ALLOWED_FROM`.
- **Pluggable delivery backend**: SMTP is built in, plus a `console` backend for testing. See [Adding a provider API backend](#adding-a-provider-api-backend).
- **Privacy**: message bodies and attachments are kept only until delivery, then dropped. Metadata is kept forever by default; set `LOG_RETENTION_DAYS` to purge entries older than N days.

## Setup

```bash
git clone <this repo> email-relay && cd email-relay
cp .env.example .env
```

Edit `.env` and set at least:

- `ADMIN_PASSWORD`
- `SECRET_KEY` (generate it with `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`)
- `MAIL_FROM` and the `SMTP_*` settings for `notify@thetruesource.com`
- `PROXY_NETWORK`: the Docker network Nginx Proxy Manager is on (see below)

`.env` is git-ignored, so the real credentials stay on the server only.

Then build and start:

```bash
./rebuild.sh --force
```

To try it without sending real mail, set `MAIL_BACKEND=console`. Messages are then printed to `docker compose logs` instead of being sent.

## HTTPS: Nginx Proxy Manager + Cloudflare Tunnel

```
 homelab apps ──HTTPS──▶ Nginx Proxy Manager ──┐
 you (LAN)    ──HTTPS──▶ Nginx Proxy Manager ──┼──http (Docker network)──▶ email-relay:8000
 you (remote) ──HTTPS──▶ Cloudflare ─tunnel─▶ cloudflared ┘   (admin UI only; /api/* refused)
```

The relay publishes **no host port**. It is reachable only through the proxies on the shared Docker network, and it enforces the rules itself:

| Setting | Effect |
|---|---|
| `REQUIRE_HTTPS=true` | Any request whose `X-Forwarded-Proto` isn't `https` gets a 403. Plain-HTTP send attempts are logged as rejected. Responses carry HSTS. `/healthz` is exempt for the container healthcheck. |
| `BLOCK_API_VIA_CLOUDFLARE=true` | `/api/*` requests that carry Cloudflare headers (`CF-Connecting-IP` / `CF-Ray`) are refused and logged. The tunnel can only ever reach the admin UI, even if its ingress rules are too broad. |
| `TRUST_PROXY=true` | Takes the client IP from `CF-Connecting-IP`, `X-Real-IP` or `X-Forwarded-For` and the scheme from `X-Forwarded-Proto`, so logs and login throttling see real addresses. |
| `COOKIE_SECURE=true` | The admin session cookie is only ever sent over HTTPS. |

### 1. Docker network

Find the network NPM is on and set it as `PROXY_NETWORK` in `.env`:

```bash
docker network ls
```

```bash
docker inspect <npm-container> --format '{{json .NetworkSettings.Networks}}'
```

If NPM runs on a different machine, there's no shared network. In that case add `ports: ["<lan-ip>:8025:8000"]` to the
service and firewall that port so only the NPM host can reach it.

### 2. Nginx Proxy Manager (internal traffic)

Add a Proxy Host:
- **Domain:** `relay.thetruesource.com`, or a name like `relay.home.thetruesource.com`. Point it at NPM in your local DNS (Pi-hole, AdGuard, router) only.
- **Scheme / Forward host / Port:** `http` / `email-relay` / `8000`.
- **SSL tab:** request a Let's Encrypt certificate **using a DNS challenge** with Cloudflare as the provider and a Cloudflare API token with `Zone:DNS:Edit`. Enable **Force SSL**, **HTTP/2** and **HSTS**.

The DNS challenge gives you a real, publicly trusted certificate for a name that only resolves on your LAN. Nothing needs
to be exposed to the internet, and no app needs a custom CA or `verify=False`. NPM already sends `X-Real-IP` and
`X-Forwarded-Proto`, so nothing is needed in the Advanced tab.

Apps then send to `https://relay.thetruesource.com/api/send`.

### 3. Cloudflare Tunnel (remote admin access)

- Add a public hostname, for example `relay-admin.thetruesource.com`, with service `http://email-relay:8000`. This needs cloudflared on the same Docker network; otherwise point it at NPM.
- **Put a Cloudflare Access application in front of it** (Zero Trust → Access → Applications). Use a policy that allows only your email, with one-time PIN or SSO. The admin password then becomes a second layer instead of the only one.
- The relay refuses `/api/*` on this path anyway. If you want the tunnel to drop those requests before they reach the relay, add an ingress rule that only matches `^/(admin|static)`.

### Self-signed certificates

If you use a self-signed or private-CA certificate in NPM instead of Let's Encrypt, make each app trust the CA. Don't turn
off verification. Use `REQUESTS_CA_BUNDLE=/path/ca.crt` (Python requests), `SSL_CERT_FILE` (httpx),
`NODE_EXTRA_CA_CERTS` (Node), `curl --cacert`, or install the CA host-wide with `update-ca-certificates`.

The relay's own outbound SMTP connection always verifies certificates. If the SMTP server uses a private CA, put the CA
certificate in `./data/` and set `SMTP_CA_FILE=/data/<name>.crt`. Don't use `SMTP_SECURITY=none`.

### `rebuild.sh`

```bash
./rebuild.sh           # deploy if anything changed
./rebuild.sh --force   # always rebuild + restart
```

1. Checks out `main` and runs `git pull`, recording the commit SHA before and after.
2. If nothing changed, it exits without rebuilding (unless `--force` is passed).
3. It also catches stale containers: it reads the `git_sha` label of the running container's image. If that label doesn't match `HEAD`, or the container isn't running, it rebuilds anyway.
4. It builds with `docker buildx build --tag email-relay:latest --build-arg GIT_SHA=<sha> --load .`, not `docker compose build`. The Dockerfile bakes the SHA in as `LABEL git_sha=...`.
5. It restarts with `docker compose down && docker compose up -d --no-build`, then waits for the healthcheck to pass.

There is no self-restart handoff: the relay never redeploys itself from inside its own container. If you later add it to Deployment Helper as an ordinary sibling app, this script works as is.

### Data and backups

Everything lives in `./data/relay.db` (SQLite, WAL mode), which is bind-mounted to `/data` in the container.
To back up while the relay is running:

```bash
docker exec email-relay python -c "import sqlite3; s=sqlite3.connect('/data/relay.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d)"
```

Run **one** container with **one** uvicorn worker. The delivery queue runs inside the app process, and that is already set in the Dockerfile.

## Sending email from an app

Authenticate with `Authorization: Bearer <key>` or `X-API-Key: <key>`.

```bash
curl -X POST https://relay.thetruesource.com/api/send \
  -H "Authorization: Bearer erk_..." \
  -H "Content-Type: application/json" \
  -d '{
        "to": ["alice@example.com"],
        "subject": "Your invoice",
        "text": "Plain-text body",
        "html": "<p>HTML body</p>"
      }'
# 202 {"id": "3f2c...", "status": "queued"}
```

| Field         | Type                     | Notes                                                                 |
|---------------|--------------------------|-----------------------------------------------------------------------|
| `to`          | string or list, required | Max `MAX_RECIPIENTS` total across to/cc/bcc (default 50)              |
| `cc`, `bcc`   | string or list           |                                                                       |
| `subject`     | string, required         |                                                                       |
| `text`        | string                   | `text` and/or `html` required                                         |
| `html`        | string                   | Sent as `multipart/alternative` with `text`                           |
| `from`        | email                    | Defaults to `MAIL_FROM`; must be allowed globally and for the key     |
| `from_name`   | string                   | Display name; defaults to `MAIL_FROM_NAME`                            |
| `reply_to`    | email                    |                                                                       |
| `attachments` | list                     | `[{"filename", "content" (base64), "content_type"}]`, total ≤ `MAX_ATTACHMENT_BYTES` |

Python example:

```python
import base64, requests
requests.post("https://relay.thetruesource.com/api/send", headers={"Authorization": f"Bearer {KEY}"}, json={
    "to": "alice@example.com", "subject": "Report", "text": "See attached.",
    "attachments": [{"filename": "report.pdf", "content_type": "application/pdf",
                     "content": base64.b64encode(open("report.pdf", "rb").read()).decode()}],
}, timeout=30).raise_for_status()
```

**Responses:**

| Status | Meaning |
|--------|---------|
| `202`  | Queued |
| `400`/`422` | Invalid request |
| `401`  | Missing or unknown key |
| `403`  | Key revoked, or sender not allowed |
| `413`  | Too large |
| `429`  | Over the per-key limit (`Retry-After: 60`) |

Every non-202 response is also logged as `rejected`.

**Delivery status:** `GET /api/messages/{id}` (with the same key) returns `queued`, `sending`, `retrying`, `sent` or `failed`, along with the number of attempts and the last error.

Interactive API docs are at `/api/docs`.

## Sending email over SMTP (SMTP-only apps)

Use the details from the key's **Connect** dialog. In the app's mail settings, enter:

| Setting | Value |
|---|---|
| Host | `PUBLIC_HOSTNAME` (e.g. `relay.thetruesource.com`) |
| Port / security | `587` + STARTTLS (preferred) or `465` + SSL/TLS |
| Username | the app's name (informational) |
| Password | the app's relay key (`erk_…`) |
| From | `notify@thetruesource.com`, or another address the key is allowed to use |

How it behaves:
- TLS is mandatory. AUTH isn't offered before STARTTLS, and MAIL is refused before AUTH.
- A message is accepted with `250 … queued as <id>` and then delivered through the same queue as the API.
- If the `From` header isn't allowed, the server replies `553`. If the app is over its rate limit, it replies `451`, a temporary error, so the app retries later.
- Every attempt, including failed logins, is logged with **Via = smtp**.

### A certificate apps can verify

With no settings, the relay generates a **self-signed** certificate in `./data/tls/`, and the Overview page flags it.
To use a trusted certificate, reuse NPM's Let's Encrypt certificate for `PUBLIC_HOSTNAME`:

1. In `.env`, set `NPM_LETSENCRYPT_DIR` to NPM's `letsencrypt` folder on the host. That's the folder NPM mounts at `/etc/letsencrypt`.
2. Find the `npm-N` folder for the certificate. Its number is the certificate id shown in NPM's *SSL Certificates* list. You can also run `ls <dir>/live`.
3. Set:
   ```
   SUBMISSION_TLS_CERT=/npm-letsencrypt/live/npm-N/fullchain.pem
   SUBMISSION_TLS_KEY=/npm-letsencrypt/live/npm-N/privkey.pem
   ```
4. Run `./rebuild.sh --force`.

The relay checks the certificate files every 5 minutes, so NPM's renewals are picked up without a restart.

### Reaching the ports

The SMTP ports are published on the host, unlike HTTP. Apps connect to `PUBLIC_HOSTNAME:587`, so in your local DNS
`PUBLIC_HOSTNAME` must resolve to the machine running the relay. That's usually the same host as NPM.

To keep the ports off other interfaces, set `SUBMISSION_HOST_BIND` to the host's LAN IP. Don't forward 587/465 on your
router or through Cloudflare Tunnel: SMTP submission is meant for the homelab only. If those ports are already in use
on the host, change `SUBMISSION_STARTTLS_PORT` / `SUBMISSION_TLS_PORT`. To turn submission off, set `SUBMISSION_ENABLED=false`.

## Adding a provider API backend

`app/backends/base.py` defines the interface. To add one (for example Postmark, Resend or SES):

1. Subclass `Backend` and implement `send(payload, from_addr, from_name) -> SendResult`. It POSTs the payload to the provider.
2. Raise `TransientError` for 429/5xx/network errors and `PermanentError` for 4xx validation errors.
3. Register it in `app/backends/__init__.py:get_backend`, and add its settings to `config.py` and `.env.example`.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest
```

To run locally with the console backend:

```bash
ADMIN_PASSWORD=dev SECRET_KEY=$(python3 -c "print('x'*40)") MAIL_FROM=notify@thetruesource.com \
  MAIL_BACKEND=console DB_PATH=./data/dev.db .venv/bin/uvicorn app.main:_default_app --factory --reload
```

## Layout

```
app/
  main.py        FastAPI app: /api/send, /api/messages/{id}, admin API, static UI
  worker.py      background delivery loop (claim → send → sent | retry | failed)
  db.py          SQLite schema + queries
  schemas.py     request validation
  security.py    key generation/hashing, sender matching, login throttling
  service.py     admission rules shared by the HTTP API and SMTP (limits, senders, logging)
  submission.py  SMTP submission server (aiosmtpd): STARTTLS/implicit TLS, AUTH with app keys
  config.py      env-var settings
  backends/      smtp.py, console.py, base.py (interface + MIME builder)
  static/        admin UI (vanilla JS)
tests/           pytest suite (fake backend)
```
