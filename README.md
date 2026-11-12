# Email Relay

A small, self-hosted outbound email relay for internal apps — a lightweight alternative to SendGrid/Mailgun.

The relay holds the **one real set of sending credentials** (for `notify@example.com`) and gives each app
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
- **SMTP submission** for apps that only have "SMTP settings" (Gitea, Grafana, Vaultwarden, …): STARTTLS on 587 and/or implicit TLS on 465, with AUTH required. The username is derived from the app name (see below); the password is the app's key. The original MIME is forwarded unchanged (minus any `Bcc` header), and the same limits, sender rules and logging apply.
- **Connection details per app**: when a key is created, the dialog shows everything the app needs: SMTP host, ports, security, username and password, the HTTP endpoint, ready-to-paste curl and Python examples, and that app's limits. A **Connect** button on each key reopens this later, without the key. The relay's own upstream SMTP credentials are never shown.
- **Persistent queue**: each request is saved to SQLite before the API returns `202`, and a background worker delivers it. Messages survive restarts, and anything that was in flight during a crash is re-queued.
- **Retry with backoff** on transient failures: network errors, SMTP 4xx, auth problems. The default schedule is 30s, 2m, 10m, 30m, 1h, with up to 5 attempts. Permanent failures (SMTP 5xx) are not retried. An admin can re-queue a failed message.
- **Every attempt is logged**, including rejected ones: bad or revoked key, validation error, quota exceeded, sender not allowed. The log records the **username** for every attempt: for SMTP, the login name exactly as the client typed it (even when the login failed, so you can see who is trying what), and for the HTTP API, the key's username. Failed logins are logged once per connection even if the client retries with another auth mechanism. You can search by username. Each log entry records the timestamp, app, recipients, subject, status, attempts, error, Message-ID and client IP, plus a per-message event timeline.
- **Usage charts** (admin UI → Charts): emails per day across all keys (sent, and failed or partial, as stacked columns) and one multi-line chart with a line per API key. The range defaults to the last 14 days, with presets (7, 30, 90 days) and a custom From/To (up to 366 days). Days are in your browser's time zone. The seven busiest keys get their own line and the rest are combined into one gray line; click a legend entry to hide or show a line. Hover for exact values, or expand "Show the data as tables". Rejected and still-pending messages aren't counted.
- **Log search and filter**: free text (subject, recipient, error, id), app, status and date range.
- **Optional per-key limits**: max messages per minute and/or per 24h. Leave them blank for no limit.
- **Optional per-key sender restriction**: a list of allowed `from` addresses or `*@domain` patterns, checked on top of the relay-wide `MAIL_ALLOWED_FROM`.
- **Pluggable delivery backend**: SMTP is built in, plus a `console` backend for testing. See [Adding a provider API backend](#adding-a-provider-api-backend).
- **Privacy**: message bodies and attachments are kept only until delivery, then dropped. Metadata is kept forever by default; set `LOG_RETENTION_DAYS` to purge entries older than N days.

## Setup

```bash
git clone https://github.com/thrawnis/email-relay.git email-relay && cd email-relay
cp .env.example .env
```

Edit `.env` and set at least:

- `ADMIN_PASSWORD`
- `SECRET_KEY` (generate it with `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`)
- `MAIL_FROM` and the `SMTP_*` settings for `notify@example.com`
- `PUBLIC_HOSTNAME`, `SUBMISSION_HOSTNAME` and `TRUSTED_PROXIES` (see below)

`.env` is git-ignored, so the real credentials stay on the server only.

Then build and start:

```bash
./rebuild.sh --force
```

To try it without sending real mail, set `MAIL_BACKEND=console`. Messages are then printed to `docker compose logs` instead of being sent.

## HTTPS: Nginx Proxy Manager (separate server) + Cloudflare Tunnel

```
 homelab apps ──HTTPS──▶ NPM server ──HTTPS (LAN)──┐
 you (LAN)    ──HTTPS──▶ NPM server ──HTTPS (LAN)──┼──▶ relay host :8443 ─▶ email-relay
 you (remote) ──▶ Cloudflare Access ─▶ tunnel ─▶ cloudflared ──HTTPS──┘   (admin UI only)
 SMTP-only apps ──SMTP + STARTTLS/TLS──▶ relay host :587 / :465 (direct; NPM can't proxy SMTP)
```

**The relay only runs over HTTPS; there is no setting to turn that off.**
- It serves HTTPS itself on its LAN port, so even the hop from NPM to the relay is encrypted. There is no plain-HTTP port at all.
- Every request must have arrived over HTTPS. Behind a proxy, that means a trusted proxy's `X-Forwarded-Proto` must be `https`. Anything else gets a 403, including `/healthz`, and plain-HTTP send attempts are logged as rejected.
- Every response carries HSTS, and the admin session cookie is always `Secure`.
- SMTP submission is TLS-only as well.
- Setting `HTTP_TLS`, `REQUIRE_HTTPS` or `COOKIE_SECURE` to `false` makes the relay refuse to start.

The relay also has these settings:

| Setting | Effect |
|---|---|
| `TRUST_PROXY=true` + `TRUSTED_PROXIES` | The client IP (`CF-Connecting-IP` / `X-Real-IP` / `X-Forwarded-For`) and scheme are taken from proxy headers **only** when the request comes from a listed IP. Set this to the NPM server's IP and the cloudflared host's IP. |
| `BLOCK_API_VIA_CLOUDFLARE=true` | `/api/*` requests carrying Cloudflare headers are refused and logged, so the tunnel can only ever reach the admin UI. |

### 1. Relay host: ports and firewall

`docker-compose.yml` publishes three ports on `RELAY_HOST_BIND`. Set that to this host's LAN IP rather than `0.0.0.0`.

| Port | What | Who should reach it |
|---|---|---|
| `8443` (`RELAY_HTTPS_PORT`) | HTTPS: admin UI + API | only the NPM server and the cloudflared host |
| `587` / `465` | SMTP submission | homelab hosts that run SMTP-only apps |

For example, with `ufw` and NPM at `192.168.1.10`:

```bash
sudo ufw allow from 192.168.1.10 to any port 8443 proto tcp
```

```bash
sudo ufw allow from 192.168.1.0/24 to any port 587,465 proto tcp
```

Docker publishes ports by writing its own iptables rules, which bypass ufw's normal rules. Either bind `RELAY_HOST_BIND` to the
LAN IP and rely on your network's segmentation, or add the restrictions to the `DOCKER-USER` chain.

### 2. Nginx Proxy Manager (on the other server)

Add a Proxy Host:
- **Domain:** `emailrelay.example.com` (`PUBLIC_HOSTNAME`). Point it at the NPM server in your local DNS only.
- **Scheme / Forward host / Port:** **`https`** / the relay host's LAN IP / `8443`.
- **SSL tab:** request a Let's Encrypt certificate **using a DNS challenge** with Cloudflare as the provider (a Cloudflare API token with `Zone:DNS:Edit`). Enable **Force SSL**, **HTTP/2** and **HSTS**.

By default NPM doesn't verify the upstream certificate, so the relay's auto-generated self-signed certificate is enough
for this hop. Apps only ever see NPM's Let's Encrypt certificate, so no app needs a custom CA or `verify=False`.

Then set `TRUSTED_PROXIES` in the relay's `.env` to the NPM server's IP (plus cloudflared's, see below).

### 3. Cloudflare Tunnel (remote admin access)

- Add a public hostname for the **same name**, `emailrelay.example.com`. Point it at **NPM** (`https://<npm-ip>` with
  the origin server name `emailrelay.example.com`), or directly at `https://<relay-host>:8443` with *No TLS Verify* enabled.
  This is split DNS: Cloudflare's public DNS sends outside visitors to the tunnel, and your local DNS override sends LAN
  clients straight to NPM. One name works everywhere, and the HSTS and cookie settings stay consistent.
  If it points straight at the relay, add the cloudflared host's IP to `TRUSTED_PROXIES`.
- **Put a Cloudflare Access application in front of it**: Zero Trust → Access → Applications, with a policy that allows only your email.
- The relay refuses `/api/*` through the tunnel regardless.

### 4. SMTP hostname and a certificate apps can verify

NPM only proxies HTTP, so SMTP-only apps connect straight to the relay host. Give it its own name, for example
`SUBMISSION_HOSTNAME=smtp.emailrelay.example.com`, and in local DNS point that name at the **relay host's** IP.

By default the relay uses a self-signed certificate covering both hostnames, stored in `./data/tls/`. The Overview page flags it.
It works, but each SMTP app would then have to trust it or skip verification. For a trusted certificate:

1. On the NPM server, issue a Let's Encrypt certificate for `smtp.emailrelay.example.com` with the DNS challenge
   (*SSL Certificates → Add → Let's Encrypt*). It doesn't need a proxy host.
2. Copy its `fullchain.pem` and `privkey.pem` to the relay host as `./data/certs/`, and keep them in sync with a daily cron job on the relay host:
   ```bash
   rsync -aL npm-server:/path/to/npm/letsencrypt/live/npm-N/ /path/to/email-relay/data/certs/ && docker restart email-relay
   ```
   `npm-N` is the certificate's id in NPM. `-L` copies the real files rather than the symlinks.
3. In `.env`, set `TLS_CERT=/data/certs/fullchain.pem` and `TLS_KEY=/data/certs/privkey.pem`, then run `./rebuild.sh --force`.

SMTP picks up a changed certificate within 5 minutes without a restart. The HTTPS port needs a restart, which is why the
cron job above runs `docker restart`; only NPM sees that certificate, so this is optional.

### Self-signed certificates for apps

If an app talks to a self-signed endpoint, make it trust the CA rather than turning verification off. Use
`REQUESTS_CA_BUNDLE=/path/ca.crt` (Python requests), `SSL_CERT_FILE` (httpx), `NODE_EXTRA_CA_CERTS` (Node),
`curl --cacert`, or install the CA host-wide with `update-ca-certificates`.

The relay's own outbound SMTP connection always verifies certificates. If the upstream SMTP server uses a private CA,
put the CA certificate in `./data/` and set `SMTP_CA_FILE=/data/<name>.crt`. Don't use `SMTP_SECURITY=none`.

### `rebuild.sh`

```bash
./rebuild.sh           # deploy if anything changed
./rebuild.sh --force   # always rebuild + restart
```

1. Fetches `origin/main` and hard-resets to it, **discarding** any local edits, local commits and untracked files in the checkout. Git-ignored files (`.env`, `data/`) are kept. It records the commit SHA before and after. If `rebuild.sh` itself changed, it restarts itself so the new version runs.
2. If nothing changed (and no local changes had to be discarded), it exits without rebuilding, unless `--force` is passed.
3. It also catches stale containers: it reads the `git_sha` label of the running container's image. If that label doesn't match `HEAD`, or the container isn't running, it rebuilds anyway.
4. It builds with `docker buildx build --tag email-relay:latest --build-arg GIT_SHA=<sha> --load .`, not `docker compose build`. The Dockerfile bakes the SHA in as `LABEL git_sha=...`.
5. It restarts with `docker compose down && docker compose up -d --no-build`, then waits for the healthcheck to pass.

There is no self-restart handoff: the relay never redeploys itself from inside its own container. If a deployment tool triggers it as an ordinary app, this script works as is.

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
curl -X POST https://emailrelay.example.com/api/send \
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
requests.post("https://emailrelay.example.com/api/send", headers={"Authorization": f"Bearer {KEY}"}, json={
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

**Delivery status:** `GET /api/messages/{id}` (with the same key) returns the status, the number of attempts and the last error.

| Status | Meaning |
|---|---|
| `queued` / `sending` / `retrying` | Not finished yet |
| `sent` | The upstream SMTP server **accepted** the message for every recipient |
| `partial` | Accepted for some recipients, refused for others; `error` lists which |
| `failed` | Permanently refused (5xx), or still failing after `MAX_ATTEMPTS` |
| `rejected` | Refused by the relay itself (bad key, invalid request, limit, sender not allowed) |

`sent` means the upstream server took responsibility for the message. If it later bounces (unknown mailbox, spam
filtering, sender not permitted), the bounce goes back to the sender's mailbox (`MAIL_FROM`), not to the relay. Check that
mailbox when a message shows `sent` but never arrived. With `MAIL_BACKEND=console`, every message shows `sent` but nothing is
delivered; the admin UI shows a test-mode banner in that case.

Interactive API docs are at `/api/docs`.

## Sending email over SMTP (SMTP-only apps)

Use the details from the key's **Connect** dialog. In the app's mail settings, enter:

| Setting | Value |
|---|---|
| Host | `SUBMISSION_HOSTNAME` (e.g. `smtp.emailrelay.example.com`) |
| Port / security | `587` + STARTTLS (preferred) or `465` + SSL/TLS |
| Username | the app's username, shown in its Connect dialog (informational) |
| Password | the app's relay key (`erk_…`) |
| From | `notify@example.com`, or another address the key is allowed to use |

**Usernames** are generated from the app name: lowercase, accents folded to plain letters, and spaces or symbols
collapsed to single hyphens, so they're safe in any app's SMTP settings. `Café Ünïcode App!` becomes `cafe-unicode-app`
(`ß`→`ss`, `ø`→`o`, `ł`→`l`; a name with no Latin letters becomes `app`). Usernames are unique, with `-2`, `-3`… added when
two names collapse to the same one, at most 32 characters, and they follow the app if you rename it. The relay doesn't check the
username at login, because the key identifies the app, so a differently typed username never causes a failed login.

How it behaves:
- TLS is mandatory. AUTH isn't offered before STARTTLS, and MAIL is refused before AUTH.
- A message is accepted with `250 … queued as <id>` and then delivered through the same queue as the API.
- If the `From` header isn't allowed, the server replies `553`. If the app is over its rate limit, it replies `451`, a temporary error, so the app retries later.
- Every attempt, including failed logins, is logged with **Via = smtp**.

### Certificate and reachability

Apps connect to `SUBMISSION_HOSTNAME`, which resolves to the relay host. See
[step 4 above](#4-smtp-hostname-and-a-certificate-apps-can-verify) for the DNS record and the trusted certificate.

Don't forward 587/465 on your router or through Cloudflare Tunnel: SMTP submission is meant for the homelab only. If those ports
are already in use on the relay host, change `SUBMISSION_STARTTLS_PORT` / `SUBMISSION_TLS_PORT`. To turn submission off,
set `SUBMISSION_ENABLED=false`.

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
ADMIN_PASSWORD=dev SECRET_KEY=$(python3 -c "print('x'*40)") MAIL_FROM=notify@example.com \
  MAIL_BACKEND=console DB_PATH=./data/dev.db SUBMISSION_ENABLED=false .venv/bin/python -m app.serve
# → https://localhost:8000/admin (self-signed cert generated in ./data/tls)
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
  tls.py         certificate loading / self-signed generation (HTTPS port + SMTP)
  serve.py       container entrypoint (uvicorn with TLS)
  config.py      env-var settings
  backends/      smtp.py, console.py, base.py (interface + MIME builder)
  static/        admin UI (vanilla JS)
tests/           pytest suite (fake backend)
```
