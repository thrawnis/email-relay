# syntax=docker/dockerfile:1.7
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DB_PATH=/data/relay.db

WORKDIR /srv

COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip pip install -r requirements.txt

COPY app ./app

# Baked in by rebuild.sh so it can tell whether the running container is stale.
ARG GIT_SHA=unknown
LABEL git_sha=$GIT_SHA \
      org.opencontainers.image.title="email-relay" \
      org.opencontainers.image.revision=$GIT_SHA
ENV GIT_SHA=$GIT_SHA

VOLUME ["/data"]
EXPOSE 8000 587 465

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

# Exactly one worker process: the delivery queue runs inside the app process.
CMD ["uvicorn", "app.main:_default_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers"]
