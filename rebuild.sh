#!/usr/bin/env bash
# Pull latest code, rebuild the image if anything changed, and restart the relay.
#
#   ./rebuild.sh           # rebuild only if main moved or the running container is stale
#   ./rebuild.sh --force   # always rebuild + restart
set -euo pipefail

cd "$(dirname "$0")"

IMAGE="email-relay:latest"
CONTAINER="email-relay"
BRANCH="main"
FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

log() { echo "[rebuild $(date '+%Y-%m-%d %H:%M:%S')] $*"; }

if [[ ! -f .env ]]; then
  log "ERROR: .env not found. Copy .env.example to .env and fill it in first."
  exit 1
fi

# 1. Pull latest code, recording the commit before and after.
git checkout "$BRANCH"
BEFORE="$(git rev-parse HEAD)"
git pull --ff-only origin "$BRANCH"
AFTER="$(git rev-parse HEAD)"
log "HEAD before=${BEFORE:0:12} after=${AFTER:0:12}"

# 3. Stale-container detection: compare the running container's baked-in git_sha label to HEAD.
RUNNING_SHA=""
if docker inspect "$CONTAINER" >/dev/null 2>&1; then
  RUNNING_IMAGE="$(docker inspect --format '{{.Image}}' "$CONTAINER")"
  RUNNING_SHA="$(docker image inspect --format '{{ index .Config.Labels "git_sha" }}' "$RUNNING_IMAGE" 2>/dev/null || true)"
  RUNNING_STATE="$(docker inspect --format '{{.State.Status}}' "$CONTAINER")"
  log "Running container: state=$RUNNING_STATE git_sha=${RUNNING_SHA:-<none>}"
else
  log "No existing '$CONTAINER' container."
fi

# 2. Skip if unchanged (and not stale, and not forced).
if [[ $FORCE -eq 0 && "$BEFORE" == "$AFTER" ]]; then
  if [[ -n "$RUNNING_SHA" && "$RUNNING_SHA" == "$AFTER" && "${RUNNING_STATE:-}" == "running" ]]; then
    log "No new commits and running container is current. Nothing to do (use --force to rebuild anyway)."
    exit 0
  fi
  log "No new commits, but running container is missing/stale/stopped — rebuilding anyway."
fi

# 4. Build with buildx directly (not `docker compose build`), baking the commit in as a label.
log "Building $IMAGE at ${AFTER:0:12}"
docker buildx build \
  --tag "$IMAGE" \
  --build-arg GIT_SHA="$AFTER" \
  --load \
  .

# Restart. A plain down/up is enough: the relay never redeploys itself from inside its own container.
mkdir -p data
log "Restarting"
docker compose down
docker compose up -d --no-build

# Quick health check.
for i in $(seq 1 20); do
  STATUS="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER" 2>/dev/null || echo missing)"
  if [[ "$STATUS" == "healthy" ]]; then
    log "Up and healthy at ${AFTER:0:12}"
    exit 0
  fi
  if [[ "$STATUS" == "exited" || "$STATUS" == "missing" ]]; then
    break
  fi
  sleep 2
done
log "WARNING: container status is '$STATUS'. Recent logs:"
docker compose logs --tail 40 email-relay || true
exit 1
