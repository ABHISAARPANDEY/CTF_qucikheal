#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/sentinel-ai-backend"
FRONTEND_DIR="$ROOT_DIR/sentinel-ai-frontend"

if [[ ! -d "$BACKEND_DIR" ]]; then
  echo "[run-dev] missing backend dir: $BACKEND_DIR" >&2
  exit 1
fi

if [[ ! -d "$FRONTEND_DIR" ]]; then
  echo "[run-dev] missing frontend dir: $FRONTEND_DIR" >&2
  exit 1
fi

if [[ ! -x "$BACKEND_DIR/.venv/bin/python" ]]; then
  echo "[run-dev] backend venv missing at sentinel-ai-backend/.venv" >&2
  echo "[run-dev] setup:" >&2
  echo "  cd sentinel-ai-backend" >&2
  echo "  python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt" >&2
  exit 1
fi

if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
  echo "[run-dev] frontend deps missing; installing..." >&2
  (cd "$FRONTEND_DIR" && npm install)
fi

# Incomplete installs (e.g. interrupted npm) leave lucide-react without dist/esm/icons,
# which breaks Vite with "Failed to resolve import lucide-react".
if [[ -d "$FRONTEND_DIR/node_modules" ]] &&
  [[ ! -f "$FRONTEND_DIR/node_modules/lucide-react/dist/esm/icons/index.mjs" ]]; then
  echo "[run-dev] lucide-react tree incomplete; reinstalling frontend deps (npm ci)..." >&2
  (
    cd "$FRONTEND_DIR"
    chmod -R u+w node_modules 2>/dev/null || true
    rm -rf .vite node_modules/.vite node_modules
    npm ci
  )
fi

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
  echo ""
  echo "[run-dev] shutting down..."
  if [[ -n "$BACKEND_PID" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  if [[ -n "$FRONTEND_PID" ]] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
    kill "$FRONTEND_PID" 2>/dev/null || true
  fi
  wait 2>/dev/null || true
}

trap cleanup INT TERM EXIT

echo "[run-dev] starting backend on http://localhost:8000"
(
  cd "$BACKEND_DIR"
  exec ./.venv/bin/python -m uvicorn app.main:app --reload --reload-dir app --host 0.0.0.0 --port 8000
) &
BACKEND_PID=$!

echo "[run-dev] starting frontend on http://localhost:5173"
(
  cd "$FRONTEND_DIR"
  exec npm run dev -- --host 0.0.0.0 --port 5173
) &
FRONTEND_PID=$!

echo "[run-dev] backend pid=$BACKEND_PID | frontend pid=$FRONTEND_PID"
echo "[run-dev] press Ctrl+C to stop both"

while true; do
  if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    wait "$BACKEND_PID" 2>/dev/null || true
    break
  fi
  if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
    wait "$FRONTEND_PID" 2>/dev/null || true
    break
  fi
  sleep 1
done
