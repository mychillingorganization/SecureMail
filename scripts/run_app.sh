#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="local"
START_FRONTEND="false"
FORCE_RECREATE="false"
BUILD_IMAGES="false"

if [[ $# -gt 0 ]]; then
  MODE="$1"
  shift
fi

for arg in "$@"; do
  case "$arg" in
    --frontend)
      START_FRONTEND="true"
      ;;
    --recreate)
      FORCE_RECREATE="true"
      ;;
    --build)
      BUILD_IMAGES="true"
      ;;
    -h|--help)
      MODE="--help"
      ;;
    *)
      echo "[ERROR] Unknown option: $arg"
      exit 1
      ;;
  esac
done

if [[ "$FORCE_RECREATE" == "true" && "$BUILD_IMAGES" == "true" ]]; then
  echo "[ERROR] --recreate and --build cannot be used together"
  exit 1
fi

print_help() {
  cat <<'EOF'
Usage:
  bash scripts/run_app.sh [local|docker|docker-full] [--frontend] [--recreate|--build]

Modes:
  local   Start all services with scripts/devctl.py using .venv (default)
  docker  Start orchestrator + postgres in docker, use host agents
  docker-full  Start full stack in docker (postgres + all agents + app)

Options:
  --frontend   Also start UI-UX Vite frontend on http://127.0.0.1:5173
  --recreate   Force recreate containers without rebuild/download
  --build      Rebuild images before startup
EOF
}

wait_for_health() {
  local url="$1"
  local name="$2"
  local timeout_s="${3:-90}"

  local elapsed=0
  while true; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      echo "[OK] ${name} healthy: ${url}"
      return 0
    fi

    sleep 2
    elapsed=$((elapsed + 2))
    if (( elapsed >= timeout_s )); then
      echo "[ERROR] ${name} did not become healthy within ${timeout_s}s: ${url}"
      return 1
    fi
  done
}

if [[ "$MODE" == "-h" || "$MODE" == "--help" ]]; then
  print_help
  exit 0
fi

cd "$ROOT_DIR"

echo "[INFO] Root: $ROOT_DIR"
echo "[INFO] Mode: $MODE"
echo "[INFO] Frontend: $START_FRONTEND"
echo "[INFO] Recreate: $FORCE_RECREATE"
echo "[INFO] Build: $BUILD_IMAGES"

start_frontend() {
  local ui_dir="$ROOT_DIR/UI-UX"
  local pid_file="$ROOT_DIR/.runtime/frontend.pid"
  local log_file="$ROOT_DIR/.runtime/frontend.log"

  if curl -fsS "http://127.0.0.1:5173" >/dev/null 2>&1; then
    echo "[INFO] Frontend already reachable at http://127.0.0.1:5173"
    return 0
  fi

  if [[ ! -d "$ui_dir" ]]; then
    echo "[ERROR] Frontend directory missing: $ui_dir"
    return 1
  fi

  if ! command -v npm >/dev/null 2>&1; then
    echo "[ERROR] npm command not found"
    return 1
  fi

  mkdir -p "$ROOT_DIR/.runtime"
  cd "$ui_dir"

  if [[ ! -d node_modules ]]; then
    echo "[INFO] Installing frontend dependencies..."
    npm install
  fi

  echo "[INFO] Starting frontend (Vite) on 127.0.0.1:5173..."
  nohup npm run dev -- --host 127.0.0.1 --port 5173 >"$log_file" 2>&1 &
  echo $! >"$pid_file"

  wait_for_health "http://127.0.0.1:5173" "frontend" 120
}

case "$MODE" in
  local)
    if [[ ! -d ".venv" ]]; then
      echo "[INFO] .venv not found. Running setup.sh first..."
      bash setup.sh
    fi

    if [[ ! -x ".venv/bin/python" ]]; then
      echo "[ERROR] Missing Python executable at .venv/bin/python"
      exit 1
    fi

    echo "[INFO] Starting local services via devctl..."
    .venv/bin/python scripts/devctl.py up

    echo "[INFO] Checking service status..."
    .venv/bin/python scripts/devctl.py status

    wait_for_health "http://127.0.0.1:8080/health" "orchestrator" 120

    if [[ "$START_FRONTEND" == "true" ]]; then
      start_frontend
    fi

    cat <<'EOF'

App is running (local mode):
- Orchestrator API: http://127.0.0.1:8080
- Email Agent:      http://127.0.0.1:8000
- File Agent:       http://127.0.0.1:8001
- Web Agent:        http://127.0.0.1:8002
- AI Agent:         http://127.0.0.1:8003
- Frontend:         http://127.0.0.1:5173

Stop services:
  .venv/bin/python scripts/devctl.py down
  kill "$(cat .runtime/frontend.pid 2>/dev/null || echo '')" 2>/dev/null || true
EOF
    ;;

  docker)
    if ! command -v docker >/dev/null 2>&1; then
      echo "[ERROR] docker command not found"
      exit 1
    fi

    echo "[INFO] Starting docker compose stack..."
    if [[ "$FORCE_RECREATE" == "true" ]]; then
      docker compose up -d --force-recreate --no-build
    elif [[ "$BUILD_IMAGES" == "true" ]]; then
      docker compose up -d --build
    else
      docker compose up -d --no-build
    fi

    wait_for_health "http://127.0.0.1:8080/health" "orchestrator" 180

    if [[ "$START_FRONTEND" == "true" ]]; then
      start_frontend
    fi

    cat <<'EOF'

App is running (docker mode):
- Orchestrator API: http://127.0.0.1:8080
- Frontend:         http://127.0.0.1:5173

View logs:
  docker compose logs -f

Stop stack:
  docker compose down
  kill "$(cat .runtime/frontend.pid 2>/dev/null || echo '')" 2>/dev/null || true
EOF
    ;;

  docker-full)
    if ! command -v docker >/dev/null 2>&1; then
      echo "[ERROR] docker command not found"
      exit 1
    fi

    echo "[INFO] Starting full docker compose stack..."
    if [[ "$FORCE_RECREATE" == "true" ]]; then
      docker compose -f docker-compose.full.yml up -d --force-recreate --no-build
    elif [[ "$BUILD_IMAGES" == "true" ]]; then
      docker compose -f docker-compose.full.yml up -d --build
    else
      docker compose -f docker-compose.full.yml up -d --no-build
    fi

    wait_for_health "http://127.0.0.1:8080/health" "orchestrator" 240

    if [[ "$START_FRONTEND" == "true" ]]; then
      start_frontend
    fi

    cat <<'EOF'

App is running (docker-full mode):
- Orchestrator API: http://127.0.0.1:8080
- Email Agent:      http://127.0.0.1:8000
- File Agent:       http://127.0.0.1:8001
- Web Agent:        http://127.0.0.1:8002
- AI Agent:         http://127.0.0.1:8003
- Frontend:         http://127.0.0.1:5173

View logs:
  docker compose -f docker-compose.full.yml logs -f

Stop stack:
  docker compose -f docker-compose.full.yml down
  kill "$(cat .runtime/frontend.pid 2>/dev/null || echo '')" 2>/dev/null || true
EOF
    ;;

  *)
    echo "[ERROR] Unknown mode: $MODE"
    print_help
    exit 1
    ;;
esac
