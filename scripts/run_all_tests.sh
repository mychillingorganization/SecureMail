#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "[ERROR] Python virtual environment not found at ${PYTHON_BIN}"
  echo "[HINT] Run: bash setup.sh"
  exit 1
fi

run_step() {
  local title="$1"
  shift
  echo
  echo "[RUN] ${title}"
  "$@"
  echo "[OK]  ${title}"
}

echo "[INFO] SecureMail full validation started"
echo "[INFO] Root: ${ROOT_DIR}"

run_step "Orchestrator tests" \
  bash -lc "cd '${ROOT_DIR}/orchestra' && '${PYTHON_BIN}' -m pytest -q tests"

run_step "Web module tests" \
  bash -lc "cd '${ROOT_DIR}/web_module' && '${PYTHON_BIN}' -m pytest -q tests"

run_step "Scan history test" \
  bash -lc "cd '${ROOT_DIR}/scripts' && '${PYTHON_BIN}' -m pytest -q test_scan_history.py"

run_step "Frontend production build" \
  bash -lc "cd '${ROOT_DIR}/UI-UX' && npm run build"

run_step "Service end-to-end smoke flow" \
  bash -lc "cd '${ROOT_DIR}' && '${PYTHON_BIN}' scripts/devctl.py up && '${PYTHON_BIN}' scripts/devctl.py status && '${PYTHON_BIN}' scripts/devctl.py test7 && '${PYTHON_BIN}' scripts/devctl.py down"

echo
echo "[DONE] SecureMail full validation passed"
