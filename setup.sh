#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "[1/5] Creating required directories..."
mkdir -p model_training_pipeline/{file_agent,email_agent,web_agent,data}
mkdir -p temporary/{root-legacy,docs,scripts}
mkdir -p src/db/migrations/versions
mkdir -p FILE_AGENT/file_agent/models email_agent/models web_agent/models

echo "[2/5] Creating virtual environment..."
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi

source .venv/bin/activate

echo "[3/5] Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[4/5] Creating .env if missing..."
if [[ ! -f .env ]]; then
  cat > .env <<'EOF'
POSTGRES_DB=securemail
POSTGRES_USER=securemail
POSTGRES_PASSWORD=securemail
SECUREMAIL_DATABASE_URL=postgresql+asyncpg://securemail:securemail@localhost:5432/securemail
SECUREMAIL_EMAIL_AGENT_URL=http://localhost:8000
SECUREMAIL_FILE_AGENT_URL=http://localhost:8001
SECUREMAIL_WEB_AGENT_URL=http://localhost:8002
SECUREMAIL_AI_AGENT_URL=http://localhost:8003
EOF
  echo "Created .env with default development values."
else
  echo ".env already exists, keeping current values."
fi

echo "[5/5] Done. Next steps:"
echo "  1) docker compose up -d --build"
echo "  2) curl http://localhost:8080/health"
