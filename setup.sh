#!/usr/bin/env bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo -e "${GREEN}[SecureMail Setup]${NC}"
echo ""

# Check for required system dependencies
echo "[0/6] Checking system dependencies..."
if ! command -v python3 &> /dev/null; then
  echo -e "${RED}ERROR: python3 is not installed${NC}"
  exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION found"

if ! command -v git &> /dev/null; then
  echo -e "${YELLOW}WARNING: git is not installed (optional)${NC}"
fi

# Create required directories
echo "[1/6] Creating required directories..."
mkdir -p model_training_pipeline/{file_module,email_module,web_module,data}
mkdir -p temporary/{root-legacy,docs,scripts}
mkdir -p src/db/migrations/versions
mkdir -p file_module/file_module/models email_module/models web_module/models
mkdir -p .runtime
echo -e "${GREEN}✓${NC} Directories created"

# Create virtual environment
echo "[2/6] Setting up Python virtual environment..."
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
  echo -e "${GREEN}✓${NC} Virtual environment created"
else
  echo -e "${GREEN}✓${NC} Virtual environment already exists"
fi

# Activate virtual environment
source .venv/bin/activate

# Upgrade pip and install dependencies
echo "[3/6] Installing Python dependencies..."
if ! pip install --upgrade pip setuptools wheel > /dev/null 2>&1; then
  echo -e "${RED}ERROR: Failed to upgrade pip${NC}"
  exit 1
fi

if ! pip install -r requirements.txt > /dev/null 2>&1; then
  echo -e "${RED}ERROR: Failed to install requirements${NC}"
  exit 1
fi
echo -e "${GREEN}✓${NC} Dependencies installed"

# Create .env file
echo "[4/6] Configuring environment..."
if [[ ! -f .env ]]; then
  # Check if .env.example exists
  if [[ -f .env.example ]]; then
    cp .env.example .env
    echo -e "${GREEN}✓${NC} Copied .env.example to .env"
  else
    cat > .env <<'EOF'
# Database
POSTGRES_DB=securemail
POSTGRES_USER=securemail
POSTGRES_PASSWORD=securemail
SECUREMAIL_DATABASE_URL=postgresql+asyncpg://securemail:securemail@127.0.0.1:5432/securemail

# Service URLs (local development)
SECUREMAIL_EMAIL_AGENT_URL=http://127.0.0.1:8000
SECUREMAIL_FILE_AGENT_URL=http://127.0.0.1:8001
SECUREMAIL_WEB_AGENT_URL=http://127.0.0.1:8002
SECUREMAIL_AI_AGENT_URL=http://127.0.0.1:8003

# AI Configuration (add your API keys here)
SECUREMAIL_GOOGLE_AI_STUDIO_API_KEY=
SECUREMAIL_AI_AGENT_GOOGLE_AI_STUDIO_API_KEY=
SECUREMAIL_AI_AGENT_GOOGLE_AI_STUDIO_MODEL=gemini-3.1-flash-lite-preview
EOF
    echo -e "${GREEN}✓${NC} Created .env with default development values"
  fi
else
  echo -e "${GREEN}✓${NC} .env already exists"
fi

# Check if .env has required API keys
if ! grep -q "SECUREMAIL_GOOGLE_AI_STUDIO_API_KEY=" .env; then
  echo -e "${YELLOW}WARNING: API keys not configured in .env - some features may not work${NC}"
fi

# Set proper file permissions
echo "[5/6] Setting file permissions..."
chmod +x scripts/*.py 2>/dev/null || true
echo -e "${GREEN}✓${NC} Permissions set"

# Summary
echo ""
echo -e "${GREEN}[6/6] Setup Complete!${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  For local development (using devctl):"
echo "    1) cd $ROOT_DIR"
echo "    2) source .venv/bin/activate"
echo "    3) python3 scripts/devctl.py up"
echo "    4) python3 scripts/devctl.py status"
echo ""
echo "  For Docker deployment:"
echo "    1) docker compose up -d --build"
echo "    2) curl http://127.0.0.1:8080/health"
echo ""
echo -e "${YELLOW}Configuration:${NC}"
echo "  Edit .env to add API keys and customize settings"
echo ""
echo -e "${GREEN}Documentation:${NC}"
echo "  See README.md for more information"
