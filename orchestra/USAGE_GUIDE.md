# SecureMail — Complete Usage Guide

**Last Updated:** March 22, 2026  
**Version:** 1.0.0

---

## Table of Contents

1. [Installation & Setup](#installation--setup)
2. [Environment Configuration](#environment-configuration)
3. [Running Services](#running-services)
4. [API Endpoints](#api-endpoints)
5. [Testing & Examples](#testing--examples)
6. [Configuration Reference](#configuration-reference)
7. [Troubleshooting](#troubleshooting)

---

## Installation & Setup

### Prerequisites

- **Python 3.11+**
- **Docker & Docker Compose** (for containerized deployment)
- **Google AI Studio API Key** (for LLM analysis) — Get it [here](https://aistudio.google.com)

### Step 1: Clone & Navigate

```bash
cd /home/passla1/projects/SecureMail
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 3: Setup Environment Variables

Create a `.env` file in the root directory:

```bash
cat > .env << 'EOF'
# Orchestrator
SECUREMAIL_DATABASE_URL=sqlite+aiosqlite:///./orchestra_api.db
SECUREMAIL_REQUEST_TIMEOUT_SECONDS=20.0
SECUREMAIL_EMAIL_SUSPICIOUS_THRESHOLD=0.8
SECUREMAIL_GOOGLE_AI_STUDIO_API_KEY=your-google-ai-key-here

# Email Agent Service
SECUREMAIL_EMAIL_AGENT_URL=http://localhost:8000

# File Agent Service
SECUREMAIL_FILE_AGENT_URL=http://localhost:8001

# Web Agent Service
SECUREMAIL_WEB_AGENT_URL=http://localhost:8002

# Optional: Threat Intelligence Hashes (comma-separated SHA256 values)
SECUREMAIL_THREAT_INTEL_MALICIOUS_HASHES=
EOF
```

**Replace** `your-google-ai-key-here` with your actual API key from [Google AI Studio](https://aistudio.google.com).

### Step 4: Initialize Database

```bash
python3 -m alembic upgrade head
```

---

## Environment Configuration

### Core Settings (Orchestrator)

All environment variables use the prefix `SECUREMAIL_` and are defined in [orchestra/config.py](orchestra/config.py).

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://securemail:securemail@localhost:5432/securemail` | SQLAlchemy database connection string. Use `sqlite+aiosqlite:///./orchestra_api.db` for local development. |
| `REQUEST_TIMEOUT_SECONDS` | `20.0` | HTTP timeout for agent calls (in seconds). |
| `EMAIL_AGENT_URL` | `http://localhost:8000` | Email Agent service endpoint. |
| `FILE_AGENT_URL` | `http://localhost:8001` | File Agent service endpoint. |
| `WEB_AGENT_URL` | `http://localhost:8002` | Web Agent service endpoint. |
| `EMAIL_SUSPICIOUS_THRESHOLD` | `0.8` | Risk score threshold (0.0–1.0) for marking email as SUSPICIOUS. |

### LLM Integration (Google AI Studio)

| Variable | Default | Description |
|----------|---------|-------------|
| `GOOGLE_AI_STUDIO_API_KEY` | `None` | **Required for LLM features.** Get from [AI Studio](https://aistudio.google.com). |
| `GOOGLE_AI_STUDIO_MODEL` | `gemini-3.1-flash-lite-preview` | LLM model to use. Alternatives: `gemini-pro`, `gemini-pro-vision`. |
| `GOOGLE_AI_STUDIO_BASE_URL` | `https://generativelanguage.googleapis.com/v1beta` | Google API base URL. |

### Threat Intelligence (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `THREAT_INTEL_MALICIOUS_HASHES` | `` (empty) | Comma-separated list of SHA256 file hashes marked as MALICIOUS. Example: `hash1,hash2,hash3`. |

---

## Running Services

### Option A: Local Python Development

#### 1. **Run Orchestrator**

```bash
export SECUREMAIL_DATABASE_URL='sqlite+aiosqlite:///./orchestra_api.db'
python3 -m uvicorn orchestra.main:app --host 127.0.0.1 --port 8080 --reload
```

Expected output:
```
INFO:     Uvicorn running on http://127.0.0.1:8080
```

#### 2. **Run Email Agent** (in another terminal)

```bash
python3 -m uvicorn email_agent.main:app --host 127.0.0.1 --port 8000 --reload
```

#### 3. **Run Web Agent** (in another terminal)

```bash
python3 -m uvicorn web_agent.main:app --host 127.0.0.1 --port 8002 --reload
```

#### 4. **Run File Agent** (stub, in another terminal)

```bash
python3 -m uvicorn email_agent.main:app --host 127.0.0.1 --port 8001 --reload
```

### Option B: Docker Compose (Production-like)

```bash
docker compose up -d --build
```

This starts:
- `orchestrator` on port 8080
- `email-agent` on port 8000
- `web-agent` on port 8002
- `file-agent` on port 8001
- `redis` on port 6379
- `postgres` on port 5432

Verify all services are healthy:

```bash
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8002/health
curl http://127.0.0.1:8001/health
```

---

## API Endpoints

### Base URL

- **Local Development:** `http://127.0.0.1:8080`
- **Docker:** `http://orchestrator:8080` (from within compose network) or `http://localhost:8080` (from host)

### Endpoints

#### 1. **Health Check**

```http
GET /health
```

Response (200 OK):
```json
{
  "status": "ok",
  "version": "1.0.0"
}
```

---

#### 2. **Rule-Based Scan** (Deterministic)

```http
POST /api/v1/scan
Content-Type: application/json
```

**Request Body:**

```json
{
  "email_path": "./test2.eml",
  "user_accepts_danger": false
}
```

**Response (200 OK):**

```json
{
  "scan_id": "abc123def456",
  "email_path": "./test2.eml",
  "final_status": "DANGER",
  "issue_count": 3,
  "termination_reason": "EARLY_TERMINATION",
  "execution_logs": [
    "[INFO] Parsed email: subject='Test Subject', sender='attacker@evil.com'",
    "[INFO] Email Agent: risk_score=0.92, confidence=0.95",
    "[DANGER] SPF+DKIM+DMARC all failed with high confidence",
    "[DECISION] Early termination triggered"
  ],
  "scan_timestamp": "2026-03-22T10:30:00Z",
  "database_id": "email-uuid-1234"
}
```

**Parameters:**

- `email_path` (string, required): Path to the EML file to scan.
- `user_accepts_danger` (boolean, optional, default: `false`): If `true`, scanning continues even on DANGER detection.

---

#### 3. **LLM Deep-Dive Analysis** (Content-Aware)

```http
POST /api/v1/scan-llm
Content-Type: application/json
```

**Request Body:**

```json
{
  "email_path": "./test3.eml",
  "user_accepts_danger": false
}
```

**Response (200 OK):**

```json
{
  "scan_id": "xyz789abc",
  "email_path": "./test3.eml",
  "final_status": "DANGER",
  "issue_count": 4,
  "termination_reason": "LLM_ANALYSIS",
  "execution_logs": [
    "[INFO] Parsed email: subject='Urgent: Verify your account', sender='noreply@bankofamer1ca.com'",
    "[INFO] Email Agent: risk_score=0.88, confidence=0.92",
    "[DANGER_ANALYSIS] Invoking LLM deep-dive...",
    "[RISK_FACTORS] Typosquat domain (bankofamer1ca ≈ bankofamerica), Urgency language, Fake link",
    "[CONFIDENCE] 95% (LLM indicates HIGH phishing probability)",
    "[RECOMMENDATION] Block sender, alert user, do not click links"
  ],
  "scan_timestamp": "2026-03-22T10:35:00Z",
  "database_id": "email-uuid-5678",
  "llm_analysis": {
    "risk_factors": [
      "Domain typosquatting (bankofamer1ca vs. bankofamerica)",
      "Urgency tactics (Verify your account immediately)",
      "Suspicious link (https://bit.ly/...)"
    ],
    "confidence_percent": 95,
    "simple_summary": "This is a phishing email attempting to trick you into clicking a malicious link.",
    "what_to_do": "Do not click any links. Report to your email provider. Delete the email."
  }
}
```

**Parameters:**

- `email_path` (string, required): Path to the EML file to scan.
- `user_accepts_danger` (boolean, optional, default: `false`): If `true`, scanning continues even on DANGER detection.

---

#### 4. **Backward-Compatible LLM Endpoint** (Alias)

```http
POST /api/v1/scan-google-aistudio
```

**Identical to `/api/v1/scan-llm`** above. This endpoint is an alias for backward compatibility.

---

#### 5. **File Upload & Scan**

```http
POST /api/v1/scan-upload
Content-Type: multipart/form-data
```

**Request:**

```bash
curl -X POST http://127.0.0.1:8080/api/v1/scan-upload \
  -F "file=@./test_email.eml" \
  -F "user_accepts_danger=false"
```

**Response (200 OK):**

Same as `/api/v1/scan` above.

---

#### 6. **Quick Check (HTML UI)**

```http
GET /quick-check
```

Opens an interactive HTML form in your browser to upload and scan emails. Access via:

```
http://127.0.0.1:8080/quick-check
```

---

## Testing & Examples

### Example 1: Test Spam/Probe Detection (Rule-Based)

```bash
curl -X POST http://127.0.0.1:8080/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"email_path":"./test2.eml","user_accepts_danger":false}' | jq
```

Expected result: `final_status: "DANGER"` (because auth checks fail)

---

### Example 2: Test Phishing Detection (LLM-Based)

```bash
curl -X POST http://127.0.0.1:8080/api/v1/scan-llm \
  -H 'Content-Type: application/json' \
  -d '{"email_path":"./test3.eml","user_accepts_danger":false}' | jq
```

Expected result: `final_status: "DANGER"` with detailed `llm_analysis` (risk factors, confidence %, recommendations)

---

### Example 3: Upload & Scan from Command Line

```bash
curl -X POST http://127.0.0.1:8080/api/v1/scan-upload \
  -F "file=@./myemail.eml" \
  -F "user_accepts_danger=false" | jq
```

---

### Example 4: Check Service Health

```bash
# Orchestrator
curl http://127.0.0.1:8080/health

# Email Agent
curl http://127.0.0.1:8000/health

# Web Agent
curl http://127.0.0.1:8002/health
```

---

### Example 5: Run Full Test Suite

```bash
cd /home/passla1/projects/SecureMail
python3 -m pytest orchestra/tests -v
```

Expected output:
```
test_integration.py::test_scan_with_email_agent PASSED
test_integration.py::test_scan_with_missing_agent PASSED
test_pipeline.py::test_execute_pipeline_safe PASSED
...
========================= 6 passed in 1.23s ==========================
```

---

## Configuration Reference

### Imports & Dependencies

#### **Orchestrator** (`orchestra/main.py`)

```python
from fastapi import FastAPI, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession
from email_agent.protocol_verifier import ProtocolVerifier
from orchestra.pipeline import execute_pipeline, PipelineDependencies
from orchestra.pipeline_deepdive import execute_pipeline_deepdive
from orchestra.config import get_settings
from orchestra.database import get_db_session, engine
from orchestra.models import Base
from orchestra.schemas import ScanRequest, ScanResponse
from orchestra.threat_intel import ThreatIntelScanner
```

#### **Email Agent** (`email_agent/main.py`)

```python
from fastapi import FastAPI
from email.parser import BytesParser
from email_agent.protocol_verifier import ProtocolVerifier
from email_agent.redis_client import RedisWhitelistCache
import joblib  # For SVM model loading
```

#### **Web Agent** (`web_agent/main.py`)

```python
from fastapi import FastAPI, HTTPException
from xgboost import Booster  # For XGBoost model
from bs4 import BeautifulSoup  # For HTML parsing
import ssl  # For certificate inspection
import socket  # For DNS lookups
```

---

### Config File Locations

| File | Purpose |
|------|---------|
| [orchestra/config.py](orchestra/config.py) | Orchestrator runtime settings (database, agents, LLM, thresholds) |
| [orchestra/models.py](orchestra/models.py) | SQLAlchemy ORM models (Email, File, URL, AuditLog) |
| [orchestra/schemas.py](orchestra/schemas.py) | Pydantic request/response schemas |
| [orchestra/pipeline.py](orchestra/pipeline.py) | Rule-based (deterministic) orchestration logic |
| [orchestra/pipeline_deepdive.py](orchestra/pipeline_deepdive.py) | LLM-based deep-dive analysis (for DANGER emails) |
| [.env](.env) | Runtime environment variables |

---

### Database Schema

**Tables (automatically created on startup):**

- `email` — Scanned email records with metadata
- `email_url` — URLs extracted from each email
- `email_file` — Attachment metadata (hash, status)
- `audit_log` — Decision traces and reasoning logs

**Connection Strings:**

```python
# SQLite (local development)
sqlite+aiosqlite:///./orchestra_api.db

# PostgreSQL (production)
postgresql+asyncpg://user:password@localhost:5432/securemail
```

---

## Troubleshooting

### Issue 1: "Connection refused" on agent calls

**Symptoms:** Orchestrator logs show `ConnectionError: Cannot connect to email-agent:8000`

**Solution:**

Make sure all agents are running:

```bash
ps aux | grep uvicorn
```

If missing, start them individually:

```bash
python3 -m uvicorn email_agent.main:app --host 127.0.0.1 --port 8000
python3 -m uvicorn web_agent.main:app --host 127.0.0.1 --port 8002
```

Or use Docker Compose:

```bash
docker compose up -d
```

---

### Issue 2: "Google API Key not configured" (LLM endpoints fail)

**Symptoms:** Response returns `simple_summary: "No Google API key configured"`

**Solution:**

1. Get a key from [Google AI Studio](https://aistudio.google.com)
2. Update `.env`:
   ```
   SECUREMAIL_GOOGLE_AI_STUDIO_API_KEY=your-actual-key
   ```
3. Restart orchestrator:
   ```bash
   pkill -f "uvicorn orchestra.main"
   python3 -m uvicorn orchestra.main:app --host 127.0.0.1 --port 8080
   ```

---

### Issue 3: "Database locked" (SQLite)

**Symptoms:** Logs show `sqlite3.OperationalError: database is locked`

**Solution:**

SQLite doesn't handle concurrent access well. For production, switch to PostgreSQL:

```bash
export SECUREMAIL_DATABASE_URL='postgresql+asyncpg://user:password@localhost:5432/securemail'
```

Or delete the stale database:

```bash
rm orchestra_api.db orchestra_api.db-wal orchestra_api.db-shm
```

---

### Issue 4: "ModuleNotFoundError" on import

**Symptoms:** `ModuleNotFoundError: No module named 'xgboost'`

**Solution:**

Reinstall dependencies:

```bash
pip install --upgrade -r requirements.txt
```

---

### Issue 5: LLM analysis times out

**Symptoms:** Scan takes >30 seconds, then returns timeout error

**Solution:**

Increase request timeout in `.env`:

```
SECUREMAIL_REQUEST_TIMEOUT_SECONDS=60.0
```

Or check your internet connection to Google API.

---

## Quick Reference

### Start Full Stack (Local)

```bash
# Terminal 1: Orchestrator
export SECUREMAIL_DATABASE_URL='sqlite+aiosqlite:///./orchestra_api.db'
python3 -m uvicorn orchestra.main:app --host 127.0.0.1 --port 8080

# Terminal 2: Email Agent
python3 -m uvicorn email_agent.main:app --host 127.0.0.1 --port 8000

# Terminal 3: Web Agent
python3 -m uvicorn web_agent.main:app --host 127.0.0.1 --port 8002

# Terminal 4: File Agent
python3 -m uvicorn email_agent.main:app --host 127.0.0.1 --port 8001
```

### Scan Email (Deterministic)

```bash
curl -X POST http://127.0.0.1:8080/api/v1/scan \
  -H 'Content-Type: application/json' \
  -d '{"email_path":"./test2.eml"}'
```

### Scan Email (LLM-Based)

```bash
curl -X POST http://127.0.0.1:8080/api/v1/scan-llm \
  -H 'Content-Type: application/json' \
  -d '{"email_path":"./test3.eml"}'
```

### Run Tests

```bash
python3 -m pytest orchestra/tests -v
```

### Clean Up (Kill all services)

```bash
pkill -f "uvicorn"
```

---

## Next Steps

1. **Add custom threat intelligence** → Update `SECUREMAIL_THREAT_INTEL_MALICIOUS_HASHES` with known malicious file hashes
2. **Deploy to production** → Switch to PostgreSQL, enable TLS, set up monitoring
3. **Extend LLM providers** → Add OpenAI or Claude support following the pattern in `pipeline_deepdive.py`
4. **Integrate email gateway** → Connect to postfix/sendmail to auto-scan inbound emails

---

## Support & Documentation

- **Main README:** [README.md](README.md)
- **Architecture Details:** [AGENTS.md](AGENTS.md)
- **Orchestrator Plan:** [orchestra/pland.md](orchestra/pland.md)
- **Email Agent:** [email_agent/README.md](email_agent/README.md)
- **Web Agent:** [web_agent/](web_agent/)

---

**Generated:** March 22, 2026  
**Status:** Production-Ready ✅
