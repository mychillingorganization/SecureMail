# SecureMail (Refactored)

SecureMail is a multi-agent email security platform with production-first structure:
- Multi-signal threat detection (phishing, malware, URL reputation)
- Autonomous AI reasoning with LangGraph + Gemini API
- Microservices architecture (email, file, web, AI, orchestrator)
- PostgreSQL database with Alembic migrations
- Web interface with real-time chat and whitelist/blacklist search
- Docker support for local and cross-platform deployment

## Project Layout

```text
SecureMail/
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── requirements.txt
├── setup.sh
├── src/
│   └── db/
│       ├── __init__.py
│       ├── config.py
│       ├── database.py
│       ├── models.py
│       ├── db_utils.py
│       ├── init.sql
│       └── migrations/
│           ├── env.py
│           ├── script.py.mako
│           └── versions/
├── orchestra/
│   ├── main.py
│   ├── config.py
│   ├── models.py        (compat wrapper -> src/db/models.py)
│   ├── database.py      (compat wrapper -> src/db/database.py)
│   └── db_utils.py      (compat wrapper -> src/db/db_utils.py)
├── email_module/
│   ├── main.py
│   └── models/
│       ├── svm_model.pkl
│       ├── tfidf.pkl
│       └── scaler.pkl
├── web_module/
│   ├── main.py
│   └── models/
│       └── xgboost_phishing_model.json
├── file_module/
│   └── file_module/
│       ├── main.py
│       └── models/
│           ├── model_word.pkl
│           ├── model_excel.pkl
│           ├── model_pdf.pkl
│           ├── model_qr.pkl
│           └── model_image.pkl
├── model_training_pipeline/
│   ├── README.md
│   ├── file_module/
│   ├── email_module/
│   ├── web_module/
│   └── data/
└── temporary/
    ├── root-legacy/
    ├── docs/
    └── scripts/
```

## Model Ownership Rule

Each agent stores its own inference artifacts:
- `email_module/models/`
- `web_module/models/`
- `file_module/file_module/models/`

Training/evaluation code and datasets live only in `model_training_pipeline/`.

## Database Standardization

Canonical DB layer is now in `src/db/`:
- ORM models: `src/db/models.py`
- Session/engine: `src/db/database.py`
- Migrations: `src/db/migrations/`
- Bootstrap SQL: `src/db/init.sql`

Alembic config entrypoint remains at `orchestra/alembic.ini` and points to `src/db/migrations`.

## Quick Start (Docker)

Recommended for new users (full stack in Docker):

```bash
cd /home/passla1/Desktop/final_project/SecureMail
sudo -E bash scripts/run_app.sh docker-full
```

Run with frontend too:

```bash
sudo -E bash scripts/run_app.sh docker-full --frontend
```

Recreate containers without rebuild/download:

```bash
sudo -E bash scripts/run_app.sh docker-full --recreate
```

Verify:

```bash
curl http://127.0.0.1:8080/health
```

Stop:

```bash
sudo docker compose -f docker-compose.full.yml down
```

## Local Setup (without Docker)

```bash
bash setup.sh
source .venv/bin/activate
./.venv/bin/python scripts/devctl.py up
./.venv/bin/python scripts/devctl.py status
```

## Frontend Only

Always run frontend from `UI-UX/`:

```bash
cd UI-UX
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

## Environment Variables

Common `.env` keys:
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `SECUREMAIL_DATABASE_URL`
- `SECUREMAIL_EMAIL_AGENT_URL`
- `SECUREMAIL_FILE_AGENT_URL`
- `SECUREMAIL_WEB_AGENT_URL`
- `SECUREMAIL_AI_AGENT_URL`

## Notes

- `temporary/` is a soft archive. Files are preserved, not deleted.
- `model_training_pipeline/` is intentionally excluded from production Docker context.
- Runtime schema source of truth is Alembic migration head in `src/db/migrations/versions/`.

## Troubleshooting

If scan shows `EmailAgent/WebAgent unavailable` or ports are busy, stop local services first, then recreate Docker services without rebuild:

```bash
./.venv/bin/python scripts/devctl.py down
sudo -E bash scripts/run_app.sh docker-full --recreate
```
=======
# SecureMail

SecureMail is a microservices-based email security platform designed to detect threats like phishing, malware, and malicious URLs. It features an orchestration layer that leverages the Gemini API for deep-dive analysis and threat reasoning.

## Architecture & Modules

The system is composed of several specialized microservices and components:

- **`orchestra/` (Orchestrator)**: The core entry point (port 8080). It coordinates the microservices, handles REST APIs for threat scanning (e.g., `/api/v1/scan-upload`), manages database interactions, and centrally utilizes the LLM for chat and deep-dive analysis.
- **`ai_module/`**: A microservice providing LLM analysis capabilities to the orchestrator (port 8003).
- **`email_module/`**: A microservice dedicated to email content analysis using machine learning models (port 8000).
- **`web_module/`**: A microservice specializing in URL reputation analysis, phishing detection, and SSL certificate verification (port 8002).
- **`file_module/`**: A microservice that scans attachments (Word, Excel, PDF, QR codes, Images) using domain-specific models (port 8001).
- **`src/db/`**: The canonical database layer managing ORM models, PostgreSQL connection pooling, and Alembic database migrations.
- **`UI-UX/`**: The frontend web interface (React + Vite) featuring real-time chat, threat reporting, and whitelist/blacklist configuration.
- **`model_training_pipeline/`**: Contains scripts, datasets, and pipelines used to train and evaluate the ML models across the different services.

*Note: Each service stores its own inference artifacts in its respective `models/` directory, while training code remains in `model_training_pipeline/`.*

## Fresh Setup Guide

### Prerequisites

- Python 3.11+
- PostgreSQL 16+
- Node.js & npm (for the frontend)
- Docker & Docker Compose (optional, for containerized deployment)
- Git

Additional compose files available:
- `docker-compose.dev.yml` for development overrides (reload/debug)
- `docker-compose.prod.yml` for production-oriented settings

---

### 1. Docker Setup (Quick Start)

> **Note:** The default `docker-compose.yml` starts the **PostgreSQL database** and the **Orchestrator** only. The individual microservices (email, file, web, ai) must be started separately on the host machine using `devctl.py` (see Local Setup below).

1. Clone the repository and navigate into it.
2. Copy `.env.example` to `.env` and fill in your API key:
   ```bash
   cp .env.example .env
   # Edit .env and set SECUREMAIL_GOOGLE_AI_STUDIO_API_KEY
   ```
3. Build and run the containers:
   ```bash
   docker compose up -d --build
   ```
4. Check the orchestrator health:
   ```bash
   curl http://localhost:8080/health
   ```
   Optional development mode with overrides:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
   ```
5. To stop the system:
   ```bash
   docker compose down
   ```

---

### 2. Local Setup (Full Development)

#### 2.1 Backend

1. Run the setup script to scaffold required directories, create a Python virtual environment, install dependencies, and create a standard `.env` file:
   ```bash
   bash setup.sh
   ```
2. Edit `.env` and set your `SECUREMAIL_GOOGLE_AI_STUDIO_API_KEY`.
3. Activate the virtual environment:
   ```bash
   source .venv/bin/activate
   ```
4. **Database**: Ensure PostgreSQL is running (or start it via `docker compose up -d postgres`). Then run the database migrations:
   ```bash
   alembic -c orchestra/alembic.ini upgrade head
   ```
   Optional (DB list seeding): URL/file blacklist and URL whitelist are **not** imported to PostgreSQL by default. To import them:
   ```bash
   python scripts/import_lists_to_postgres.py
   ```
5. Start all microservices (email, file, web, ai, orchestrator):
   ```bash
   python scripts/devctl.py up
   ```
   Alternative helper (supports optional frontend startup):
   ```bash
   bash scripts/run_app.sh local --frontend
   ```
6. Check the status of all services:
   ```bash
   python scripts/devctl.py status
   ```
7. To stop the local services:
   ```bash
   python scripts/devctl.py down
   ```

#### 2.2 Frontend (UI-UX)

1. Navigate to the frontend directory:
   ```bash
   cd UI-UX
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the development server:
   ```bash
   npm run dev
   ```
   The frontend will be available at `http://localhost:5173` by default.

---

### 3. Testing

You can test the system by uploading an `.eml` file via the frontend scanner page or by sending a request directly to the API:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/scan-upload \
  -F "file=@path/to/your/email.eml"
```

Additional useful scan endpoints:
- `POST /api/v1/scan` (JSON payload with `email_path`)
- `POST /api/v1/scan-batch` (JSON batch)
- `POST /api/v1/scan-upload-batch` (multipart batch upload)
- `POST /api/v1/scan-llm` and `POST /api/v1/scan-upload-llm` (LLM-assisted mode)

## Environment Variables

Key configuration variables in the `.env` file (see `.env.example` for full reference):

- **Database**: `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `SECUREMAIL_DATABASE_URL`
- **Service URLs**: `SECUREMAIL_EMAIL_AGENT_URL`, `SECUREMAIL_FILE_AGENT_URL`, `SECUREMAIL_WEB_AGENT_URL`, `SECUREMAIL_AI_AGENT_URL`
- **AI config**: `SECUREMAIL_GOOGLE_AI_STUDIO_API_KEY`, `SECUREMAIL_AI_AGENT_GOOGLE_AI_STUDIO_MODEL`