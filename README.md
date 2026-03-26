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
