# SecureMail (Refactored)

SecureMail is a multi-agent email security platform with a production-first structure:
- Runtime services and inference models are separated from training assets.
- Database schema and migrations are centralized under `src/db`.
- Legacy/experimental files are soft-archived in `temporary/`.

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
├── email_agent/
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
│   ├── email_agent/
│   ├── web_module/
│   └── data/
└── temporary/
    ├── root-legacy/
    ├── docs/
    └── scripts/
```

## Model Ownership Rule

Each agent stores its own inference artifacts:
- `email_agent/models/`
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

### 1) Build and run

```bash
docker compose up -d --build
```

### 2) Verify

```bash
curl http://localhost:8080/health
```

### 3) Stop

```bash
docker compose down
```

## Local Setup (without Docker)

```bash
bash setup.sh
source .venv/bin/activate
/home/passla1/Desktop/SecureMail/.venv/bin/python scripts/devctl.py up
/home/passla1/Desktop/SecureMail/.venv/bin/python scripts/devctl.py status
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
