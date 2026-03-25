FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application source
COPY orchestra ./orchestra
COPY src ./src
COPY ai_module ./ai_module
COPY email_agent ./email_agent
COPY web_module ./web_module
COPY file_module/file_module ./file_module/file_module
COPY scripts ./scripts

EXPOSE 8080

HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1

CMD ["sh", "-c", "alembic -c orchestra/alembic.ini upgrade head && uvicorn orchestra.main:app --host 0.0.0.0 --port 8080"]
