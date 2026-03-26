FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel uv && \
    uv pip install --system --no-cache -r requirements.txt

# Copy application source files
COPY orchestra ./orchestra
COPY src ./src
COPY ai_module ./ai_module
COPY email_module ./email_module
COPY web_module ./web_module
COPY file_module/file_module ./file_module/file_module
COPY utils ./utils
COPY scripts ./scripts

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1

# Run migrations and start application
CMD ["sh", "-c", "alembic -c orchestra/alembic.ini upgrade head && uvicorn orchestra.main:app --host 0.0.0.0 --port 8080 --workers 2"]
