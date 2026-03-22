FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Install dependencies (from project root)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source files
COPY web_agent/*.py ./
COPY web_agent/xgboost_phishing_model.json ./

# Optional list files (mount or bake in)
# COPY whitelist.txt blacklist.txt ./

EXPOSE 8002

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
