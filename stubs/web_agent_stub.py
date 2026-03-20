"""
Stub Web Agent — Dịch vụ tạm để kiểm thử pipeline.
Trả về điểm rủi ro giả cho các URL.
"""

import os
import time

from fastapi import FastAPI

app = FastAPI(title="Web Agent (Stub)")
STARTED_AT = time.time()


@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "service": "web-agent",
        "mode": "stub",
        "version": os.getenv("WEB_AGENT_STUB_VERSION", "0.1.0"),
        "uptime_seconds": round(time.time() - STARTED_AT, 3),
    }


@app.post("/api/v1/analyze")
async def analyze_urls(request: dict) -> dict:
    email_id = request.get("email_id", "unknown")
    urls = request.get("urls", [])
    url_count = len(urls) if isinstance(urls, list) else 0
    malicious_urls: list[str] = []
    suspicious_keywords = ("login", "verify", "secure", "bank", "update", "account")

    for url in urls if isinstance(urls, list) else []:
        if not isinstance(url, str):
            continue
        lowered = url.lower()
        if any(keyword in lowered for keyword in suspicious_keywords):
            malicious_urls.append(url)

    has_suspicious = len(malicious_urls) > 0
    risk_score = 0.7 if has_suspicious else (0.4 if url_count > 0 else 0.1)
    confidence = 0.85 if has_suspicious else (0.7 if url_count > 0 else 0.6)

    return {
        "email_id": email_id,
        "risk_score": risk_score,
        "confidence": confidence,
        "checks": {
            "url_reputation": {
                "malicious_urls": malicious_urls,
                "detail": "Suspicious URL keyword match found (stub)" if has_suspicious else "No suspicious keyword match (stub)",
            },
            "domain_age": {
                "suspicious": has_suspicious,
                "detail": "Some domains may be newly created (stub)" if has_suspicious else "All domains aged > 30 days (stub)",
            },
            "request_summary": {
                "url_count": url_count,
            },
        },
        "reasoning_trace": [
            "Received URL analysis request",
            f"Parsed {url_count} URLs",
            "URL reputation keyword check (stub)",
            "Domain age heuristic (stub)",
        ],
        "processing_time_ms": 30,
    }
