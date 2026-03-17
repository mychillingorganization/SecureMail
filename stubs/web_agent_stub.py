"""
Stub Web Agent — Dịch vụ tạm để kiểm thử pipeline.
Trả về điểm rủi ro giả cho các URL.
"""

from fastapi import FastAPI

app = FastAPI(title="Web Agent (Stub)")


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "web-agent"}


@app.post("/api/v1/analyze")
async def analyze_urls(request: dict) -> dict:
    email_id = request.get("email_id", "unknown")
    return {
        "email_id": email_id,
        "risk_score": 0.4,
        "confidence": 0.70,
        "checks": {"url_reputation": {"malicious_urls": [], "detail": "No threats found (stub)"}, "domain_age": {"suspicious": False, "detail": "All domains aged > 30 days (stub)"}},
        "reasoning_trace": ["Received URL analysis request", "URL reputation check (stub)", "Domain age check (stub)"],
        "processing_time_ms": 30,
    }
