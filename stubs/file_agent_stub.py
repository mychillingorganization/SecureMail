"""
Stub File Agent — Dịch vụ tạm để kiểm thử pipeline.
Trả về điểm rủi ro giả cho tệp đính kèm.
"""
from fastapi import FastAPI

app = FastAPI(title="File Agent (Stub)")


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "file-agent"}


@app.post("/api/v1/analyze")
async def analyze_file(request: dict) -> dict:
    email_id = request.get("email_id", "unknown")
    attachments = request.get("attachments", [])
    return {
        "email_id": email_id,
        "risk_score": 0.3,
        "confidence": 0.75,
        "checks": {
            "clamav_scan": {
                "infected": False,
                "detail": "No threats found (stub)"
            },
            "file_type_analysis": {
                "suspicious": False,
                "types_found": [a.get("filename", "unknown") for a in attachments]
            }
        },
        "reasoning_trace": ["Received file analysis request", "ClamAV scan (stub)", "File type check (stub)"],
        "processing_time_ms": 50
    }
