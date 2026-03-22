from fastapi import FastAPI

app = FastAPI(title="Email Agent API", description="API cho Email Agent (SPF/DKIM/DMARC, Typosquatting, LLM Analysis)")


@app.get("/health")
async def health_check():
    """Endpoint kiểm tra sức khỏe của dịch vụ."""
    return {"status": "ok"}


# Endpoint phân tích email (cấu trúc tham khảo từ document)
@app.post("/api/v1/analyze")
async def analyze_email(request: dict) -> dict:
    # Dummy implementation based on doc format
    email_id = request.get("email_id", "unknown-uuid")
    return {
        "email_id": email_id,
        "risk_score": 0.85,
        "confidence": 0.92,
        "checks": {
            "spf": {"pass": False, "detail": "softfail"},
            "dkim": {"pass": False, "detail": "chữ ký không hợp lệ"},
            "dmarc": {"pass": False, "detail": "chính sách reject"},
            "typosquat": {"detected": True, "matched_brand": "bankofamerica.com", "sender_domain": "bankofamer1ca.com", "jaro_winkler": 0.96, "levenshtein": 2},
            "llm_intent": {"classification": "phishing", "confidence": 0.88, "reasoning": "Email chứa ngôn ngữ khẩn cấp..."},
        },
        "reasoning_trace": ["Tiếp nhận email", "Phân tích SPF...", "Cảnh báo phishing từ LLM"],
        "processing_time_ms": 1200,
    }
