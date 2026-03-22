"""
main.py — FastAPI application
File Agent: phân tích tệp đính kèm email

Endpoints:
  POST /analyze              — Upload file để phân tích (hash + static)
  POST /analyze/full         — Upload file, phân tích đầy đủ (+ sandbox)
  POST /sandbox/{id}         — Kích hoạt sandbox cho kết quả đã có
  POST /clawback/{id}        — Thực hiện post-delivery clawback
  GET  /result/{id}          — Lấy kết quả theo analysis_id
  GET  /results              — Liệt kê kết quả gần nhất
  GET  /clawback/log         — Xem clawback audit log
  GET  /health               — Health check
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import redis.asyncio as aioredis
import structlog
from fastapi import FastAPI, File, Form, HTTPException, UploadFile, Depends
from fastapi.middleware.cors import CORSMiddleware

from clawback import execute_clawback, get_quarantine_log
from config import settings
from dynamic_sandbox import run_sandbox
from hash_triage import run_hash_triage
from models import AnalysisResult, FileType, RiskLevel, XGBoostResult
from static_analyzer import run_static_analysis
from xgboost_classifier import predict_risk

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(
        logging.getLevelName(settings.log_level)
    ),
)
log = structlog.get_logger()

# ─────────────────────────────────────────────
# Startup / Shutdown
# ─────────────────────────────────────────────
redis_client: Optional[aioredis.Redis] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global redis_client
    log.info("File Agent khởi động")

    # Kết nối Redis
    redis_client = aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=False,
    )
    try:
        await redis_client.ping()
        log.info(" Redis kết nối thành công", url=settings.redis_url)
    except Exception as e:
        log.warning("  Redis không khả dụng — cache bị vô hiệu", error=str(e))

    yield

    # Cleanup
    if redis_client:
        await redis_client.aclose()
    log.info(" File Agent đã dừng")


# ─────────────────────────────────────────────
# App
# ─────────────────────────────────────────────
app = FastAPI(
    title="File Agent — Malware Analysis API",
    description="Pipeline phân tích tệp đính kèm: hash triage → static analysis → sandbox → AI report",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
# Dependencies
# ─────────────────────────────────────────────

async def get_redis() -> aioredis.Redis:
    if redis_client is None:
        raise HTTPException(503, "Redis chưa sẵn sàng")
    return redis_client


# ─────────────────────────────────────────────
# Result store (in-memory cho demo; thay bằng PostgreSQL ở production)
# ─────────────────────────────────────────────
_result_store: dict[str, AnalysisResult] = {}


# ─────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────

@app.get("/health")
async def health():
    redis_ok = False
    if redis_client:
        try:
            await redis_client.ping()
            redis_ok = True
        except Exception:
            pass
    return {
        "status": "ok",
        "redis": redis_ok,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/analyze", response_model=AnalysisResult, status_code=200)
async def analyze_file(
    file: UploadFile = File(...),
    redis: aioredis.Redis = Depends(get_redis),
):
    """
    Upload file để phân tích.
    
    Pipeline:
      1. Hash triage (SHA-256 → Redis → IOC DB → ClamAV)
      2. Static analysis (oletools / pdf-parser / pefile / YARA / archive)
      3. Risk scoring & aggregation
    """
    # ── Validate file size ─────────────────────────────────────
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    data = await file.read()

    if len(data) == 0:
        raise HTTPException(400, "File trống")
    if len(data) > max_bytes:
        raise HTTPException(413, f"File vượt quá giới hạn {settings.max_upload_size_mb}MB")

    filename = file.filename or "unknown"
    analysis_id = str(uuid.uuid4())

    log.info(" Nhận file", filename=filename, size=len(data), id=analysis_id)
    
    # Debug: Save uploaded file for analysis
    debug_dir = Path("/tmp/file_agent_debug")
    debug_dir.mkdir(exist_ok=True)
    debug_path = debug_dir / f"{analysis_id}_{filename}"
    debug_path.write_bytes(data)
    log.info(f" Saved debug file: {debug_path}")

    # ── Stage 1: Hash Triage ───────────────────────────────────
    log.info(" Bắt đầu hash triage", id=analysis_id)
    hash_result = await run_hash_triage(data, redis)

    # ── Stage 2: Static Analysis ───────────────────────────────
    log.info(" Bắt đầu static analysis", id=analysis_id)
    static_result = run_static_analysis(data, filename)

    # ── Aggregate ─────────────────────────────────────────────
    result = AnalysisResult(
        analysis_id=analysis_id,
        filename=filename,
        file_type=static_result.file_type,
        hash_triage=hash_result,
        static_analysis=static_result,
    )
    
    # ── Stage 3: XGBoost Prediction ────────────────────────────
    log.info(" Bắt đầu XGBoost prediction", id=analysis_id)
    xgb_result = predict_risk(result)
    if xgb_result.get("available"):
        log.info(
            f"[XGBoost] Prediction: {xgb_result['risk_level']} "
            f"(confidence={xgb_result['confidence']:.2f})",
            id=analysis_id
        )
        result._xgboost_result = xgb_result  # type: ignore
        result.xgboost = XGBoostResult(
            available=xgb_result.get("available", False),
            risk_level=xgb_result.get("risk_level", "unknown"),
            confidence=xgb_result.get("confidence", 0.0),
            probabilities=xgb_result.get("probabilities", {}),
            top_features=xgb_result.get("top_features", []),
        )
    else:
        log.info("[XGBoost] Model không khả dụng", id=analysis_id)
        result.xgboost = XGBoostResult(available=False)
    
    result.compute_risk()

    # ── Determine if sandbox needed ────────────────────────────
    # ✅ PE + SCRIPT: Always sandbox if medium+
    # ✅ PDF: Sandbox if has JS + launch action
    # ✅ OFFICE: Sandbox if has macros + suspicious keywords
    needs_pdf_sandbox = (
        static_result.file_type == FileType.PDF
        and static_result.pdf
        and static_result.pdf.has_javascript
        and (static_result.pdf.has_open_action or static_result.pdf.has_launch_action)
    )
    
    needs_office_sandbox = (
        static_result.file_type == FileType.OFFICE
        and static_result.ole
        and static_result.ole.has_macros
        and len(static_result.ole.suspicious_keywords) > 0
    )
    
    result.needs_sandbox = (
        (static_result.file_type in (FileType.PE, FileType.SCRIPT) and result.risk_score >= 0.15)
        or needs_pdf_sandbox
        or needs_office_sandbox
        or result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    )

    # Store result
    _result_store[analysis_id] = result

    log.info(
        " Phân tích hoàn thành",
        id=analysis_id,
        risk_level=result.risk_level.value,
        risk_score=result.risk_score,
        recommended_action=result.recommended_action,
    )

    return result


@app.post("/analyze/full", response_model=AnalysisResult, status_code=200)
async def analyze_file_full(
    file: UploadFile = File(...),
    redis: aioredis.Redis = Depends(get_redis),
):
    """
    Full analysis: hash triage → static → sandbox (if needed).
    Slower than /analyze but provides most complete results.
    """
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    data = await file.read()

    if len(data) == 0:
        raise HTTPException(400, "File trống")
    if len(data) > max_bytes:
        raise HTTPException(413, f"File vượt quá giới hạn {settings.max_upload_size_mb}MB")

    filename = file.filename or "unknown"
    analysis_id = str(uuid.uuid4())

    log.info(" [Full] Nhận file", filename=filename, size=len(data), id=analysis_id)

    # Stage 1: Hash Triage
    hash_result = await run_hash_triage(data, redis)

    # Stage 2: Static Analysis
    static_result = run_static_analysis(data, filename)

    result = AnalysisResult(
        analysis_id=analysis_id,
        filename=filename,
        file_type=static_result.file_type,
        hash_triage=hash_result,
        static_analysis=static_result,
    )
    
    # Stage 3: XGBoost Prediction
    log.info(" [Full] Bắt đầu XGBoost prediction", id=analysis_id)
    xgb_result = predict_risk(result)
    if xgb_result.get("available"):
        log.info(
            f"[XGBoost] Prediction: {xgb_result['risk_level']} "
            f"(confidence={xgb_result['confidence']:.2f})",
            id=analysis_id
        )
        result._xgboost_result = xgb_result  # type: ignore
        result.xgboost = XGBoostResult(
            available=xgb_result.get("available", False),
            risk_level=xgb_result.get("risk_level", "unknown"),
            confidence=xgb_result.get("confidence", 0.0),
            probabilities=xgb_result.get("probabilities", {}),
            top_features=xgb_result.get("top_features", []),
        )
    else:
        log.info("[XGBoost] Model không khả dụng", id=analysis_id)
        result.xgboost = XGBoostResult(available=False)

    result.compute_risk()
    
    # Stage 2B: Decide if sandbox needed
    # ALWAYS run sandbox for HIGH/CRITICAL, regardless of confidence
    needs_office_sandbox = (
        static_result.file_type == FileType.OFFICE
        and static_result.ole
        and static_result.ole.has_macros
        and (len(static_result.ole.suspicious_keywords) > 0 or static_result.ole.has_doevents)
    )
    needs_pdf_sandbox = (
        static_result.file_type == FileType.PDF
        and static_result.pdf
        and static_result.pdf.has_javascript
        and static_result.pdf.has_open_action
    )
    
    result.needs_sandbox = (
        (static_result.file_type in (FileType.PE, FileType.SCRIPT) and result.risk_score >= 0.15)
        or needs_pdf_sandbox
        or needs_office_sandbox
        or result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    )

    # Stage 3: Dynamic Sandbox (nếu cần)
    if result.needs_sandbox:
        log.info(" [Bắt đầu sandbox", id=analysis_id)
        sandbox_result = await run_sandbox(data, filename, static_result.file_type)
        result.sandbox = sandbox_result
        result.compute_risk()
        log.info(" Sandbox hoàn thành", id=analysis_id,
                 executed=sandbox_result.executed,
                 c2=len(sandbox_result.c2_indicators))

    _result_store[analysis_id] = result

    log.info(" [Full] Hoàn thành", id=analysis_id,
             risk_level=result.risk_level.value,
             risk_score=result.risk_score)

    return result


@app.get("/result/{analysis_id}", response_model=AnalysisResult)
async def get_result(analysis_id: str):
    """Lấy kết quả phân tích theo ID."""
    result = _result_store.get(analysis_id)
    if not result:
        raise HTTPException(404, f"Không tìm thấy analysis_id: {analysis_id}")
    return result


@app.get("/results", response_model=list[dict])
async def list_results(limit: int = 20):
    """Liệt kê kết quả phân tích gần nhất."""
    results = list(_result_store.values())[-limit:]
    return [
        {
            "analysis_id": r.analysis_id,
            "filename": r.filename,
            "risk_level": r.risk_level.value,
            "risk_score": r.risk_score,
            "recommended_action": r.recommended_action,
            "timestamp": r.timestamp.isoformat(),
        }
        for r in reversed(results)
    ]


# ─────────────────────────────────────────────
# Sandbox on-demand
# ─────────────────────────────────────────────

@app.post("/sandbox/{analysis_id}")
async def trigger_sandbox(analysis_id: str):
    """
    Kích hoạt sandbox cho kết quả phân tích đã có.
    Hữu ích khi /analyze trả về needs_sandbox=true.
    """
    result = _result_store.get(analysis_id)
    if not result:
        raise HTTPException(404, f"Không tìm thấy: {analysis_id}")

    if result.sandbox and result.sandbox.executed:
        return {"message": "Sandbox đã chạy", "sandbox": result.sandbox}

    # Cần đọc lại bytes — trong demo lưu trữ tạm trong result store
    # Production: lưu bytes vào object storage (S3/MinIO)
    raise HTTPException(
        501,
        "Sandbox on-demand cần object storage. Dùng POST /analyze/full để chạy toàn pipeline."
    )


# ─────────────────────────────────────────────
# Post-delivery Clawback
# ─────────────────────────────────────────────

@app.post("/clawback/{analysis_id}")
async def clawback_endpoint(
    analysis_id: str,
    message_id:      Optional[str] = Form(default=None),
    recipient_email: Optional[str] = Form(default=None),
    sender_email:    Optional[str] = Form(default=None),
):
    """
    Thực hiện post-delivery clawback cho email chứa tệp độc hại.

    Tự động quarantine email / xóa attachment / alert người nhận
    nếu risk level là HIGH hoặc CRITICAL.
    """
    result = _result_store.get(analysis_id)
    if not result:
        raise HTTPException(404, f"Không tìm thấy: {analysis_id}")

    log.info(" Clawback triggered",
             id=analysis_id, risk=result.risk_level.value)

    clawback_result = execute_clawback(
        result=result,
        message_id=message_id,
        recipient_email=recipient_email,
        sender_email=sender_email,
    )

    return {
        "analysis_id":   analysis_id,
        "filename":      result.filename,
        "risk_level":    result.risk_level.value,
        "clawback":      clawback_result.to_dict(),
    }


@app.get("/clawback/log")
async def clawback_log():
    """Lấy audit log của tất cả các lần clawback."""
    return {
        "log":   get_quarantine_log(),
        "count": len(get_quarantine_log()),
    }