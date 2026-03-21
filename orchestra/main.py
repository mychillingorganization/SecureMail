"""
SecureMail Orchestrator — FastAPI Application.
Điểm vào chính cho dịch vụ điều phối pipeline phân tích email.
Implements PRD improve_plan.md endpoints.
"""

import logging
import time
from contextlib import asynccontextmanager

from audit_logger import AuditLogger
from blacklist_service import BlacklistService
from config import get_settings
from database import Database
from fastapi import FastAPI, HTTPException
from models import EmailScanRequest, ScanResult
from pipeline import ReActPipeline
from pydantic import BaseModel
from redis_bus import RedisBus

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Quản lý vòng đời ứng dụng: kết nối Redis, PostgreSQL khi khởi động."""
    # Startup
    logger.info("Orchestrator starting...")
    try:
        app.state.redis_bus = RedisBus(
            redis_url=settings.REDIS_URL,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
        )
        await app.state.redis_bus.connect()
        logger.info("Redis connected")
    except Exception as e:
        logger.warning(f"Cannot connect Redis: {e} — continuing with HTTP fallback")
        app.state.redis_bus = None

    try:
        app.state.database = Database(settings.POSTGRES_URL)
        await app.state.database.connect()
        app.state.audit_logger = AuditLogger(app.state.database)
        app.state.blacklist_service = BlacklistService(app.state.database)
        logger.info("PostgreSQL connected")
    except Exception as e:
        logger.warning(f"Cannot connect PostgreSQL: {e} — audit logging disabled")
        app.state.database = None
        app.state.audit_logger = None
        app.state.blacklist_service = None

    app.state.pipeline = ReActPipeline(
        settings=settings,
        redis_bus=app.state.redis_bus,
        audit_logger=getattr(app.state, "audit_logger", None),
        blacklist_service=getattr(app.state, "blacklist_service", None),
    )
    logger.info("Orchestrator ready")

    yield

    # Shutdown
    logger.info("Orchestrator shutting down...")
    if app.state.redis_bus:
        await app.state.redis_bus.close()
    if getattr(app.state, "database", None):
        await app.state.database.disconnect()
    logger.info("Orchestrator stopped")


app = FastAPI(
    title="SecureMail Orchestrator",
    description="Email Security Orchestrator — 8-step pipeline per PRD improve_plan.md",
    version="2.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "orchestrator", "version": "2.0.0"}


@app.post("/api/v1/scan", response_model=ScanResult)
async def scan_email(request: EmailScanRequest):
    """
    Quét email qua pipeline 8 bước.
    Returns ScanResult theo PRD output specification:
    {final_status, issue_count, termination_reason, execution_logs}
    """
    start_time = time.time()
    try:
        result = await app.state.pipeline.run(request)
        result.processing_time_ms = (time.time() - start_time) * 1000
        return result
    except Exception as e:
        logger.error(f"Pipeline error for email {request.email_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Pipeline error: {str(e)}",
        ) from e


class ConfirmDangerRequest(BaseModel):
    """Request body for confirming a DANGER verdict."""
    email_id: str
    file_hashes: list[str] | None = None
    urls: list[str] | None = None
    domains: list[str] | None = None


@app.post("/api/v1/confirm-danger")
async def confirm_danger(request: ConfirmDangerRequest):
    """
    Step 8: User confirms email is dangerous.
    Persist file hashes and URLs to blacklist tables.
    """
    blacklist_service = getattr(app.state, "blacklist_service", None)
    if not blacklist_service:
        raise HTTPException(
            status_code=503,
            detail="Database not available for blacklist persistence",
        )

    try:
        await blacklist_service.persist_danger_indicators(
            file_hashes=request.file_hashes,
            urls=request.urls,
            domains=request.domains,
        )
        return {
            "status": "ok",
            "message": f"Danger indicators persisted for email {request.email_id}",
            "persisted": {
                "file_hashes": len(request.file_hashes or []),
                "urls": len(request.urls or []),
                "domains": len(request.domains or []),
            },
        }
    except Exception as e:
        logger.error(f"Blacklist persistence error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Blacklist persistence error: {str(e)}",
        ) from e


@app.get("/api/v1/trace/{email_id}")
async def get_trace(email_id: str):
    """
    Get full audit trail for an email.
    Returns orchestrator trace + per-agent traces + email info.
    """
    audit_logger = getattr(app.state, "audit_logger", None)
    if not audit_logger:
        raise HTTPException(
            status_code=503,
            detail="Database not available for trace retrieval",
        )

    trace = await audit_logger.get_full_trace(email_id)
    if not trace:
        raise HTTPException(
            status_code=404,
            detail=f"No trace found for email_id={email_id}",
        )
    return trace
