"""
SecureMail Orchestrator — FastAPI Application.
Điểm vào chính cho dịch vụ điều phối pipeline phân tích email.
"""
from fastapi import FastAPI, HTTPException
from contextlib import asynccontextmanager
import time
import logging

from config import get_settings
from models import EmailScanRequest, ScanResult
from pipeline import ReActPipeline
from redis_bus import RedisBus
from database import Database
from audit_logger import AuditLogger

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Quản lý vòng đời ứng dụng: kết nối Redis, PostgreSQL khi khởi động."""
    # Startup
    logger.info("Orchestrator đang khởi động...")
    try:
        app.state.redis_bus = RedisBus(
            redis_url=settings.REDIS_URL,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
        )
        await app.state.redis_bus.connect()
        logger.info("Đã kết nối Redis")
    except Exception as e:
        logger.warning(f"Không thể kết nối Redis: {e} — tiếp tục với HTTP fallback")
        app.state.redis_bus = None

    try:
        app.state.database = Database(settings.POSTGRES_URL)
        await app.state.database.connect()
        app.state.audit_logger = AuditLogger(app.state.database)
        logger.info("Đã kết nối PostgreSQL")
    except Exception as e:
        logger.warning(f"Không thể kết nối PostgreSQL: {e} — audit logging tắt")
        app.state.database = None
        app.state.audit_logger = None

    app.state.pipeline = ReActPipeline(
        settings=settings,
        redis_bus=app.state.redis_bus,
        audit_logger=getattr(app.state, "audit_logger", None),
    )
    logger.info("Orchestrator sẵn sàng")

    yield

    # Shutdown
    logger.info("Orchestrator đang tắt...")
    if app.state.redis_bus:
        await app.state.redis_bus.close()
    if getattr(app.state, "database", None):
        await app.state.database.disconnect()
    logger.info("Orchestrator đã tắt")


app = FastAPI(
    title="SecureMail Orchestrator",
    description="Dịch vụ điều phối pipeline phân tích bảo mật email",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health_check():
    """Endpoint kiểm tra sức khỏe của Orchestrator."""
    return {"status": "ok", "service": "orchestrator"}


@app.post("/api/v1/scan", response_model=ScanResult)
async def scan_email(request: EmailScanRequest):
    """
    Quét email qua pipeline ReAct.
    Nhận email → suy luận → gọi agents → tính điểm → trả kết quả.
    """
    start_time = time.time()
    try:
        result = await app.state.pipeline.run(request)
        result.processing_time_ms = (time.time() - start_time) * 1000
        return result
    except Exception as e:
        logger.error(f"Lỗi pipeline cho email {request.email_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")
