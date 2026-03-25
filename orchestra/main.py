import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from email_agent.protocol_verifier import ProtocolVerifier
from orchestra.clients import AgentClient
from orchestra.config import get_settings
from orchestra.database import engine, get_db_session
from orchestra.models import Base, ScanHistory
from orchestra.pipeline import PipelineDependencies, execute_pipeline
from orchestra.pipeline_deepdive import execute_pipeline_deepdive
from orchestra.schemas import ScanRequest, ScanResponse, ScanHistoryCreate, ScanHistoryResponse
from orchestra.threat_intel import ThreatIntelScanner


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Keep startup deterministic in local environments.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(title="SecureMail Orchestrator", version="1.0.0", lifespan=lifespan)

settings = get_settings()
origins = [item.strip() for item in settings.cors_allow_origins.split(",") if item.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

QUICK_CHECK_HTML_PATH = Path(__file__).with_name("quick_check.html")
QUICK_CHECK_HTML = QUICK_CHECK_HTML_PATH.read_text(encoding="utf-8")


async def _save_uploaded_eml_to_temp(file: UploadFile) -> tuple[str, str]:
    filename = file.filename or "uploaded.eml"
    if Path(filename).suffix.lower() != ".eml":
        raise HTTPException(status_code=422, detail="Only .eml files are supported")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp_file:
        temp_path = tmp_file.name
        tmp_file.write(await file.read())

    return filename, temp_path


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "orchestrator"}


@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_email(request: ScanRequest, session: AsyncSession = Depends(get_db_session)) -> ScanResponse:
    settings = get_settings()
    threat_hashes = {item.strip() for item in settings.threat_intel_malicious_hashes.split(",") if item.strip()}

    deps = PipelineDependencies(
        settings=settings,
        email_client=AgentClient(settings.email_agent_url, settings.request_timeout_seconds),
        file_client=AgentClient(settings.file_agent_url, settings.request_timeout_seconds),
        web_client=AgentClient(settings.web_agent_url, settings.request_timeout_seconds),
        threat_scanner=ThreatIntelScanner(threat_hashes),
        protocol_verifier=ProtocolVerifier(),
    )

    try:
        return await execute_pipeline(
            email_path=request.email_path,
            session=session,
            deps=deps,
            user_accepts_danger=request.user_accepts_danger,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/scan-llm", response_model=ScanResponse)
async def scan_email_llm(request: ScanRequest, session: AsyncSession = Depends(get_db_session)) -> ScanResponse:
    """LLM-based orchestrator: Deep-dive analysis with detailed threat reasoning."""
    settings = get_settings()

    try:
        return await execute_pipeline_deepdive(
            email_path=request.email_path,
            session=session,
            settings=settings,
            user_accepts_danger=request.user_accepts_danger,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/v1/scan-google-aistudio", response_model=ScanResponse)
async def scan_email_google_aistudio(request: ScanRequest, session: AsyncSession = Depends(get_db_session)) -> ScanResponse:
    """Alias for LLM endpoint (deprecated, use /api/v1/scan-llm instead)."""
    return await scan_email_llm(request, session)


@app.post("/api/v1/test-upload")
async def test_upload(
    file: UploadFile = File(...),
):
    """Simple test endpoint to verify FormData upload works."""
    try:
        # Read all content to check file is received
        content = await file.read()
        
        return {
            "status": "ok",
            "filename": file.filename,
            "content_type": file.content_type,
            "size_bytes": len(content),
            "message": "Test upload successful!"
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "type": type(e).__name__,
        }


@app.post("/api/v1/scan-upload", response_model=ScanResponse)
async def scan_uploaded_email(
    file: UploadFile = File(...),
    user_accepts_danger: bool = False,
    session: AsyncSession = Depends(get_db_session),
) -> ScanResponse:
    _, temp_path = await _save_uploaded_eml_to_temp(file)

    settings = get_settings()
    threat_hashes = {item.strip() for item in settings.threat_intel_malicious_hashes.split(",") if item.strip()}
    deps = PipelineDependencies(
        settings=settings,
        email_client=AgentClient(settings.email_agent_url, settings.request_timeout_seconds),
        file_client=AgentClient(settings.file_agent_url, settings.request_timeout_seconds),
        web_client=AgentClient(settings.web_agent_url, settings.request_timeout_seconds),
        threat_scanner=ThreatIntelScanner(threat_hashes),
        protocol_verifier=ProtocolVerifier(),
    )

    try:
        return await execute_pipeline(
            email_path=temp_path,
            session=session,
            deps=deps,
            user_accepts_danger=user_accepts_danger,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


@app.post("/api/v1/scan-upload-llm", response_model=ScanResponse)
async def scan_uploaded_email_llm(
    file: UploadFile = File(...),
    user_accepts_danger: bool = False,
    session: AsyncSession = Depends(get_db_session),
) -> ScanResponse:
    _, temp_path = await _save_uploaded_eml_to_temp(file)
    settings = get_settings()

    try:
        return await execute_pipeline_deepdive(
            email_path=temp_path,
            session=session,
            settings=settings,
            user_accepts_danger=user_accepts_danger,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


@app.get("/quick-check", response_class=HTMLResponse)
async def quick_check_page() -> HTMLResponse:
    return HTMLResponse(content=QUICK_CHECK_HTML)


@app.post("/api/v1/scan-history", response_model=ScanHistoryResponse)
async def save_scan_history(
    data: ScanHistoryCreate,
    session: AsyncSession = Depends(get_db_session),
) -> ScanHistoryResponse:
    """Save a scan result to the database for history tracking."""
    try:
        scan_history = ScanHistory(
            scan_mode=data.scan_mode,
            file_name=data.file_name,
            final_status=data.final_status,
            issue_count=data.issue_count,
            duration_ms=data.duration_ms,
            termination_reason=data.termination_reason,
            ai_classify=data.ai_classify,
            ai_reason=data.ai_reason,
            ai_summary=data.ai_summary,
            ai_provider=data.ai_provider,
            ai_confidence_percent=data.ai_confidence_percent,
            execution_logs=data.execution_logs,
            ai_cot_steps=data.ai_cot_steps,
        )
        session.add(scan_history)
        await session.commit()
        await session.refresh(scan_history)

        return ScanHistoryResponse(
            id=scan_history.id,
            timestamp=scan_history.timestamp.isoformat(),
            scan_mode=scan_history.scan_mode,
            file_name=scan_history.file_name,
            final_status=scan_history.final_status,
            issue_count=scan_history.issue_count,
            duration_ms=scan_history.duration_ms,
            termination_reason=scan_history.termination_reason,
            ai_classify=scan_history.ai_classify,
            ai_reason=scan_history.ai_reason,
            ai_summary=scan_history.ai_summary,
            ai_provider=scan_history.ai_provider,
            ai_confidence_percent=scan_history.ai_confidence_percent,
            execution_logs=scan_history.execution_logs,
            ai_cot_steps=scan_history.ai_cot_steps,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save scan history: {str(exc)}") from exc


@app.get("/api/v1/scan-history", response_model=list[ScanHistoryResponse])
async def get_scan_history(
    limit: int = Query(50, ge=1, le=500),
    scan_mode: str | None = Query(None),
    session: AsyncSession = Depends(get_db_session),
) -> list[ScanHistoryResponse]:
    """Retrieve scan history from the database, ordered by most recent first."""
    try:
        query = select(ScanHistory)

        if scan_mode:
            query = query.where(ScanHistory.scan_mode == scan_mode)

        query = query.order_by(desc(ScanHistory.timestamp)).limit(limit)

        result = await session.execute(query)
        scan_histories = result.scalars().all()

        return [
            ScanHistoryResponse(
                id=sh.id,
                timestamp=sh.timestamp.isoformat(),
                scan_mode=sh.scan_mode,
                file_name=sh.file_name,
                final_status=sh.final_status,
                issue_count=sh.issue_count,
                duration_ms=sh.duration_ms,
                termination_reason=sh.termination_reason,
                ai_classify=sh.ai_classify,
                ai_reason=sh.ai_reason,
                ai_summary=sh.ai_summary,
                ai_provider=sh.ai_provider,
                ai_confidence_percent=sh.ai_confidence_percent,
                execution_logs=sh.execution_logs,
                ai_cot_steps=sh.ai_cot_steps,
            )
            for sh in scan_histories
        ]
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve scan history: {str(exc)}") from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("orchestra.main:app", host="0.0.0.0", port=8080, reload=False)
