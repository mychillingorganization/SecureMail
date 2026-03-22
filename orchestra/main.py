import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession

from email_agent.protocol_verifier import ProtocolVerifier
from orchestra.clients import AgentClient
from orchestra.config import get_settings
from orchestra.database import engine, get_db_session
from orchestra.models import Base
from orchestra.pipeline import PipelineDependencies, execute_pipeline
from orchestra.pipeline_deepdive import execute_pipeline_deepdive
from orchestra.schemas import ScanRequest, ScanResponse
from orchestra.threat_intel import ThreatIntelScanner


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Keep startup deterministic in local environments.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(title="SecureMail Orchestrator", version="1.0.0", lifespan=lifespan)

QUICK_CHECK_HTML_PATH = Path(__file__).with_name("quick_check.html")
QUICK_CHECK_HTML = QUICK_CHECK_HTML_PATH.read_text(encoding="utf-8")


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


@app.post("/api/v1/scan-upload", response_model=ScanResponse)
async def scan_uploaded_email(
    file: UploadFile = File(...),
    user_accepts_danger: bool = False,
    session: AsyncSession = Depends(get_db_session),
) -> ScanResponse:
    filename = file.filename or "uploaded.eml"
    if Path(filename).suffix.lower() != ".eml":
        raise HTTPException(status_code=422, detail="Only .eml files are supported")

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

    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp_file:
        temp_path = tmp_file.name
        tmp_file.write(await file.read())

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


@app.get("/quick-check", response_class=HTMLResponse)
async def quick_check_page() -> HTMLResponse:
    return HTMLResponse(content=QUICK_CHECK_HTML)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("orchestra.main:app", host="0.0.0.0", port=8080, reload=False)
