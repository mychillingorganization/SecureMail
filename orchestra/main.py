import os
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import json
import hashlib
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import httpx
from sqlalchemy import Text, cast, delete, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from email_agent.protocol_verifier import ProtocolVerifier
from orchestra.chat_tools import detect_chat_intent as detect_chat_intent_helper, run_tool, summarize_tool_result
from orchestra.clients import AgentClient
from orchestra.config import get_settings
from orchestra.database import engine, get_db_session
from orchestra.models import Base, ChatConversation, ChatMessage, ChatRole, EntityStatus, File as FileEntity, ScanHistory
from orchestra.pipeline import PipelineDependencies, execute_pipeline
from orchestra.pipeline_deepdive import execute_pipeline_deepdive
from orchestra.schemas import (
    ChatConversationResponse,
    ChatIntentRequest,
    ChatIntentResponse,
    ChatMessageResponse,
    ChatMessagesResponse,
    ChatSendRequest,
    ChatSendResponse,
    ScanHistoryCreate,
    ScanHistoryPaginatedResponse,
    ScanHistoryResponse,
    ScanRequest,
    ScanResponse,
)
from orchestra.threat_intel import ThreatIntelScanner


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Keep startup deterministic in local environments.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


app = FastAPI(title="SecureMail Orchestrator", version="1.0.0", lifespan=lifespan)

settings = get_settings()
# Handle wildcard origin specially
if settings.cors_allow_origins == "*":
    origins = ["*"]
    allow_credentials = False  # Wildcard origins cannot use credentials
else:
    origins = [item.strip() for item in settings.cors_allow_origins.split(",") if item.strip()]
    allow_credentials = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

QUICK_CHECK_HTML_PATH = Path(__file__).with_name("quick_check.html")
QUICK_CHECK_HTML = QUICK_CHECK_HTML_PATH.read_text(encoding="utf-8")


async def _generate_general_chat_response(
    settings_obj,
    user_message: str,
    history_messages: list[str],
) -> str:
    """Generate a helpful conversational response for non-tool chat prompts."""
    api_key = settings_obj.google_ai_studio_api_key
    if not api_key:
        raise RuntimeError("Google AI Studio API key is not configured")

    base_url = settings_obj.google_ai_studio_base_url.rstrip("/")
    model = settings_obj.google_ai_studio_model
    url = f"{base_url}/models/{model}:generateContent?key={api_key}"

    prompt = (
        "You are SecureMail Assistant. Help the user with practical cybersecurity guidance. "
        "If asked about data summary, suggest using KPI/risk summary requests. "
        "If asked about scanning, remind them .eml upload is in /scanner. "
        "Be concise and actionable.\n\n"
        f"Recent conversation:\n{chr(10).join(history_messages) if history_messages else 'No previous messages.'}\n\n"
        f"User message: {user_message}\n"
    )

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.3,
            "maxOutputTokens": 600,
            "topP": 0.9,
        },
    }

    async with httpx.AsyncClient(timeout=settings_obj.ai_agent_timeout_seconds) as client:
        response = await client.post(url, json=payload)
        response.raise_for_status()
        body = response.json()

    candidates = body.get("candidates", []) if isinstance(body, dict) else []
    if not candidates:
        raise RuntimeError("No response candidates from model")

    parts = candidates[0].get("content", {}).get("parts", [])
    text_chunks = [str(part.get("text", "")).strip() for part in parts if isinstance(part, dict)]
    text = "\n".join([chunk for chunk in text_chunks if chunk]).strip()
    if not text:
        raise RuntimeError("Model returned empty text")
    return text


def _to_chat_conversation_response(conversation: ChatConversation) -> ChatConversationResponse:
    return ChatConversationResponse(
        id=conversation.id,
        title=conversation.title,
        created_at=conversation.created_at.isoformat(),
        updated_at=conversation.updated_at.isoformat(),
        last_message_at=conversation.last_message_at.isoformat(),
    )


def _to_chat_message_response(message: ChatMessage) -> ChatMessageResponse:
    return ChatMessageResponse(
        id=message.id,
        conversation_id=message.conversation_id,
        role=message.role.value if hasattr(message.role, "value") else str(message.role),
        content=message.content,
        status=message.status,
        tool_name=message.tool_name,
        tool_payload=message.tool_payload,
        created_at=message.created_at.isoformat(),
    )


def _title_from_message(message: str) -> str:
    clean = " ".join(message.strip().split())
    if not clean:
        return "New Chat"
    return clean[:57] + "..." if len(clean) > 60 else clean


async def _apply_chat_retention(session: AsyncSession, days: int = 30) -> None:
    cutoff = datetime.utcnow() - timedelta(days=days)
    await session.execute(delete(ChatMessage).where(ChatMessage.created_at < cutoff))
    empty_conversations_stmt = select(ChatConversation).where(
        ~ChatConversation.messages.any(),
        ChatConversation.updated_at < cutoff,
    )
    empty_conversations = (await session.execute(empty_conversations_stmt)).scalars().all()
    for conversation in empty_conversations:
        await session.delete(conversation)


async def _save_uploaded_eml_to_temp(file: UploadFile) -> tuple[str, str]:
    filename = file.filename or "uploaded.eml"
    if Path(filename).suffix.lower() != ".eml":
        raise HTTPException(status_code=422, detail="Only .eml files are supported")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp_file:
        temp_path = tmp_file.name
        tmp_file.write(await file.read())

    return filename, temp_path


async def _save_uploaded_file_to_temp(file: UploadFile) -> tuple[str, str]:
    filename = file.filename or "uploaded.bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(filename).suffix or ".bin") as tmp_file:
        temp_path = tmp_file.name
        tmp_file.write(await file.read())
    return filename, temp_path


def _hash_file_path(file_path: str) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _build_pipeline_dependencies(settings_obj) -> PipelineDependencies:
    threat_hashes = {item.strip() for item in settings_obj.threat_intel_malicious_hashes.split(",") if item.strip()}
    return PipelineDependencies(
        settings=settings_obj,
        email_client=AgentClient(settings_obj.email_agent_url, settings_obj.request_timeout_seconds),
        file_client=AgentClient(settings_obj.file_agent_url, settings_obj.request_timeout_seconds),
        web_client=AgentClient(settings_obj.web_agent_url, settings_obj.request_timeout_seconds),
        threat_scanner=ThreatIntelScanner(threat_hashes),
        protocol_verifier=ProtocolVerifier(),
    )


def _truncate_text(value: str, max_len: int) -> str:
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."


def _compact_json_preview(value: object, max_len: int = 320) -> str | None:
    if value is None:
        return None
    try:
        text = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    except TypeError:
        text = str(value)
    clean = " ".join(text.split())
    return _truncate_text(clean, max_len)


def _sanitize_tool_trace(tool_trace: object) -> list[dict[str, object]]:
    if not isinstance(tool_trace, list):
        return []

    sanitized: list[dict[str, object]] = []
    for idx, item in enumerate(tool_trace[:15]):
        if not isinstance(item, dict):
            continue

        step_raw = item.get("step")
        step = step_raw if isinstance(step_raw, int) else idx + 1
        tool_name = str(item.get("tool_name", "unknown"))
        args_preview = _compact_json_preview(item.get("tool_args"), max_len=260)
        result_preview = _compact_json_preview(item.get("tool_result"), max_len=360)
        review_status = item.get("review_status")

        sanitized_step: dict[str, object] = {
            "step": step,
            "tool_name": tool_name,
        }
        if args_preview:
            sanitized_step["tool_args_preview"] = args_preview
        if result_preview:
            sanitized_step["tool_result_preview"] = result_preview
        if isinstance(review_status, str) and review_status.strip():
            sanitized_step["review_status"] = review_status.strip()

        sanitized.append(sanitized_step)

    return sanitized


def _normalize_contact_field(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None

    addresses = [addr.strip().lower() for _, addr in getaddresses([text]) if addr and "@" in addr]
    if addresses:
        seen: set[str] = set()
        deduped: list[str] = []
        for addr in addresses:
            if addr not in seen:
                seen.add(addr)
                deduped.append(addr)
        return ", ".join(deduped)

    # Fallback for malformed values: compact whitespace to avoid garbage formatting.
    compact = " ".join(text.replace("\n", " ").replace("\r", " ").split())
    return compact or None


def _extract_sender_receiver_from_eml(eml_path: str) -> tuple[str | None, str | None]:
    with open(eml_path, "rb") as handle:
        msg = BytesParser(policy=policy.default).parse(handle)

    sender = _normalize_contact_field(msg.get("From"))

    to_values = msg.get_all("To", [])
    receiver_raw = ", ".join(v for v in to_values if v)
    receiver = _normalize_contact_field(receiver_raw)

    return sender, receiver


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "orchestrator"}


@app.post("/api/v1/scan", response_model=ScanResponse)
async def scan_email(request: ScanRequest, session: AsyncSession = Depends(get_db_session)) -> ScanResponse:
    settings = get_settings()
    deps = _build_pipeline_dependencies(settings)

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
    deps = _build_pipeline_dependencies(settings)

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
            sender=_normalize_contact_field(data.sender),
            receiver=_normalize_contact_field(data.receiver),
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
            sender=scan_history.sender,
            receiver=scan_history.receiver,
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


@app.get("/api/v1/scan-history", response_model=ScanHistoryPaginatedResponse)
async def get_scan_history(
    limit: int = Query(10, ge=1, le=100),
    skip: int = Query(0, ge=0),
    scan_mode: str | None = Query(None),
    search: str | None = Query(None),
    session: AsyncSession = Depends(get_db_session),
) -> ScanHistoryPaginatedResponse:
    """Retrieve scan history from the database, ordered by most recent first."""
    try:
        query = select(ScanHistory)
        count_query = select(func.count(ScanHistory.id))

        if scan_mode:
            query = query.where(ScanHistory.scan_mode == scan_mode)
            count_query = count_query.where(ScanHistory.scan_mode == scan_mode)

        if search:
            pattern = f"%{search.strip()}%"
            search_filter = or_(
                ScanHistory.file_name.ilike(pattern),
                ScanHistory.sender.ilike(pattern),
                ScanHistory.receiver.ilike(pattern),
                ScanHistory.ai_summary.ilike(pattern),
                ScanHistory.ai_reason.ilike(pattern),
                cast(ScanHistory.execution_logs, Text).ilike(pattern),
            )
            query = query.where(search_filter)
            count_query = count_query.where(search_filter)

        query = query.order_by(desc(ScanHistory.timestamp)).offset(skip).limit(limit)

        result = await session.execute(query)
        scan_histories = result.scalars().all()
        total_result = await session.execute(count_query)
        total = total_result.scalar() or 0

        passed_query = select(func.count(ScanHistory.id))
        issues_query = select(func.coalesce(func.sum(ScanHistory.issue_count), 0))
        danger_query = select(func.count(ScanHistory.id)).where(ScanHistory.final_status != "PASS")

        if scan_mode:
            passed_query = passed_query.where(ScanHistory.scan_mode == scan_mode)
            issues_query = issues_query.where(ScanHistory.scan_mode == scan_mode)
            danger_query = danger_query.where(ScanHistory.scan_mode == scan_mode)

        if search:
            pattern = f"%{search.strip()}%"
            agg_search_filter = or_(
                ScanHistory.file_name.ilike(pattern),
                ScanHistory.sender.ilike(pattern),
                ScanHistory.receiver.ilike(pattern),
                ScanHistory.ai_summary.ilike(pattern),
                ScanHistory.ai_reason.ilike(pattern),
                cast(ScanHistory.execution_logs, Text).ilike(pattern),
            )
            passed_query = passed_query.where(agg_search_filter)
            issues_query = issues_query.where(agg_search_filter)
            danger_query = danger_query.where(agg_search_filter)

        passed_result = await session.execute(passed_query.where(ScanHistory.final_status == "PASS"))
        issues_result = await session.execute(issues_query)
        danger_result = await session.execute(danger_query)

        passed_count = passed_result.scalar() or 0
        issues_count = int(issues_result.scalar() or 0)
        danger_count = danger_result.scalar() or 0

        return ScanHistoryPaginatedResponse(
            total=total,
            skip=skip,
            limit=limit,
            passed_count=passed_count,
            issues_count=issues_count,
            danger_count=danger_count,
            items=[
                ScanHistoryResponse(
                    id=sh.id,
                    timestamp=sh.timestamp.isoformat(),
                    scan_mode=sh.scan_mode,
                    file_name=sh.file_name,
                    sender=sh.sender,
                    receiver=sh.receiver,
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
            ],
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve scan history: {str(exc)}") from exc


@app.get("/api/v1/chat/conversations", response_model=list[ChatConversationResponse])
async def list_chat_conversations(
    limit: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_db_session),
) -> list[ChatConversationResponse]:
    await _apply_chat_retention(session, days=30)
    await session.commit()

    stmt = select(ChatConversation).order_by(desc(ChatConversation.last_message_at)).limit(limit)
    conversations = (await session.execute(stmt)).scalars().all()
    return [_to_chat_conversation_response(conv) for conv in conversations]


@app.post("/api/v1/chat/conversations", response_model=ChatConversationResponse)
async def create_chat_conversation(
    session: AsyncSession = Depends(get_db_session),
) -> ChatConversationResponse:
    await _apply_chat_retention(session, days=30)

    conversation = ChatConversation(title="New Chat")
    session.add(conversation)
    await session.commit()
    await session.refresh(conversation)

    return _to_chat_conversation_response(conversation)


@app.post("/api/v1/chat/intent", response_model=ChatIntentResponse)
async def detect_chat_intent_endpoint(request: ChatIntentRequest) -> ChatIntentResponse:
    intent = detect_chat_intent_helper(
        request.message,
        has_pending_attachment=request.has_pending_attachment,
    )

    return ChatIntentResponse(
        detected_tool=intent.get("detected_tool"),
        should_trigger_attachment_scan=bool(intent.get("should_trigger_attachment_scan", False)),
        reason=str(intent.get("reason", "No intent detected")),
    )


@app.delete("/api/v1/chat/conversations/{conversation_id}")
async def delete_chat_conversation(
    conversation_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, object]:
    conversation = await session.get(ChatConversation, conversation_id)
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")

    await session.delete(conversation)
    await session.commit()
    return {"deleted": True, "conversation_id": conversation_id}


@app.get("/api/v1/chat/messages", response_model=ChatMessagesResponse)
async def list_chat_messages(
    conversation_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_db_session),
) -> ChatMessagesResponse:
    conversation = await session.get(ChatConversation, conversation_id)
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")

    stmt = (
        select(ChatMessage)
        .where(ChatMessage.conversation_id == conversation_id)
        .order_by(ChatMessage.created_at.asc())
        .limit(limit)
        .offset(offset)
    )
    messages = (await session.execute(stmt)).scalars().all()

    return ChatMessagesResponse(
        conversation_id=conversation_id,
        messages=[_to_chat_message_response(msg) for msg in messages],
    )


@app.post("/api/v1/chat/send", response_model=ChatSendResponse)
async def send_chat_message(
    request: ChatSendRequest,
    session: AsyncSession = Depends(get_db_session),
) -> ChatSendResponse:
    message_text = request.message.strip()
    if not message_text:
        raise HTTPException(status_code=422, detail="Message cannot be empty")

    await _apply_chat_retention(session, days=30)

    conversation: ChatConversation | None = None
    if request.conversation_id:
        conversation = await session.get(ChatConversation, request.conversation_id)
        if not conversation:
            raise HTTPException(status_code=404, detail="Conversation not found")

    if conversation is None:
        conversation = ChatConversation(title=_title_from_message(message_text))
        session.add(conversation)
        await session.flush()

    user_message = ChatMessage(
        conversation_id=conversation.id,
        role=ChatRole.user,
        content=message_text,
        status="sent",
    )
    session.add(user_message)
    await session.flush()

    intent = detect_chat_intent_helper(message_text)
    tool_name = intent.get("detected_tool") if isinstance(intent.get("detected_tool"), str) else None
    tool_payload = None
    lower_message = message_text.lower()

    history_stmt = (
        select(ChatMessage)
        .where(ChatMessage.conversation_id == conversation.id)
        .order_by(ChatMessage.created_at.desc())
        .limit(10)
    )
    history_records = (await session.execute(history_stmt)).scalars().all()
    history_lines = [
        f"{(msg.role.value if hasattr(msg.role, 'value') else msg.role)}: {msg.content}"
        for msg in reversed(history_records)
    ]

    if "select " in lower_message or "drop table" in lower_message or "update " in lower_message:
        assistant_text = (
            "I can not execute raw SQL. Please ask for a summary like KPI trends, risky senders/domains, "
            "file risk, URL threat, or AI confidence."
        )
    elif tool_name:
        try:
            tool_payload = await run_tool(tool_name, session, message_text, settings)
            assistant_text = summarize_tool_result(tool_name, tool_payload)
        except Exception as exc:
            assistant_text = f"I could not complete that summary request: {str(exc)}"
            tool_name = None
            tool_payload = None
    elif any(token in lower_message for token in [".eml", "upload email", "check email", "scan email", "scan eml"]):
        assistant_text = (
            "Yes, you can upload an .eml file for scanning from the Check Email page (/scanner). "
            "Use Rule-Based or LLM Deep Dive mode, then I can help summarize the results here in chat."
        )
    else:
        try:
            assistant_text = await _generate_general_chat_response(settings, message_text, history_lines)
        except Exception:
            assistant_text = (
                "I can help with security guidance and summaries. "
                "Try asking for KPI summary, risky senders/domains, file risk, URL threat, or AI confidence trends."
            )

    assistant_message = ChatMessage(
        conversation_id=conversation.id,
        role=ChatRole.assistant,
        content=assistant_text,
        status="sent",
        tool_name=tool_name,
        tool_payload=tool_payload,
    )
    session.add(assistant_message)

    conversation.updated_at = datetime.utcnow()
    conversation.last_message_at = conversation.updated_at

    await session.commit()
    await session.refresh(conversation)
    await session.refresh(user_message)
    await session.refresh(assistant_message)

    return ChatSendResponse(
        conversation=_to_chat_conversation_response(conversation),
        user_message=_to_chat_message_response(user_message),
        assistant_message=_to_chat_message_response(assistant_message),
    )


@app.post("/api/v1/chat/upload-eml", response_model=ChatSendResponse)
async def upload_chat_eml(
    file: UploadFile = File(...),
    conversation_id: str | None = Form(None),
    scan_mode: str = Form("llm"),
    user_accepts_danger: bool = Form(False),
    trigger_message: str | None = Form(None),
    session: AsyncSession = Depends(get_db_session),
) -> ChatSendResponse:
    await _apply_chat_retention(session, days=30)

    mode = (scan_mode or "llm").strip().lower()
    if mode not in {"rule", "llm"}:
        raise HTTPException(status_code=422, detail="scan_mode must be 'rule' or 'llm'")

    conversation: ChatConversation | None = None
    if conversation_id:
        conversation = await session.get(ChatConversation, conversation_id)
        if not conversation:
            raise HTTPException(status_code=404, detail="Conversation not found")

    filename, temp_path = await _save_uploaded_eml_to_temp(file)
    settings_obj = get_settings()
    scan_result: ScanResponse
    sender: str | None = None
    receiver: str | None = None

    try:
        if mode == "rule":
            scan_result = await execute_pipeline(
                email_path=temp_path,
                session=session,
                deps=_build_pipeline_dependencies(settings_obj),
                user_accepts_danger=user_accepts_danger,
            )
        else:
            scan_result = await execute_pipeline_deepdive(
                email_path=temp_path,
                session=session,
                settings=settings_obj,
                user_accepts_danger=user_accepts_danger,
            )

        # Parse normalized sender/receiver directly from the uploaded EML.
        sender, receiver = _extract_sender_receiver_from_eml(temp_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    if conversation is None:
        conversation = ChatConversation(title=f"EML upload: {filename[:50]}")
        session.add(conversation)
        await session.flush()

    trigger_clean = (trigger_message or "").strip()
    user_text = trigger_clean if trigger_clean else f"Uploaded .eml file '{filename}' for {mode.upper()} scan"
    user_message = ChatMessage(
        conversation_id=conversation.id,
        role=ChatRole.user,
        content=user_text,
        status="sent",
    )
    session.add(user_message)
    await session.flush()

    trace_payload = {
        "scan_mode": mode,
        "file_name": filename,
        "sender": sender,
        "receiver": receiver,
        "final_status": scan_result.final_status,
        "issue_count": scan_result.issue_count,
        "termination_reason": scan_result.termination_reason,
        "ai_classify": scan_result.ai_classify,
        "ai_reason": scan_result.ai_reason,
        "ai_summary": scan_result.ai_summary,
        "ai_provider": scan_result.ai_provider,
        "ai_confidence_percent": scan_result.ai_confidence_percent,
        "execution_logs": scan_result.execution_logs,
        "ai_cot_steps": scan_result.ai_cot_steps,
        "tool_trace": _sanitize_tool_trace(scan_result.ai_tool_trace),
    }

    assistant_lines = [
        f"Scan completed for {filename} ({mode.upper()}).",
        f"Status: {scan_result.final_status}",
        f"Issues detected: {scan_result.issue_count}",
    ]
    if scan_result.ai_reason:
        assistant_lines.append(f"Reason: {scan_result.ai_reason}")
    if scan_result.ai_confidence_percent is not None:
        assistant_lines.append(f"Confidence: {scan_result.ai_confidence_percent}%")
    if scan_result.ai_cot_steps:
        assistant_lines.append(f"Reason trace steps: {len(scan_result.ai_cot_steps)}")
    elif scan_result.execution_logs:
        assistant_lines.append(f"Execution trace lines: {len(scan_result.execution_logs)}")

    assistant_message = ChatMessage(
        conversation_id=conversation.id,
        role=ChatRole.assistant,
        content="\n".join(assistant_lines),
        status="sent",
        tool_name=f"scan_upload_{mode}",
        tool_payload=trace_payload,
    )
    session.add(assistant_message)

    # Persist this upload result to scan history for dashboard continuity.
    session.add(
        ScanHistory(
            scan_mode=mode,
            file_name=filename,
            sender=sender,
            receiver=receiver,
            final_status=scan_result.final_status,
            issue_count=scan_result.issue_count,
            duration_ms=0,
            termination_reason=scan_result.termination_reason,
            ai_classify=scan_result.ai_classify,
            ai_reason=scan_result.ai_reason,
            ai_summary=scan_result.ai_summary,
            ai_provider=scan_result.ai_provider,
            ai_confidence_percent=scan_result.ai_confidence_percent,
            execution_logs=scan_result.execution_logs,
            ai_cot_steps=scan_result.ai_cot_steps,
        )
    )

    conversation.updated_at = datetime.utcnow()
    conversation.last_message_at = conversation.updated_at

    await session.commit()
    await session.refresh(conversation)
    await session.refresh(user_message)
    await session.refresh(assistant_message)

    return ChatSendResponse(
        conversation=_to_chat_conversation_response(conversation),
        user_message=_to_chat_message_response(user_message),
        assistant_message=_to_chat_message_response(assistant_message),
    )


@app.post("/api/v1/chat/upload-file", response_model=ChatSendResponse)
async def upload_chat_file(
    file: UploadFile = File(...),
    conversation_id: str | None = Form(None),
    analysis_mode: str = Form("quick"),
    trigger_message: str | None = Form(None),
    session: AsyncSession = Depends(get_db_session),
) -> ChatSendResponse:
    await _apply_chat_retention(session, days=30)

    mode = (analysis_mode or "quick").strip().lower()
    if mode not in {"quick", "full"}:
        raise HTTPException(status_code=422, detail="analysis_mode must be 'quick' or 'full'")

    conversation: ChatConversation | None = None
    if conversation_id:
        conversation = await session.get(ChatConversation, conversation_id)
        if not conversation:
            raise HTTPException(status_code=404, detail="Conversation not found")

    filename, temp_path = await _save_uploaded_file_to_temp(file)
    settings_obj = get_settings()

    file_hash: str | None = None
    file_blacklisted = False
    file_status = "unknown"
    file_scan_result: dict[str, object] | None = None
    ai_result: dict[str, object] | None = None

    try:
        file_hash = _hash_file_path(temp_path)
        db_file = await session.get(FileEntity, file_hash)
        if db_file is not None:
            file_status = db_file.status.value if hasattr(db_file.status, "value") else str(db_file.status)
            file_blacklisted = db_file.status == EntityStatus.malicious

        file_client = AgentClient(settings_obj.file_agent_url, settings_obj.request_timeout_seconds)
        ai_client = AgentClient(settings_obj.ai_agent_url, settings_obj.ai_agent_timeout_seconds)

        file_scan_result = await file_client.analyze_file(temp_path, full_analysis=(mode == "full"))
        risk_level = str(file_scan_result.get("risk_level", "unknown")).lower()
        if file_blacklisted:
            provisional_status = "DANGER"
            issue_count = 2
            termination_reason = "File hash is blacklisted"
        elif risk_level in {"high", "critical"}:
            provisional_status = "DANGER"
            issue_count = 2
            termination_reason = "File analysis indicates high/critical risk"
        elif risk_level == "medium":
            provisional_status = "WARNING"
            issue_count = 1
            termination_reason = "File analysis indicates medium risk"
        else:
            provisional_status = "PASS"
            issue_count = 0
            termination_reason = None

        ai_payload = {
            "subject": f"Uploaded file: {filename}",
            "sender": "chat-upload",
            "auth": {},
            "email_agent": {},
            "file_agent": [file_scan_result],
            "web_agent": {},
            "issue_count": issue_count,
            "provisional_final_status": provisional_status,
            "termination_reason": termination_reason,
            "urls": [],
        }
        ai_result = await ai_client.analyze(ai_payload)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    if conversation is None:
        conversation = ChatConversation(title=f"File upload: {filename[:50]}")
        session.add(conversation)
        await session.flush()

    trigger_clean = (trigger_message or "").strip()
    user_text = trigger_clean if trigger_clean else f"Uploaded file '{filename}' for {mode} analysis"
    user_message = ChatMessage(
        conversation_id=conversation.id,
        role=ChatRole.user,
        content=user_text,
        status="sent",
    )
    session.add(user_message)
    await session.flush()

    ai_classify = str(ai_result.get("classify")) if isinstance(ai_result, dict) and ai_result.get("classify") is not None else None
    ai_reason = str(ai_result.get("reason")) if isinstance(ai_result, dict) and ai_result.get("reason") is not None else None
    ai_confidence = ai_result.get("confidence_percent") if isinstance(ai_result, dict) else None

    trace_payload = {
        "upload_type": "file",
        "analysis_mode": mode,
        "file_name": filename,
        "file_hash": file_hash,
        "is_blacklisted": file_blacklisted,
        "file_status": file_status,
        "file_scan": file_scan_result,
        "ai_classify": ai_classify,
        "ai_reason": ai_reason,
        "ai_confidence_percent": ai_confidence,
        "tool_trace": _sanitize_tool_trace(ai_result.get("tool_trace") if isinstance(ai_result, dict) else None),
    }

    assistant_lines = [
        f"File analysis completed for {filename} ({mode}).",
        f"SHA-256: {file_hash}",
        f"Blacklist match: {'YES' if file_blacklisted else 'NO'}",
        f"Stored status: {file_status}",
    ]
    if isinstance(file_scan_result, dict):
        assistant_lines.append(f"File risk level: {file_scan_result.get('risk_level', 'unknown')}")
    if ai_classify:
        assistant_lines.append(f"AI classify: {ai_classify}")
    if ai_confidence is not None:
        assistant_lines.append(f"AI confidence: {ai_confidence}%")
    if ai_reason:
        assistant_lines.append(f"AI reason: {ai_reason}")

    assistant_message = ChatMessage(
        conversation_id=conversation.id,
        role=ChatRole.assistant,
        content="\n".join(assistant_lines),
        status="sent",
        tool_name="scan_uploaded_file",
        tool_payload=trace_payload,
    )
    session.add(assistant_message)

    conversation.updated_at = datetime.utcnow()
    conversation.last_message_at = conversation.updated_at

    await session.commit()
    await session.refresh(conversation)
    await session.refresh(user_message)
    await session.refresh(assistant_message)

    return ChatSendResponse(
        conversation=_to_chat_conversation_response(conversation),
        user_message=_to_chat_message_response(user_message),
        assistant_message=_to_chat_message_response(assistant_message),
    )


# Whitelist/Blacklist Management Endpoints

@app.get("/api/v1/list/{action}")
async def get_list(
    action: str, 
    type: str = Query(...), 
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=1000),
    session: AsyncSession = Depends(get_db_session)
):
    """Get paginated whitelist or blacklist items for URLs or file hashes."""
    if action not in ["whitelist", "blacklist"]:
        raise HTTPException(status_code=400, detail="action must be 'whitelist' or 'blacklist'")
    if type not in ["url", "file_hash"]:
        raise HTTPException(status_code=400, detail="type must be 'url' or 'file_hash'")

    try:
        if type == "url":
            from orchestra.models import Url
            from sqlalchemy import func
            is_whitelisted = action == "whitelist"
            if is_whitelisted:
                where_clause = Url.is_whitelisted == True
            else:
                where_clause = Url.is_blacklisted == True
            
            # Get total count
            count_stmt = select(func.count(Url.url_hash)).where(where_clause)
            count_result = await session.execute(count_stmt)
            total = count_result.scalar() or 0
            
            # Get paginated items
            stmt = select(Url).where(where_clause).offset(skip).limit(limit)
            result = await session.execute(stmt)
            items = result.scalars().all()
            
            return {
                "total": total,
                "skip": skip,
                "limit": limit,
                "items": [
                    {
                        "id": item.url_hash,
                        "value": item.raw_url,
                        "type": type,
                        "action": action,
                        "created_at": item.first_seen.isoformat() if item.first_seen else item.last_seen.isoformat(),
                    }
                    for item in items
                ]
            }
        else:  # file_hash
            from orchestra.models import File
            from sqlalchemy import func
            is_whitelisted = action == "whitelist"
            if is_whitelisted:
                where_clause = File.is_whitelisted == True
            else:
                where_clause = File.is_blacklisted == True
            
            # Get total count
            count_stmt = select(func.count(File.file_hash)).where(where_clause)
            count_result = await session.execute(count_stmt)
            total = count_result.scalar() or 0
            
            # Get paginated items
            stmt = select(File).where(where_clause).offset(skip).limit(limit)
            result = await session.execute(stmt)
            items = result.scalars().all()
            
            return {
                "total": total,
                "skip": skip,
                "limit": limit,
                "items": [
                    {
                        "id": item.file_hash,
                        "value": item.file_hash,
                        "type": type,
                        "action": action,
                        "created_at": item.first_seen.isoformat() if item.first_seen else item.last_seen.isoformat(),
                    }
                    for item in items
                ]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/list/add")
async def add_to_list(
    value: str = Form(...),
    type: str = Form(...),
    action: str = Form(...),
    session: AsyncSession = Depends(get_db_session),
):
    """Add an item to whitelist or blacklist."""
    if action not in ["whitelist", "blacklist"]:
        raise HTTPException(status_code=400, detail="action must be 'whitelist' or 'blacklist'")
    if type not in ["url", "file_hash"]:
        raise HTTPException(status_code=400, detail="type must be 'url' or 'file_hash'")

    try:
        if type == "url":
            from orchestra.models import Url
            url_hash = hashlib.sha256(value.strip().encode()).hexdigest()
            
            stmt = select(Url).where(Url.url_hash == url_hash)
            result = await session.execute(stmt)
            url_obj = result.scalar_one_or_none()

            if url_obj is None:
                url_obj = Url(
                    url_hash=url_hash,
                    raw_url=value.strip(),
                    is_whitelisted=action == "whitelist",
                    is_blacklisted=action == "blacklist",
                )
                session.add(url_obj)
            else:
                if action == "whitelist":
                    url_obj.is_whitelisted = True
                    url_obj.is_blacklisted = False
                else:
                    url_obj.is_blacklisted = True
                    url_obj.is_whitelisted = False

            await session.commit()
            return {"status": "ok", "id": url_hash, "message": f"Added to {action}"}
        else:  # file_hash
            from orchestra.models import File
            file_hash = value.strip().upper()

            stmt = select(File).where(File.file_hash == file_hash)
            result = await session.execute(stmt)
            file_obj = result.scalar_one_or_none()

            if file_obj is None:
                file_obj = File(
                    file_hash=file_hash,
                    is_whitelisted=action == "whitelist",
                    is_blacklisted=action == "blacklist",
                )
                session.add(file_obj)
            else:
                if action == "whitelist":
                    file_obj.is_whitelisted = True
                    file_obj.is_blacklisted = False
                else:
                    file_obj.is_blacklisted = True
                    file_obj.is_whitelisted = False

            await session.commit()
            return {"status": "ok", "id": file_hash, "message": f"Added to {action}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/v1/list/{item_id}")
async def remove_from_list(item_id: str, session: AsyncSession = Depends(get_db_session)):
    """Remove an item from whitelist/blacklist."""
    try:
        # Try URL first
        from orchestra.models import Url, File

        url_stmt = select(Url).where(Url.url_hash == item_id)
        url_result = await session.execute(url_stmt)
        url_obj = url_result.scalar_one_or_none()

        if url_obj:
            url_obj.is_whitelisted = False
            url_obj.is_blacklisted = False
            await session.commit()
            return {"status": "ok", "message": "Removed from list"}

        # Try File
        file_stmt = select(File).where(File.file_hash == item_id)
        file_result = await session.execute(file_stmt)
        file_obj = file_result.scalar_one_or_none()

        if file_obj:
            file_obj.is_whitelisted = False
            file_obj.is_blacklisted = False
            await session.commit()
            return {"status": "ok", "message": "Removed from list"}

        raise HTTPException(status_code=404, detail="Item not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("orchestra.main:app", host="0.0.0.0", port=8080, reload=False)
