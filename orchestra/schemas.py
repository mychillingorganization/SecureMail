from typing import Any

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    email_path: str = Field(min_length=1)
    user_accepts_danger: bool = False


class ScanBatchRequest(BaseModel):
    items: list[ScanRequest] = Field(min_length=1, max_length=50)
    continue_on_error: bool = True


class ScanResponse(BaseModel):
    final_status: str
    issue_count: int
    termination_reason: str | None
    execution_logs: list[str]
    ai_classify: str | None = None
    ai_reason: str | None = None
    ai_summary: str | None = None
    ai_provider: str | None = None
    ai_confidence_percent: int | None = None
    ai_cot_steps: list[str] = Field(default_factory=list)
    ai_tool_trace: list[dict[str, Any]] = Field(default_factory=list)


class ScanBatchItemResult(BaseModel):
    index: int
    email_path: str
    success: bool
    result: ScanResponse | None = None
    error: str | None = None


class ScanBatchResponse(BaseModel):
    total: int
    succeeded: int
    failed: int
    items: list[ScanBatchItemResult]


class ScanHistoryCreate(BaseModel):
    """Model for creating a new scan history entry."""

    scan_mode: str  # "rule" or "llm"
    file_name: str
    sender: str | None = None
    receiver: str | None = None
    final_status: str
    issue_count: int
    duration_ms: int
    termination_reason: str | None = None
    ai_classify: str | None = None
    ai_reason: str | None = None
    ai_summary: str | None = None
    ai_provider: str | None = None
    ai_confidence_percent: int | None = None
    execution_logs: list[str] = Field(default_factory=list)
    ai_cot_steps: list[str] = Field(default_factory=list)


class ScanHistoryResponse(BaseModel):
    """Model for scan history response."""

    id: str
    timestamp: str
    scan_mode: str
    file_name: str
    sender: str | None = None
    receiver: str | None = None
    final_status: str
    issue_count: int
    duration_ms: int
    termination_reason: str | None = None
    ai_classify: str | None = None
    ai_reason: str | None = None
    ai_summary: str | None = None
    ai_provider: str | None = None
    ai_confidence_percent: int | None = None
    execution_logs: list[str]
    ai_cot_steps: list[str]


class ScanHistoryPaginatedResponse(BaseModel):
    total: int
    skip: int
    limit: int
    passed_count: int = 0
    issues_count: int = 0
    danger_count: int = 0
    items: list[ScanHistoryResponse]


class AuditEntry(BaseModel):
    agent_name: str
    reasoning_trace: dict[str, Any]
    cryptographic_hash: str | None = None


class ChatSendRequest(BaseModel):
    conversation_id: str | None = None
    message: str = Field(min_length=1, max_length=8000)
    context_mode: str = "general"  # general | scan


class ChatIntentRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    has_pending_attachment: bool = False


class ChatIntentResponse(BaseModel):
    detected_tool: str | None = None
    should_trigger_attachment_scan: bool = False
    reason: str


class ChatMessageResponse(BaseModel):
    id: str
    conversation_id: str
    role: str
    content: str
    status: str
    tool_name: str | None = None
    tool_payload: dict[str, Any] | None = None
    created_at: str


class ChatConversationResponse(BaseModel):
    id: str
    title: str
    created_at: str
    updated_at: str
    last_message_at: str


class ChatSendResponse(BaseModel):
    conversation: ChatConversationResponse
    user_message: ChatMessageResponse
    assistant_message: ChatMessageResponse


class ChatMessagesResponse(BaseModel):
    conversation_id: str
    messages: list[ChatMessageResponse]
