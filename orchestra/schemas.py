from typing import Any

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    email_path: str = Field(min_length=1)
    user_accepts_danger: bool = False


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


class ScanHistoryCreate(BaseModel):
    """Model for creating a new scan history entry."""

    scan_mode: str  # "rule" or "llm"
    file_name: str
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


class AuditEntry(BaseModel):
    agent_name: str
    reasoning_trace: dict[str, Any]
    cryptographic_hash: str | None = None
