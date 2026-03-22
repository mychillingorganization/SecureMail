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


class AuditEntry(BaseModel):
    agent_name: str
    reasoning_trace: dict[str, Any]
    cryptographic_hash: str | None = None
