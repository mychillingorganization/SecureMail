from typing import Any

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    subject: str | None = None
    sender: str | None = None
    auth: dict[str, Any] = Field(default_factory=dict)
    email_agent: dict[str, Any] = Field(default_factory=dict)
    file_module: list[dict[str, Any]] = Field(default_factory=list)
    web_module: dict[str, Any] = Field(default_factory=dict)
    issue_count: int = 0
    provisional_final_status: str = "PASS"
    termination_reason: str | None = None
    urls: list[str] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    available: bool = True
    classify: str = "safe"  # safe | suspicious | dangerous
    reason: str = ""
    summary: str = ""
    risk_factors: list[str] = Field(default_factory=list)
    danger_reasons: list[str] = Field(default_factory=list)
    safe_reasons: list[str] = Field(default_factory=list)
    confidence_percent: int = 0
    should_escalate: bool = False
    provider: str = "gemini"
    tool_trace: list[dict[str, Any]] = Field(default_factory=list)
    schema_review: dict[str, Any] = Field(default_factory=dict)
