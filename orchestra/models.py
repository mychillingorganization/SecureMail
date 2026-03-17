"""
Pydantic schemas cho Orchestrator.
Định nghĩa tất cả request/response models và internal data structures.
"""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Verdict(StrEnum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class EmailScanRequest(BaseModel):
    """Yêu cầu quét email đầu vào."""

    email_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    headers: dict[str, Any] = Field(default_factory=dict)
    body_text: str = ""
    body_html: str | None = None
    attachments: list[dict[str, Any]] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AgentResult(BaseModel):
    """Kết quả trả về từ một agent."""

    agent_name: str
    risk_score: float = 0.0
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)
    processing_time_ms: float = 0.0


class ReasoningTrace(BaseModel):
    """Một bước suy luận trong pipeline."""

    step: int
    phase: str  # PERCEIVE, REASON, ACT, OBSERVE
    description: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    data: dict[str, Any] = Field(default_factory=dict)


class RiskResult(BaseModel):
    """Kết quả tính điểm rủi ro tổng hợp."""

    total_score: float
    verdict: Verdict
    weights_used: dict[str, float]
    component_scores: dict[str, float | None]


class ScanResult(BaseModel):
    """Kết quả quét email cuối cùng."""

    email_id: str
    verdict: Verdict
    risk_score: float
    confidence: float
    agent_results: list[AgentResult] = Field(default_factory=list)
    reasoning_traces: list[ReasoningTrace] = Field(default_factory=list)
    early_terminated: bool = False
    processing_time_ms: float = 0.0
