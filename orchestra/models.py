"""
Pydantic schemas cho Orchestrator.
Định nghĩa tất cả request/response models và internal data structures.
"""
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum
import uuid


class Verdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class EmailScanRequest(BaseModel):
    """Yêu cầu quét email đầu vào."""
    email_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    headers: Dict[str, Any] = Field(default_factory=dict)
    body_text: str = ""
    body_html: Optional[str] = None
    attachments: List[Dict[str, Any]] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AgentResult(BaseModel):
    """Kết quả trả về từ một agent."""
    agent_name: str
    risk_score: float = 0.0
    confidence: float = 0.0
    details: Dict[str, Any] = Field(default_factory=dict)
    processing_time_ms: float = 0.0


class ReasoningTrace(BaseModel):
    """Một bước suy luận trong pipeline."""
    step: int
    phase: str  # PERCEIVE, REASON, ACT, OBSERVE
    description: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    data: Dict[str, Any] = Field(default_factory=dict)


class RiskResult(BaseModel):
    """Kết quả tính điểm rủi ro tổng hợp."""
    total_score: float
    verdict: Verdict
    weights_used: Dict[str, float]
    component_scores: Dict[str, Optional[float]]


class ScanResult(BaseModel):
    """Kết quả quét email cuối cùng."""
    email_id: str
    verdict: Verdict
    risk_score: float
    confidence: float
    agent_results: List[AgentResult] = Field(default_factory=list)
    reasoning_traces: List[ReasoningTrace] = Field(default_factory=list)
    early_terminated: bool = False
    processing_time_ms: float = 0.0
