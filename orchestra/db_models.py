"""
Database Models — ORM models cho PostgreSQL.
Bảng: emails, reasoning_traces, agent_scores, clawback_events
"""

import uuid
from datetime import datetime

from database import Base
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship


def generate_uuid():
    return str(uuid.uuid4())


class EmailRecord(Base):
    """Bảng emails — lưu trữ thông tin email đã quét."""

    __tablename__ = "emails"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    email_id = Column(String(255), nullable=False, index=True, unique=True)
    sender = Column(String(255))
    recipient = Column(String(255))
    subject = Column(Text)
    verdict = Column(String(20), nullable=False)  # SAFE, SUSPICIOUS, MALICIOUS
    risk_score = Column(Float, nullable=False)
    confidence = Column(Float, default=0.0)
    early_terminated = Column(Boolean, default=False)
    processing_time_ms = Column(Float)
    raw_request = Column(JSONB)  # Lưu toàn bộ request gốc
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    reasoning_traces = relationship("ReasoningTraceRecord", back_populates="email", cascade="all, delete-orphan")
    agent_scores = relationship("AgentScoreRecord", back_populates="email", cascade="all, delete-orphan")
    clawback_events = relationship("ClawbackEventRecord", back_populates="email", cascade="all, delete-orphan")


class ReasoningTraceRecord(Base):
    """Bảng reasoning_traces — dấu vết suy luận cho mỗi bước."""

    __tablename__ = "reasoning_traces"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    email_id = Column(String(255), ForeignKey("emails.email_id"), nullable=False, index=True)
    step = Column(Integer, nullable=False)
    phase = Column(String(20), nullable=False)  # PERCEIVE, REASON, ACT, OBSERVE
    description = Column(Text, nullable=False)
    data = Column(JSONB)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    email = relationship("EmailRecord", back_populates="reasoning_traces")


class AgentScoreRecord(Base):
    """Bảng agent_scores — điểm rủi ro từ mỗi agent."""

    __tablename__ = "agent_scores"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    email_id = Column(String(255), ForeignKey("emails.email_id"), nullable=False, index=True)
    agent_name = Column(String(50), nullable=False)  # email, file, web
    risk_score = Column(Float, nullable=False)
    confidence = Column(Float, default=0.0)
    details = Column(JSONB)
    processing_time_ms = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    email = relationship("EmailRecord", back_populates="agent_scores")


class ClawbackEventRecord(Base):
    """Bảng clawback_events — sự kiện thu hồi/thay đổi phán định."""

    __tablename__ = "clawback_events"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    email_id = Column(String(255), ForeignKey("emails.email_id"), nullable=False, index=True)
    original_verdict = Column(String(20), nullable=False)
    new_verdict = Column(String(20), nullable=False)
    reason = Column(Text, nullable=False)
    created_by = Column(String(100), default="system")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationship
    email = relationship("EmailRecord", back_populates="clawback_events")


# Composite indices
Index("idx_reasoning_email_step", ReasoningTraceRecord.email_id, ReasoningTraceRecord.step)
Index("idx_agent_scores_email_agent", AgentScoreRecord.email_id, AgentScoreRecord.agent_name)
