"""
Database Models — ORM models cho PostgreSQL.
Bảng: emails, audit_logs, domain_emails, files, urls, favicons (+ junction tables)
"""
import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Float, Boolean, Integer, DateTime, Text, ForeignKey, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from database import Base


def generate_uuid():
    return str(uuid.uuid4())


class EmailRecord(Base):
    """Bảng emails — lưu trữ thông tin email đã quét."""
    __tablename__ = "emails"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    message_id = Column(String, index=True)  # RFC 5322 Message-ID / pipeline email_id
    sender = Column(String, nullable=False)
    receiver = Column(String, nullable=False)
    status = Column(Enum(EmailStatusEnum), default=EmailStatusEnum.PROCESSING)
    total_risk_score = Column(Float, nullable=True)
    final_verdict = Column(Enum(VerdictTypeEnum), nullable=True)
    processed_at = Column(DateTime, nullable=True)

    # Relationships
    audit_logs = relationship("AuditLog", back_populates="email", cascade="all, delete-orphan")
    urls = relationship("Url", secondary=email_urls, back_populates="emails")
    files = relationship("File", secondary=email_files, back_populates="emails")


class ReasoningTraceRecord(Base):
    """Bảng reasoning_traces — dấu vết suy luận cho mỗi bước."""
    __tablename__ = "reasoning_traces"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_id = Column(UUID(as_uuid=True), ForeignKey("emails.id"), nullable=False, index=True)
    agent_name = Column(String, nullable=False)  # orchestrator | email | file | web | system
    reasoning_trace = Column(JSONB, nullable=False)
    cryptographic_hash = Column(String, nullable=False)  # SHA-256 of reasoning_trace
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
    emails = relationship("Email", secondary=email_files, back_populates="files")


class ClawbackEventRecord(Base):
    """Bảng clawback_events — sự kiện thu hồi/thay đổi phán định."""
    __tablename__ = "clawback_events"

    url_hash = Column(String, primary_key=True)
    raw_url = Column(TEXT, nullable=False)
    status = Column(Enum(IntelligenceStatusEnum), default=IntelligenceStatusEnum.UNKNOWN)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    emails = relationship("Email", secondary=email_urls, back_populates="urls")


class Favicon(Base):
    """Bảng favicons — lưu trữ pHash của favicon thương hiệu để so sánh."""

    __tablename__ = "favicons"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    brand_name = Column(String, index=True, nullable=False)
    phash_value = Column(String, nullable=False)
