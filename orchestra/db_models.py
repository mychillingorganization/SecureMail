"""
Database Models — ORM models cho PostgreSQL.
Bảng: emails, audit_logs, domain_emails, files, urls, favicons (+ junction tables)
"""

import enum
import uuid
from datetime import datetime

from database import Base
from sqlalchemy import Column, DateTime, Enum, Float, ForeignKey, String, Table
from sqlalchemy.dialects.postgresql import JSONB, TEXT, UUID
from sqlalchemy.orm import relationship


# ==========================================
# ENUMs
# ==========================================

class EmailStatusEnum(enum.Enum):
    PROCESSING = "processing"
    COMPLETED = "completed"
    QUARANTINED = "quarantined"


class VerdictTypeEnum(enum.Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class IntelligenceStatusEnum(enum.Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


# ==========================================
# Junction Tables (N-N)
# ==========================================

email_urls = Table(
    "email_urls",
    Base.metadata,
    Column("email_id", UUID(as_uuid=True), ForeignKey("emails.id"), primary_key=True),
    Column("url_hash", String, ForeignKey("urls.url_hash"), primary_key=True),
)

email_files = Table(
    "email_files",
    Base.metadata,
    Column("email_id", UUID(as_uuid=True), ForeignKey("emails.id"), primary_key=True),
    Column("file_hash", String, ForeignKey("files.file_hash"), primary_key=True),
)


# ==========================================
# Core Tables
# ==========================================

class Email(Base):
    """Bảng emails — lưu trữ thông tin email đã xử lý."""

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


class AuditLog(Base):
    """Bảng audit_logs — nhật ký kiểm toán bất biến cho mỗi quyết định của agent."""

    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email_id = Column(UUID(as_uuid=True), ForeignKey("emails.id"), nullable=False, index=True)
    agent_name = Column(String, nullable=False)  # orchestrator | email | file | web | system
    reasoning_trace = Column(JSONB, nullable=False)
    cryptographic_hash = Column(String, nullable=False)  # SHA-256 of reasoning_trace
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationship
    email = relationship("Email", back_populates="audit_logs")


# ==========================================
# Intelligence Tables
# ==========================================

class DomainEmail(Base):
    """Bảng domain_emails — thông tin tình báo về domain/email đã thấy."""

    __tablename__ = "domain_emails"

    domain_email = Column(String, primary_key=True)
    status = Column(Enum(IntelligenceStatusEnum), default=IntelligenceStatusEnum.UNKNOWN)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class File(Base):
    """Bảng files — thông tin tình báo về file đính kèm (theo SHA-256)."""

    __tablename__ = "files"

    file_hash = Column(String, primary_key=True)  # SHA-256
    status = Column(Enum(IntelligenceStatusEnum), default=IntelligenceStatusEnum.UNKNOWN)
    file_path = Column(String, nullable=True)  # Đường dẫn lưu trữ cục bộ cho sandbox
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    emails = relationship("Email", secondary=email_files, back_populates="files")


class Url(Base):
    """Bảng urls — thông tin tình báo về URL (theo hash)."""

    __tablename__ = "urls"

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
