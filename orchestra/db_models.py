"""
Database Models — ORM models cho PostgreSQL.
Tables: emails, audit_logs, domain_emails, files, urls, favicons,
        email_urls (junction), email_files (junction)
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Enum, Float, ForeignKey, Index, String, Table, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


# --- Enum types ---
EMAIL_STATUS = Enum("processing", "completed", "quarantined", name="email_status")
VERDICT_TYPE = Enum("safe", "suspicious", "malicious", name="verdict_type")
THREAT_STATUS = Enum("benign", "suspicious", "malicious", "unknown", name="threat_status")


# --- Junction tables ---
email_urls = Table(
    "email_urls",
    Base.metadata,
    Column("email_id", UUID(as_uuid=False), ForeignKey("emails.id"), primary_key=True),
    Column("url_hash", String(64), ForeignKey("urls.url_hash"), primary_key=True),
)

email_files = Table(
    "email_files",
    Base.metadata,
    Column("email_id", UUID(as_uuid=False), ForeignKey("emails.id"), primary_key=True),
    Column("file_hash", String(64), ForeignKey("files.file_hash"), primary_key=True),
)


# --- Main tables ---
class EmailRecord(Base):
    """Bảng emails — lưu trữ email đã xử lý."""

    __tablename__ = "emails"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    message_id = Column(String(255), nullable=True, index=True, comment="RFC 5322 Message-ID")
    sender = Column(String(255), nullable=False)
    receiver = Column(String(255), nullable=False)
    status = Column(EMAIL_STATUS, nullable=False, default="processing")
    total_risk_score = Column(Float, nullable=False, default=0.0, comment="R_total")
    final_verdict = Column(VERDICT_TYPE, nullable=False, default="safe")
    processed_at = Column(DateTime, default=datetime.utcnow, index=True)

    audit_logs = relationship("AuditLogRecord", back_populates="email", cascade="all, delete-orphan")
    urls = relationship("UrlRecord", secondary=email_urls, back_populates="emails")
    files = relationship("FileRecord", secondary=email_files, back_populates="emails")


class AuditLogRecord(Base):
    """Bảng audit_logs — reasoning trace per agent per email."""

    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    email_id = Column(UUID(as_uuid=False), ForeignKey("emails.id"), nullable=False, index=True)
    agent_name = Column(String(50), nullable=False)
    reasoning_trace = Column(JSONB, nullable=False)
    cryptographic_hash = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    email = relationship("EmailRecord", back_populates="audit_logs")


class DomainEmailRecord(Base):
    """Bảng domain_emails — threat intelligence cho domain/email."""

    __tablename__ = "domain_emails"

    domain_email = Column(String(255), primary_key=True)
    status = Column(THREAT_STATUS, nullable=False, default="unknown")
    last_seen = Column(DateTime, default=datetime.utcnow)


class FileRecord(Base):
    """Bảng files — theo dõi hash tập tin."""

    __tablename__ = "files"

    file_hash = Column(String(64), primary_key=True)
    status = Column(THREAT_STATUS, nullable=False, default="unknown")
    file_path = Column(String(512), nullable=True)
    last_seen = Column(DateTime, default=datetime.utcnow)

    emails = relationship("EmailRecord", secondary=email_files, back_populates="files")


class UrlRecord(Base):
    """Bảng urls — theo dõi URL đã phân tích."""

    __tablename__ = "urls"

    url_hash = Column(String(64), primary_key=True)
    raw_url = Column(Text, nullable=False)
    status = Column(THREAT_STATUS, nullable=False, default="unknown")
    last_seen = Column(DateTime, default=datetime.utcnow)

    emails = relationship("EmailRecord", secondary=email_urls, back_populates="urls")


class FaviconRecord(Base):
    """Bảng favicons — perceptual hash cho nhận diện giả mạo thương hiệu."""

    __tablename__ = "favicons"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    brand_name = Column(String(255), nullable=False)
    phash_value = Column(String(64), nullable=False)


# --- Composite indices ---
Index("idx_audit_logs_email_agent", AuditLogRecord.email_id, AuditLogRecord.agent_name)
Index("idx_domain_email_status", DomainEmailRecord.status)
Index("idx_files_status", FileRecord.status)
Index("idx_urls_status", UrlRecord.status)
