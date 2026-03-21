"""
Database Models — ORM models cho PostgreSQL theo PRD improve_plan.md.
Tables: emails, audit_logs, domain_email, files, urls, favicons,
        email_urls (junction), email_files (junction)
"""

import uuid
from datetime import datetime

from database import Base
from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    String,
    Table,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship


def generate_uuid():
    return str(uuid.uuid4())


# --- Enum types ---
EMAIL_STATUS = Enum("processing", "completed", "quarantined", name="email_status")
VERDICT_TYPE = Enum("safe", "suspicious", "malicious", name="verdict_type")
THREAT_STATUS = Enum("benign", "suspicious", "malicious", "unknown", name="threat_status")


# --- Junction tables ---
email_urls = Table(
    "email_urls",
    Base.metadata,
    Column("email_id", String(255), ForeignKey("emails.id"), primary_key=True),
    Column("url_hash", String(64), ForeignKey("urls.url_hash"), primary_key=True),
)

email_files = Table(
    "email_files",
    Base.metadata,
    Column("email_id", String(255), ForeignKey("emails.id"), primary_key=True),
    Column("file_hash", String(64), ForeignKey("files.file_hash"), primary_key=True),
)


# --- Main tables ---

class EmailRecord(Base):
    """
    Table emails — PRD Section database schema.
    Stores processed email records with verdict and risk score.
    """

    __tablename__ = "emails"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    message_id = Column(String(255), nullable=True, index=True, comment="RFC 5322 Message-ID")
    sender = Column(String(255))
    receiver = Column(String(255))
    status = Column(EMAIL_STATUS, nullable=False, default="processing")
    total_risk_score = Column(Float, nullable=False, default=0.0, comment="R_total")
    final_verdict = Column(VERDICT_TYPE, nullable=False, default="safe")
    processed_at = Column(DateTime, default=datetime.utcnow, index=True)

    # Relationships
    audit_logs = relationship("AuditLogRecord", back_populates="email", cascade="all, delete-orphan")
    urls = relationship("UrlRecord", secondary=email_urls, back_populates="emails")
    files = relationship("FileRecord", secondary=email_files, back_populates="emails")


class AuditLogRecord(Base):
    """
    Table audit_logs — reasoning trace per agent per email.
    Each agent (Orchestrator, Email Agent, File Agent, Web Agent) writes its trace here.
    """

    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    email_id = Column(UUID(as_uuid=False), ForeignKey("emails.id"), nullable=False, index=True)
    agent_name = Column(
        String(50),
        nullable=False,
        comment="Orchestrator | Email Agent | File Agent | Web Agent",
    )
    reasoning_trace = Column(JSONB, comment="Full reasoning trace as JSON")
    cryptographic_hash = Column(String(128), comment="Hash for tamper-proof audit")
    created_at = Column(DateTime, default=datetime.utcnow, comment="Timestamp of log entry")

    # Relationship
    email = relationship("EmailRecord", back_populates="audit_logs")


class DomainEmailRecord(Base):
    """
    Table domain_email — Whitelist + Blacklist for domains and email addresses.
    """

    __tablename__ = "domain_email"

    domain_email = Column(String(255), primary_key=True, comment="Domain or email address")
    status = Column(THREAT_STATUS, nullable=False, default="unknown")
    last_seen = Column(DateTime, default=datetime.utcnow, comment="Last time system processed this domain")


class FileRecord(Base):
    """
    Table files — SHA-256 file hash tracking.
    """

    __tablename__ = "files"

    file_hash = Column(String(64), primary_key=True, comment="SHA-256 hash")
    status = Column(THREAT_STATUS, nullable=False, default="unknown")
    file_path = Column(String(512), comment="Path to file storage")
    last_seen = Column(DateTime, default=datetime.utcnow, comment="Last analysis time")

    # Relationship
    emails = relationship("EmailRecord", secondary=email_files, back_populates="files")


class UrlRecord(Base):
    """
    Table urls — URL hash tracking.
    """

    __tablename__ = "urls"

    url_hash = Column(String(64), primary_key=True, comment="Hash of URL")
    raw_url = Column(Text, comment="Original URL")
    status = Column(THREAT_STATUS, nullable=False, default="unknown")
    last_seen = Column(DateTime, default=datetime.utcnow, comment="Last analysis time")

    # Relationship
    emails = relationship("EmailRecord", secondary=email_urls, back_populates="urls")


class FaviconRecord(Base):
    """
    Table favicons — perceptual hash for brand impersonation detection.
    """

    __tablename__ = "favicons"

    id = Column(UUID(as_uuid=False), primary_key=True, default=generate_uuid)
    brand_name = Column(String(255))
    phash_value = Column(String(64), comment="Perceptual hash value")


# --- Composite indices ---
Index("idx_audit_logs_email_agent", AuditLogRecord.email_id, AuditLogRecord.agent_name)
Index("idx_domain_email_status", DomainEmailRecord.status)
Index("idx_files_status", FileRecord.status)
Index("idx_urls_status", UrlRecord.status)
