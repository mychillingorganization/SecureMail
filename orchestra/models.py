from datetime import datetime
from enum import Enum
from uuid import uuid4

from sqlalchemy import JSON, DateTime, Enum as SQLEnum, Float, ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class EmailStatus(str, Enum):
    processing = "processing"
    completed = "completed"
    quarantined = "quarantined"


class VerdictType(str, Enum):
    safe = "safe"
    suspicious = "suspicious"
    malicious = "malicious"


class EntityStatus(str, Enum):
    benign = "benign"
    suspicious = "suspicious"
    malicious = "malicious"
    unknown = "unknown"


class Email(Base):
    __tablename__ = "emails"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    message_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sender: Mapped[str | None] = mapped_column(String(255), nullable=True)
    receiver: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[EmailStatus] = mapped_column(SQLEnum(EmailStatus), default=EmailStatus.processing)
    total_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    final_verdict: Mapped[VerdictType] = mapped_column(SQLEnum(VerdictType), default=VerdictType.safe)
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="email", cascade="all, delete-orphan")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), index=True)
    agent_name: Mapped[str] = mapped_column(String(100))
    reasoning_trace: Mapped[dict] = mapped_column(JSON)
    cryptographic_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    email: Mapped[Email] = relationship(back_populates="audit_logs")


class DomainEmail(Base):
    __tablename__ = "domain_emails"

    domain_email: Mapped[str] = mapped_column(String(255), primary_key=True)
    status: Mapped[EntityStatus] = mapped_column(SQLEnum(EntityStatus), default=EntityStatus.unknown)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class File(Base):
    __tablename__ = "files"

    file_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[EntityStatus] = mapped_column(SQLEnum(EntityStatus), default=EntityStatus.unknown)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class Url(Base):
    __tablename__ = "urls"

    url_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    raw_url: Mapped[str] = mapped_column(Text)
    status: Mapped[EntityStatus] = mapped_column(SQLEnum(EntityStatus), default=EntityStatus.unknown)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class Favicon(Base):
    __tablename__ = "favicons"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    brand_name: Mapped[str] = mapped_column(String(255))
    phash_value: Mapped[str] = mapped_column(String(255))


class EmailUrl(Base):
    __tablename__ = "email_urls"

    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), primary_key=True)
    url_hash: Mapped[str] = mapped_column(ForeignKey("urls.url_hash", ondelete="CASCADE"), primary_key=True)


class EmailFile(Base):
    __tablename__ = "email_files"

    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), primary_key=True)
    file_hash: Mapped[str] = mapped_column(ForeignKey("files.file_hash", ondelete="CASCADE"), primary_key=True)
