from datetime import datetime
from enum import Enum
from uuid import uuid4

from sqlalchemy import JSON, DateTime, Enum as SQLEnum, Float, ForeignKey, String, Text, Boolean, Integer, BigInteger
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


# New Enums for enhanced schema
class FileAnalysisStage(str, Enum):
    hash_triage = "hash_triage"
    static_ole = "static_ole"
    static_pdf = "static_pdf"
    static_pe = "static_pe"
    yara = "yara"
    archive = "archive"
    sandbox = "sandbox"
    xgboost = "xgboost"


class FileType(str, Enum):
    pe = "pe"
    ole = "ole"
    pdf = "pdf"
    archive = "archive"
    other = "other"


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class AiClassification(str, Enum):
    safe = "safe"
    suspicious = "suspicious"
    dangerous = "dangerous"


class ThreatSource(str, Enum):
    web_module = "web_module"
    threat_feed = "threat_feed"
    manual = "manual"


class ModelAgentType(str, Enum):
    email_agent = "email_agent"
    file_module = "file_module"
    web_module = "web_module"
    ai_module = "ai_module"


class FeedbackSource(str, Enum):
    manual_review = "manual_review"
    telemetry = "telemetry"
    appeal = "appeal"


class EntityOperation(str, Enum):
    add = "add"
    remove = "remove"
    update = "update"


class Email(Base):
    __tablename__ = "emails"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    message_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sender: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    receiver: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[EmailStatus] = mapped_column(SQLEnum(EmailStatus), default=EmailStatus.processing)
    total_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    final_verdict: Mapped[VerdictType] = mapped_column(SQLEnum(VerdictType), default=VerdictType.safe)
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    priority: Mapped[int] = mapped_column(Integer, default=0)

    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="email", cascade="all, delete-orphan")
    pipeline_executions: Mapped[list["PipelineExecution"]] = relationship(back_populates="email", cascade="all, delete-orphan")
    agent_responses: Mapped[list["AgentResponse"]] = relationship(back_populates="email", cascade="all, delete-orphan")
    file_analyses: Mapped[list["FileAnalysis"]] = relationship(back_populates="email", cascade="all, delete-orphan")
    url_analyses: Mapped[list["UrlAnalysis"]] = relationship(back_populates="email", cascade="all, delete-orphan")
    ai_analyses: Mapped[list["AiAnalysis"]] = relationship(back_populates="email", cascade="all, delete-orphan")
    model_predictions: Mapped[list["ModelPredictionsLog"]] = relationship(back_populates="email", cascade="all, delete-orphan")


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
    risk_level: Mapped[RiskLevel | None] = mapped_column(SQLEnum(RiskLevel), nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_analyzed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_whitelisted: Mapped[bool] = mapped_column(default=False, index=True)
    is_blacklisted: Mapped[bool] = mapped_column(default=False, index=True)

    file_analyses: Mapped[list["FileAnalysis"]] = relationship(back_populates="file", cascade="all, delete-orphan")


class Url(Base):
    __tablename__ = "urls"

    url_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    raw_url: Mapped[str] = mapped_column(Text)
    status: Mapped[EntityStatus] = mapped_column(SQLEnum(EntityStatus), default=EntityStatus.unknown)
    is_whitelisted: Mapped[bool] = mapped_column(default=False, index=True)
    is_blacklisted: Mapped[bool] = mapped_column(default=False, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    risk_level: Mapped[RiskLevel | None] = mapped_column(SQLEnum(RiskLevel), nullable=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    phishing_target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_verified: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    url_analyses: Mapped[list["UrlAnalysis"]] = relationship(back_populates="url", cascade="all, delete-orphan")
    url_threat_history: Mapped[list["UrlThreatHistory"]] = relationship(back_populates="url", cascade="all, delete-orphan")


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


# New Models for Enhanced Schema

class PipelineExecution(Base):
    __tablename__ = "pipeline_executions"

    execution_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), index=True)
    correlation_id: Mapped[str] = mapped_column(String(36), index=True)
    execution_status: Mapped[str] = mapped_column(String(50))  # processing, completed, failed
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    total_duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    email: Mapped[Email] = relationship(back_populates="pipeline_executions")


class AgentResponse(Base):
    __tablename__ = "agent_responses"

    response_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), index=True)
    correlation_id: Mapped[str] = mapped_column(String(36), index=True)
    agent_type: Mapped[str] = mapped_column(String(50), index=True)  # email_agent, file_module, web_module, ai_module
    response_payload: Mapped[dict] = mapped_column(JSON)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    email: Mapped[Email] = relationship(back_populates="agent_responses")


class FileAnalysis(Base):
    __tablename__ = "file_analyses"

    analysis_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    file_hash: Mapped[str] = mapped_column(ForeignKey("files.file_hash", ondelete="CASCADE"), index=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), index=True)
    correlation_id: Mapped[str] = mapped_column(String(36), index=True)
    analysis_stage: Mapped[FileAnalysisStage] = mapped_column(SQLEnum(FileAnalysisStage))
    status: Mapped[str] = mapped_column(String(50))  # pending, in_progress, completed, failed
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    file: Mapped[File] = relationship(back_populates="file_analyses")
    email: Mapped[Email] = relationship(back_populates="file_analyses")
    static_analysis: Mapped["FileStaticAnalysis | None"] = relationship(back_populates="file_analysis", cascade="all, delete-orphan", uselist=False)
    sandbox_results: Mapped["FileSandboxResults | None"] = relationship(back_populates="file_analysis", cascade="all, delete-orphan", uselist=False)
    xgboost_results: Mapped["FileXgboostResults | None"] = relationship(back_populates="file_analysis", cascade="all, delete-orphan", uselist=False)


class FileHashTriage(Base):
    __tablename__ = "file_hash_triage"

    triage_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    file_hash: Mapped[str] = mapped_column(ForeignKey("files.file_hash", ondelete="CASCADE"), index=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    md5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sha1: Mapped[str | None] = mapped_column(String(40), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    clamav_verdict: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ioc_db_hits: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    cache_hit: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

class FileStaticAnalysis(Base):
    __tablename__ = "file_static_analysis"

    analysis_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    file_analysis_id: Mapped[str] = mapped_column(ForeignKey("file_analyses.analysis_id", ondelete="CASCADE"), index=True)
    file_type: Mapped[FileType] = mapped_column(SQLEnum(FileType))
    has_macros: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    obfuscation_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    packing_detected: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    suspicious_imports: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    entropy_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    yara_matches: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    file_analysis: Mapped[FileAnalysis] = relationship(back_populates="static_analysis")


class FileSandboxResults(Base):
    __tablename__ = "file_sandbox_results"

    sandbox_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    file_analysis_id: Mapped[str] = mapped_column(ForeignKey("file_analyses.analysis_id", ondelete="CASCADE"), index=True)
    dns_queries: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    http_requests: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    registry_changes: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    dropped_files: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    c2_indicators: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    behavioral_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    runtime_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    file_analysis: Mapped[FileAnalysis] = relationship(back_populates="sandbox_results")


class FileXgboostResults(Base):
    __tablename__ = "file_xgboost_results"

    xgboost_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    file_analysis_id: Mapped[str] = mapped_column(ForeignKey("file_analyses.analysis_id", ondelete="CASCADE"), index=True)
    risk_level: Mapped[RiskLevel] = mapped_column(SQLEnum(RiskLevel))
    confidence: Mapped[float] = mapped_column(Float)
    probabilities: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    top_features: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    file_analysis: Mapped[FileAnalysis] = relationship(back_populates="xgboost_results")


class UrlAnalysis(Base):
    __tablename__ = "url_analyses"

    url_analysis_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    url_hash: Mapped[str] = mapped_column(ForeignKey("urls.url_hash", ondelete="CASCADE"), index=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), index=True)
    correlation_id: Mapped[str] = mapped_column(String(36), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    label: Mapped[str] = mapped_column(String(50))  # safe, suspicious, malicious
    phishing_indicators: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    brand_target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    url: Mapped[Url] = relationship(back_populates="url_analyses")
    email: Mapped[Email] = relationship(back_populates="url_analyses")


class UrlThreatHistory(Base):
    __tablename__ = "url_threat_history"

    history_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    url_hash: Mapped[str] = mapped_column(ForeignKey("urls.url_hash", ondelete="CASCADE"), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    label: Mapped[str] = mapped_column(String(50))
    source: Mapped[ThreatSource] = mapped_column(SQLEnum(ThreatSource))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    url: Mapped[Url] = relationship(back_populates="url_threat_history")


class DomainReputationHistory(Base):
    __tablename__ = "domain_reputation_history"

    history_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    domain: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(50))
    reputation_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    source: Mapped[str | None] = mapped_column(String(100), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class AiAnalysis(Base):
    __tablename__ = "ai_analyses"

    analysis_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), index=True)
    correlation_id: Mapped[str] = mapped_column(String(36), index=True)
    model_id: Mapped[str] = mapped_column(String(100), index=True)
    provider: Mapped[str] = mapped_column(String(50))  # gemini, openai
    classification: Mapped[AiClassification] = mapped_column(SQLEnum(AiClassification))
    confidence_percent: Mapped[float] = mapped_column(Float)
    reasoning_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool_use_trace: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    escalation_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    email: Mapped[Email] = relationship(back_populates="ai_analyses")


class ModelDeployment(Base):
    __tablename__ = "model_deployments"

    model_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    agent_type: Mapped[ModelAgentType] = mapped_column(SQLEnum(ModelAgentType), index=True)
    version: Mapped[str] = mapped_column(String(50))
    provider: Mapped[str | None] = mapped_column(String(50), nullable=True)
    deployment_date: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accuracy_baseline: Mapped[float | None] = mapped_column(Float, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    predictions_logs: Mapped[list["ModelPredictionsLog"]] = relationship(back_populates="model_deployment", cascade="all, delete-orphan")


class ModelPredictionsLog(Base):
    __tablename__ = "model_predictions_log"

    prediction_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    model_id: Mapped[str | None] = mapped_column(ForeignKey("model_deployments.model_id", ondelete="SET NULL"), nullable=True, index=True)
    email_id: Mapped[int] = mapped_column(ForeignKey("emails.id", ondelete="CASCADE"), index=True)
    predicted_label: Mapped[str] = mapped_column(String(50))
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    actual_label: Mapped[str | None] = mapped_column(String(50), nullable=True)
    feedback_source: Mapped[FeedbackSource | None] = mapped_column(SQLEnum(FeedbackSource), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    model_deployment: Mapped["ModelDeployment | None"] = relationship(back_populates="predictions_logs")
    email: Mapped[Email] = relationship(back_populates="model_predictions")


class ThreatListUpdate(Base):
    __tablename__ = "threat_list_updates"

    update_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    list_name: Mapped[str] = mapped_column(String(255))
    update_source: Mapped[ThreatSource] = mapped_column(SQLEnum(ThreatSource))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    added_count: Mapped[int] = mapped_column(Integer, default=0)
    removed_count: Mapped[int] = mapped_column(Integer, default=0)
    changed_count: Mapped[int] = mapped_column(Integer, default=0)
    update_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    threat_list_changes: Mapped[list["ThreatListChange"]] = relationship(back_populates="threat_list_update", cascade="all, delete-orphan")


class ThreatListChange(Base):
    __tablename__ = "threat_list_changes"

    change_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    update_id: Mapped[str] = mapped_column(ForeignKey("threat_list_updates.update_id", ondelete="CASCADE"), index=True)
    entity_type: Mapped[str] = mapped_column(String(50))  # domain, hash, url
    entity_value: Mapped[str] = mapped_column(Text)
    operation: Mapped[EntityOperation] = mapped_column(SQLEnum(EntityOperation))
    old_value: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    new_value: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    threat_list_update: Mapped[ThreatListUpdate] = relationship(back_populates="threat_list_changes")


class ScanHistory(Base):
    """Stores frontend scan result history for dashboard and analytics."""

    __tablename__ = "scan_history"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    scan_mode: Mapped[str] = mapped_column(String(50), index=True)  # "rule" or "llm"
    file_name: Mapped[str] = mapped_column(String(255))
    sender: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    receiver: Mapped[str | None] = mapped_column(String(255), nullable=True)
    final_status: Mapped[str] = mapped_column(String(100))
    issue_count: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    termination_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    ai_classify: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ai_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_provider: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ai_confidence_percent: Mapped[int | None] = mapped_column(Integer, nullable=True)
    execution_logs: Mapped[list[str]] = mapped_column(JSON, default=[])
    ai_cot_steps: Mapped[list[str]] = mapped_column(JSON, default=[])


class ChatRole(str, Enum):
    user = "user"
    assistant = "assistant"
    tool = "tool"


class ChatConversation(Base):
    """Stores chat conversation threads."""

    __tablename__ = "chat_conversations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    title: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    last_message_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)

    messages: Mapped[list["ChatMessage"]] = relationship(
        back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="ChatMessage.created_at",
    )


class ChatMessage(Base):
    """Stores a message within a conversation."""

    __tablename__ = "chat_messages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    conversation_id: Mapped[str] = mapped_column(ForeignKey("chat_conversations.id", ondelete="CASCADE"), index=True)
    role: Mapped[ChatRole] = mapped_column(SQLEnum(ChatRole), index=True)
    content: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="sent")
    tool_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    tool_payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)

    conversation: Mapped[ChatConversation] = relationship(back_populates="messages")
