"""Enhance schema with file analysis, sandbox, AI, URL tracking, and threat intelligence

Revision ID: 0002_enhance_schema
Revises: 0001_init_schema
Create Date: 2026-03-24
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0002_enhance_schema"
down_revision = "0001_init_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create new enums
    file_analysis_stage = sa.Enum(
        "hash_triage", "static_ole", "static_pdf", "static_pe", "yara", "archive", "sandbox", "xgboost",
        name="fileanalysisstage"
    )
    file_type = sa.Enum("pe", "ole", "pdf", "archive", "other", name="filetype")
    risk_level = sa.Enum("low", "medium", "high", name="risklevel")
    ai_classification = sa.Enum("safe", "suspicious", "dangerous", name="aiclassification")
    threat_source = sa.Enum("web_module", "threat_feed", "manual", name="threatsource")
    model_agent_type = sa.Enum("email_agent", "file_module", "web_module", "ai_module", name="modelagenttype")
    feedback_source_enum = sa.Enum("manual_review", "telemetry", "appeal", name="feedbacksource")
    entity_operation = sa.Enum("add", "remove", "update", name="entityoperation")

    # Alter emails table: add correlation_id, retry_count, priority
    op.add_column("emails", sa.Column("correlation_id", sa.String(36), nullable=True, unique=False))
    op.add_column("emails", sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("emails", sa.Column("priority", sa.Integer(), nullable=False, server_default="0"))
    op.create_index("ix_emails_correlation_id", "emails", ["correlation_id"])
    op.create_index("ix_emails_sender", "emails", ["sender"])
    op.create_index("ix_emails_processed_at", "emails", ["processed_at"])

    # 1. pipeline_executions table
    op.create_table(
        "pipeline_executions",
        sa.Column("execution_id", sa.String(36), primary_key=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("correlation_id", sa.String(36), nullable=False, index=True),
        sa.Column("execution_status", sa.String(50), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_duration_ms", sa.Integer(), nullable=True),
    )

    # 2. agent_responses table
    op.create_table(
        "agent_responses",
        sa.Column("response_id", sa.String(36), primary_key=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("correlation_id", sa.String(36), nullable=False, index=True),
        sa.Column("agent_type", sa.String(50), nullable=False),
        sa.Column("response_payload", sa.JSON(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_agent_responses_agent_type", "agent_responses", ["agent_type"])

    # 3. file_analyses table
    op.create_table(
        "file_analyses",
        sa.Column("analysis_id", sa.String(36), primary_key=True),
        sa.Column("file_hash", sa.String(64), sa.ForeignKey("files.file_hash", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("correlation_id", sa.String(36), nullable=False, index=True),
        sa.Column("analysis_stage", file_analysis_stage, nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 4. file_hash_triage table
    op.create_table(
        "file_hash_triage",
        sa.Column("triage_id", sa.String(36), primary_key=True),
        sa.Column("file_hash", sa.String(64), sa.ForeignKey("files.file_hash", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("md5", sa.String(32), nullable=True),
        sa.Column("sha1", sa.String(40), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("clamav_verdict", sa.String(255), nullable=True),
        sa.Column("ioc_db_hits", sa.JSON(), nullable=True),
        sa.Column("cache_hit", sa.Boolean(), server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 5. file_static_analysis table
    op.create_table(
        "file_static_analysis",
        sa.Column("analysis_id", sa.String(36), primary_key=True),
        sa.Column("file_analysis_id", sa.String(36), sa.ForeignKey("file_analyses.analysis_id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("file_type", file_type, nullable=False),
        sa.Column("has_macros", sa.Boolean(), nullable=True),
        sa.Column("obfuscation_score", sa.Float(), nullable=True),
        sa.Column("packing_detected", sa.Boolean(), nullable=True),
        sa.Column("suspicious_imports", sa.JSON(), nullable=True),
        sa.Column("entropy_score", sa.Float(), nullable=True),
        sa.Column("yara_matches", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 6. file_sandbox_results table
    op.create_table(
        "file_sandbox_results",
        sa.Column("sandbox_id", sa.String(36), primary_key=True),
        sa.Column("file_analysis_id", sa.String(36), sa.ForeignKey("file_analyses.analysis_id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("dns_queries", sa.JSON(), nullable=True),
        sa.Column("http_requests", sa.JSON(), nullable=True),
        sa.Column("registry_changes", sa.JSON(), nullable=True),
        sa.Column("dropped_files", sa.JSON(), nullable=True),
        sa.Column("c2_indicators", sa.JSON(), nullable=True),
        sa.Column("behavioral_score", sa.Float(), nullable=True),
        sa.Column("runtime_seconds", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 7. file_xgboost_results table
    op.create_table(
        "file_xgboost_results",
        sa.Column("xgboost_id", sa.String(36), primary_key=True),
        sa.Column("file_analysis_id", sa.String(36), sa.ForeignKey("file_analyses.analysis_id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("risk_level", risk_level, nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("probabilities", sa.JSON(), nullable=True),
        sa.Column("top_features", sa.JSON(), nullable=True),
        sa.Column("model_version", sa.String(50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 8. url_analyses table
    op.create_table(
        "url_analyses",
        sa.Column("url_analysis_id", sa.String(36), primary_key=True),
        sa.Column("url_hash", sa.String(64), sa.ForeignKey("urls.url_hash", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("correlation_id", sa.String(36), nullable=False, index=True),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("label", sa.String(50), nullable=False),
        sa.Column("phishing_indicators", sa.JSON(), nullable=True),
        sa.Column("brand_target", sa.String(255), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 9. url_threat_history table
    op.create_table(
        "url_threat_history",
        sa.Column("history_id", sa.String(36), primary_key=True),
        sa.Column("url_hash", sa.String(64), sa.ForeignKey("urls.url_hash", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("label", sa.String(50), nullable=False),
        sa.Column("source", threat_source, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 10. domain_reputation_history table
    op.create_table(
        "domain_reputation_history",
        sa.Column("history_id", sa.String(36), primary_key=True),
        sa.Column("domain", sa.String(255), nullable=False, index=True),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("reputation_score", sa.Float(), nullable=True),
        sa.Column("source", sa.String(100), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 11. ai_analyses table
    op.create_table(
        "ai_analyses",
        sa.Column("analysis_id", sa.String(36), primary_key=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("correlation_id", sa.String(36), nullable=False, index=True),
        sa.Column("model_id", sa.String(100), nullable=False, index=True),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("classification", ai_classification, nullable=False),
        sa.Column("confidence_percent", sa.Float(), nullable=False),
        sa.Column("reasoning_text", sa.Text(), nullable=True),
        sa.Column("tool_use_trace", sa.JSON(), nullable=True),
        sa.Column("escalation_flag", sa.Boolean(), server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 12. model_deployments table
    op.create_table(
        "model_deployments",
        sa.Column("model_id", sa.String(100), primary_key=True),
        sa.Column("agent_type", model_agent_type, nullable=False, index=True),
        sa.Column("version", sa.String(50), nullable=False),
        sa.Column("provider", sa.String(50), nullable=True),
        sa.Column("deployment_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accuracy_baseline", sa.Float(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 13. model_predictions_log table
    op.create_table(
        "model_predictions_log",
        sa.Column("prediction_id", sa.String(36), primary_key=True),
        sa.Column("model_id", sa.String(100), sa.ForeignKey("model_deployments.model_id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("predicted_label", sa.String(50), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("actual_label", sa.String(50), nullable=True),
        sa.Column("feedback_source", feedback_source_enum, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 14. threat_list_updates table
    op.create_table(
        "threat_list_updates",
        sa.Column("update_id", sa.String(36), primary_key=True),
        sa.Column("list_name", sa.String(255), nullable=False),
        sa.Column("update_source", threat_source, nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("added_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("removed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("changed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("update_hash", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 15. threat_list_changes table
    op.create_table(
        "threat_list_changes",
        sa.Column("change_id", sa.String(36), primary_key=True),
        sa.Column("update_id", sa.String(36), sa.ForeignKey("threat_list_updates.update_id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("entity_value", sa.Text(), nullable=False),
        sa.Column("operation", entity_operation, nullable=False),
        sa.Column("old_value", sa.JSON(), nullable=True),
        sa.Column("new_value", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Update files table: add risk_level, analysis_id, first_seen, last_analyzed
    op.add_column("files", sa.Column("risk_level", risk_level, nullable=True))
    op.add_column("files", sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("files", sa.Column("last_analyzed", sa.DateTime(timezone=True), nullable=True))

    # Update urls table: add risk_level, first_seen, phishing_target, last_verified
    op.add_column("urls", sa.Column("risk_level", risk_level, nullable=True))
    op.add_column("urls", sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True))
    op.add_column("urls", sa.Column("phishing_target", sa.String(255), nullable=True))
    op.add_column("urls", sa.Column("last_verified", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    # Drop new columns from existing tables
    op.drop_column("urls", "last_verified")
    op.drop_column("urls", "phishing_target")
    op.drop_column("urls", "first_seen")
    op.drop_column("urls", "risk_level")
    op.drop_column("files", "last_analyzed")
    op.drop_column("files", "first_seen")
    op.drop_column("files", "risk_level")
    op.drop_column("emails", "priority")
    op.drop_column("emails", "retry_count")
    op.drop_column("emails", "correlation_id")

    # Drop new tables
    op.drop_table("threat_list_changes")
    op.drop_table("threat_list_updates")
    op.drop_table("model_predictions_log")
    op.drop_table("model_deployments")
    op.drop_table("ai_analyses")
    op.drop_table("domain_reputation_history")
    op.drop_table("url_threat_history")
    op.drop_table("url_analyses")
    op.drop_table("file_xgboost_results")
    op.drop_table("file_sandbox_results")
    op.drop_table("file_static_analysis")
    op.drop_table("file_hash_triage")
    op.drop_table("file_analyses")
    op.drop_table("agent_responses")
    op.drop_table("pipeline_executions")

    # Drop enums
    sa.Enum(name="entityoperation").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="feedbacksource").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="modelagenttype").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="threatsource").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="aiclassification").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="risklevel").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="filetype").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="fileanalysisstage").drop(op.get_bind(), checkfirst=True)
