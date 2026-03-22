"""002_redesigned_schema — Thiết kế lại schema database

Thay thế bảng emails/reasoning_traces/agent_scores/clawback_events cũ
bằng schema mới: emails, audit_logs, domain_emails, files, urls, favicons.

Revision ID: 002_redesigned_schema
Revises: 001_initial_schema
Create Date: 2026-03-17
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ENUM as pgEnum
from sqlalchemy.dialects.postgresql import JSONB, TEXT, UUID

revision = "002_redesigned_schema"
down_revision = "001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # === Xóa các bảng cũ (theo thứ tự FK) ===
    op.drop_index("idx_clawback_created_at", table_name="clawback_events")
    op.drop_index("idx_clawback_email_id", table_name="clawback_events")
    op.drop_table("clawback_events")

    op.drop_index("idx_agent_scores_email_agent", table_name="agent_scores")
    op.drop_index("idx_agent_scores_email_id", table_name="agent_scores")
    op.drop_table("agent_scores")

    op.drop_index("idx_reasoning_email_step", table_name="reasoning_traces")
    op.drop_index("idx_reasoning_traces_email_id", table_name="reasoning_traces")
    op.drop_table("reasoning_traces")

    op.drop_index("idx_emails_created_at", table_name="emails")
    op.drop_index("idx_emails_email_id", table_name="emails")
    op.drop_table("emails")

    # === Tạo PostgreSQL ENUM types (idempotent: drop-then-create) ===
    op.execute(sa.text("DROP TYPE IF EXISTS emailstatusenum"))
    op.execute(sa.text(
        "CREATE TYPE emailstatusenum AS ENUM ('processing', 'completed', 'quarantined')"
    ))
    op.execute(sa.text("DROP TYPE IF EXISTS verdicttypeenum"))
    op.execute(sa.text(
        "CREATE TYPE verdicttypeenum AS ENUM ('safe', 'suspicious', 'malicious')"
    ))
    op.execute(sa.text("DROP TYPE IF EXISTS intelligencestatusenum"))
    op.execute(sa.text(
        "CREATE TYPE intelligencestatusenum AS ENUM ('benign', 'suspicious', 'malicious', 'unknown')"
    ))

    # === Tạo bảng emails mới ===
    op.create_table(
        "emails",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("message_id", sa.String, nullable=True),
        sa.Column("sender", sa.String, nullable=False),
        sa.Column("receiver", sa.String, nullable=False),
        sa.Column("status", pgEnum("processing", "completed", "quarantined",
                    name="emailstatusenum", create_type=False), nullable=True),
        sa.Column("total_risk_score", sa.Float, nullable=True),
        sa.Column("final_verdict", pgEnum("safe", "suspicious", "malicious",
                    name="verdicttypeenum", create_type=False), nullable=True),
        sa.Column("processed_at", sa.DateTime, nullable=True),
    )
    op.create_index("idx_emails_message_id", "emails", ["message_id"])

    # === Tạo bảng audit_logs ===
    op.create_table(
        "audit_logs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("email_id", UUID(as_uuid=True), sa.ForeignKey("emails.id"), nullable=False),
        sa.Column("agent_name", sa.String, nullable=False),
        sa.Column("reasoning_trace", JSONB, nullable=False),
        sa.Column("cryptographic_hash", sa.String, nullable=False),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("idx_audit_logs_email_id", "audit_logs", ["email_id"])

    # === Tạo bảng intelligence ===
    op.create_table(
        "domain_emails",
        sa.Column("domain_email", sa.String, primary_key=True),
        sa.Column("status", pgEnum("benign", "suspicious", "malicious", "unknown",
                    name="intelligencestatusenum", create_type=False), nullable=True),
        sa.Column("last_seen", sa.DateTime, server_default=sa.func.now()),
    )

    op.create_table(
        "files",
        sa.Column("file_hash", sa.String, primary_key=True),
        sa.Column("status", pgEnum("benign", "suspicious", "malicious", "unknown",
                    name="intelligencestatusenum", create_type=False), nullable=True),
        sa.Column("file_path", sa.String, nullable=True),
        sa.Column("last_seen", sa.DateTime, server_default=sa.func.now()),
    )

    op.create_table(
        "urls",
        sa.Column("url_hash", sa.String, primary_key=True),
        sa.Column("raw_url", TEXT, nullable=False),
        sa.Column("status", pgEnum("benign", "suspicious", "malicious", "unknown",
                    name="intelligencestatusenum", create_type=False), nullable=True),
        sa.Column("last_seen", sa.DateTime, server_default=sa.func.now()),
    )

    op.create_table(
        "favicons",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("brand_name", sa.String, nullable=False),
        sa.Column("phash_value", sa.String, nullable=False),
    )
    op.create_index("idx_favicons_brand_name", "favicons", ["brand_name"])

    # === Junction tables ===
    op.create_table(
        "email_urls",
        sa.Column("email_id", UUID(as_uuid=True), sa.ForeignKey("emails.id"), primary_key=True),
        sa.Column("url_hash", sa.String, sa.ForeignKey("urls.url_hash"), primary_key=True),
    )

    op.create_table(
        "email_files",
        sa.Column("email_id", UUID(as_uuid=True), sa.ForeignKey("emails.id"), primary_key=True),
        sa.Column("file_hash", sa.String, sa.ForeignKey("files.file_hash"), primary_key=True),
    )


def downgrade() -> None:
    op.drop_table("email_files")
    op.drop_table("email_urls")
    op.drop_index("idx_favicons_brand_name", table_name="favicons")
    op.drop_table("favicons")
    op.drop_table("urls")
    op.drop_table("files")
    op.drop_table("domain_emails")
    op.drop_index("idx_audit_logs_email_id", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("idx_emails_message_id", table_name="emails")
    op.drop_table("emails")

    # Drop ENUM types
    op.execute(sa.text("DROP TYPE IF EXISTS emailstatusenum"))
    op.execute(sa.text("DROP TYPE IF EXISTS verdicttypeenum"))
    op.execute(sa.text("DROP TYPE IF EXISTS intelligencestatusenum"))

    # Recreate schema từ revision 001
    op.create_table(
        "emails",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("email_id", sa.String(255), nullable=False, unique=True),
        sa.Column("sender", sa.String(255)),
        sa.Column("recipient", sa.String(255)),
        sa.Column("subject", sa.Text),
        sa.Column("verdict", sa.String(20), nullable=False),
        sa.Column("risk_score", sa.Float, nullable=False),
        sa.Column("confidence", sa.Float),
        sa.Column("early_terminated", sa.Boolean),
        sa.Column("processing_time_ms", sa.Float),
        sa.Column("raw_request", JSONB),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("idx_emails_email_id", "emails", ["email_id"])
    op.create_index("idx_emails_created_at", "emails", ["created_at"])

    op.create_table(
        "reasoning_traces",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("email_id", sa.String(255), sa.ForeignKey("emails.email_id"), nullable=False),
        sa.Column("step", sa.Integer, nullable=False),
        sa.Column("phase", sa.String(20), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("data", JSONB),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("idx_reasoning_traces_email_id", "reasoning_traces", ["email_id"])
    op.create_index("idx_reasoning_email_step", "reasoning_traces", ["email_id", "step"])

    op.create_table(
        "agent_scores",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("email_id", sa.String(255), sa.ForeignKey("emails.email_id"), nullable=False),
        sa.Column("agent_name", sa.String(50), nullable=False),
        sa.Column("risk_score", sa.Float, nullable=False),
        sa.Column("confidence", sa.Float),
        sa.Column("details", JSONB),
        sa.Column("processing_time_ms", sa.Float),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("idx_agent_scores_email_id", "agent_scores", ["email_id"])
    op.create_index("idx_agent_scores_email_agent", "agent_scores", ["email_id", "agent_name"])

    op.create_table(
        "clawback_events",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("email_id", sa.String(255), sa.ForeignKey("emails.email_id"), nullable=False),
        sa.Column("original_verdict", sa.String(20), nullable=False),
        sa.Column("new_verdict", sa.String(20), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("created_by", sa.String(100)),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("idx_clawback_email_id", "clawback_events", ["email_id"])
    op.create_index("idx_clawback_created_at", "clawback_events", ["created_at"])
