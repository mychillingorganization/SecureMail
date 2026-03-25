"""Initial orchestrator schema

Revision ID: 0001_init_schema
Revises: 
Create Date: 2026-03-22
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0001_init_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    email_status = sa.Enum("processing", "completed", "quarantined", name="emailstatus")
    verdict_type = sa.Enum("safe", "suspicious", "malicious", name="verdicttype")
    entity_status = sa.Enum("benign", "suspicious", "malicious", "unknown", name="entitystatus")

    op.create_table(
        "emails",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("message_id", sa.String(length=255), nullable=True),
        sa.Column("sender", sa.String(length=255), nullable=True),
        sa.Column("receiver", sa.String(length=255), nullable=True),
        sa.Column("status", email_status, nullable=False),
        sa.Column("total_risk_score", sa.Float(), nullable=False),
        sa.Column("final_verdict", verdict_type, nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), nullable=False),
        sa.Column("agent_name", sa.String(length=100), nullable=False),
        sa.Column("reasoning_trace", sa.JSON(), nullable=False),
        sa.Column("cryptographic_hash", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_logs_email_id", "audit_logs", ["email_id"])

    op.create_table(
        "domain_emails",
        sa.Column("domain_email", sa.String(length=255), primary_key=True),
        sa.Column("status", entity_status, nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "files",
        sa.Column("file_hash", sa.String(length=64), primary_key=True),
        sa.Column("status", entity_status, nullable=False),
        sa.Column("file_path", sa.String(length=1024), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "urls",
        sa.Column("url_hash", sa.String(length=64), primary_key=True),
        sa.Column("raw_url", sa.Text(), nullable=False),
        sa.Column("status", entity_status, nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "favicons",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("brand_name", sa.String(length=255), nullable=False),
        sa.Column("phash_value", sa.String(length=255), nullable=False),
    )

    op.create_table(
        "email_urls",
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("url_hash", sa.String(length=64), sa.ForeignKey("urls.url_hash", ondelete="CASCADE"), primary_key=True),
    )

    op.create_table(
        "email_files",
        sa.Column("email_id", sa.Integer(), sa.ForeignKey("emails.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("file_hash", sa.String(length=64), sa.ForeignKey("files.file_hash", ondelete="CASCADE"), primary_key=True),
    )


def downgrade() -> None:
    op.drop_table("email_files")
    op.drop_table("email_urls")
    op.drop_table("favicons")
    op.drop_table("urls")
    op.drop_table("files")
    op.drop_table("domain_emails")
    op.drop_index("ix_audit_logs_email_id", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_table("emails")

    sa.Enum(name="entitystatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="verdicttype").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="emailstatus").drop(op.get_bind(), checkfirst=True)
