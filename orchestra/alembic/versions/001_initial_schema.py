"""001_initial_schema — Tạo schema ban đầu

Revision ID: 001
Create Date: 2026-03-08
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # === Bảng emails ===
    op.create_table(
        "emails",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("email_id", sa.String(255), nullable=False, unique=True),
        sa.Column("sender", sa.String(255)),
        sa.Column("recipient", sa.String(255)),
        sa.Column("subject", sa.Text),
        sa.Column("verdict", sa.String(20), nullable=False),
        sa.Column("risk_score", sa.Float, nullable=False),
        sa.Column("confidence", sa.Float, default=0.0),
        sa.Column("early_terminated", sa.Boolean, default=False),
        sa.Column("processing_time_ms", sa.Float),
        sa.Column("raw_request", JSONB),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("idx_emails_email_id", "emails", ["email_id"])
    op.create_index("idx_emails_created_at", "emails", ["created_at"])

    # === Bảng reasoning_traces ===
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

    # === Bảng agent_scores ===
    op.create_table(
        "agent_scores",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("email_id", sa.String(255), sa.ForeignKey("emails.email_id"), nullable=False),
        sa.Column("agent_name", sa.String(50), nullable=False),
        sa.Column("risk_score", sa.Float, nullable=False),
        sa.Column("confidence", sa.Float, default=0.0),
        sa.Column("details", JSONB),
        sa.Column("processing_time_ms", sa.Float),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("idx_agent_scores_email_id", "agent_scores", ["email_id"])
    op.create_index("idx_agent_scores_email_agent", "agent_scores", ["email_id", "agent_name"])

    # === Bảng clawback_events ===
    op.create_table(
        "clawback_events",
        sa.Column("id", UUID(as_uuid=False), primary_key=True),
        sa.Column("email_id", sa.String(255), sa.ForeignKey("emails.email_id"), nullable=False),
        sa.Column("original_verdict", sa.String(20), nullable=False),
        sa.Column("new_verdict", sa.String(20), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("created_by", sa.String(100), default="system"),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index("idx_clawback_email_id", "clawback_events", ["email_id"])
    op.create_index("idx_clawback_created_at", "clawback_events", ["created_at"])


def downgrade() -> None:
    op.drop_table("clawback_events")
    op.drop_table("agent_scores")
    op.drop_table("reasoning_traces")
    op.drop_table("emails")
