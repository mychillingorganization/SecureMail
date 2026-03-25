"""Add sender and receiver to scan_history.

Revision ID: 0005_scan_hist_sender_receiver
Revises: 0004_add_whitelist_files
Create Date: 2026-03-25 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0005_scan_hist_sender_receiver"
down_revision = "0004_add_whitelist_files"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scan_history", sa.Column("sender", sa.String(length=255), nullable=True))
    op.add_column("scan_history", sa.Column("receiver", sa.String(length=255), nullable=True))
    op.create_index(op.f("ix_scan_history_sender"), "scan_history", ["sender"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_scan_history_sender"), table_name="scan_history")
    op.drop_column("scan_history", "receiver")
    op.drop_column("scan_history", "sender")
