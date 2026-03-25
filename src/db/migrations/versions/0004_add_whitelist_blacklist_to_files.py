"""Add whitelist/blacklist flags to files table.

Revision ID: 0004_add_whitelist_blacklist_files
Revises: 0003_add_whitelist_blacklist
Create Date: 2026-03-25 23:35:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0004_add_whitelist_files"
down_revision = "0003_add_whitelist_blacklist"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add whitelist/blacklist flags to files table
    op.add_column(
        "files",
        sa.Column("is_whitelisted", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "files",
        sa.Column("is_blacklisted", sa.Boolean(), nullable=False, server_default="false"),
    )
    
    # Add indexes for efficient filtering
    op.create_index(
        op.f("ix_files_is_whitelisted"),
        "files",
        ["is_whitelisted"],
        unique=False,
    )
    op.create_index(
        op.f("ix_files_is_blacklisted"),
        "files",
        ["is_blacklisted"],
        unique=False,
    )


def downgrade() -> None:
    # Drop indexes
    op.drop_index(op.f("ix_files_is_blacklisted"), table_name="files")
    op.drop_index(op.f("ix_files_is_whitelisted"), table_name="files")
    
    # Drop columns
    op.drop_column("files", "is_blacklisted")
    op.drop_column("files", "is_whitelisted")
