"""Add whitelist/blacklist flags to urls and files tables.

Revision ID: 0003_add_whitelist_blacklist
Revises: 0002_enhance_schema
Create Date: 2026-03-25 23:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "0003_add_whitelist_blacklist"
down_revision = "0002_enhance_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add whitelist/blacklist flags to urls table
    op.add_column(
        "urls",
        sa.Column("is_whitelisted", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "urls",
        sa.Column("is_blacklisted", sa.Boolean(), nullable=False, server_default="false"),
    )
    
    # Add indexes for efficient filtering
    op.create_index(
        op.f("ix_urls_is_whitelisted"),
        "urls",
        ["is_whitelisted"],
        unique=False,
    )
    op.create_index(
        op.f("ix_urls_is_blacklisted"),
        "urls",
        ["is_blacklisted"],
        unique=False,
    )


def downgrade() -> None:
    # Drop indexes
    op.drop_index(op.f("ix_urls_is_blacklisted"), table_name="urls")
    op.drop_index(op.f("ix_urls_is_whitelisted"), table_name="urls")
    
    # Drop columns
    op.drop_column("urls", "is_blacklisted")
    op.drop_column("urls", "is_whitelisted")
