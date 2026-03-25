"""Compatibility wrapper for migrated DB models.

Canonical models now live in src.db.models.
"""

from src.db.models import *  # noqa: F401,F403
