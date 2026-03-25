"""Compatibility wrapper for migrated DB persistence helpers.

Canonical persistence module now lives in src.db.db_utils.
"""

from src.db.db_utils import *  # noqa: F401,F403
