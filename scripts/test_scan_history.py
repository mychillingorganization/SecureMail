#!/usr/bin/env python3
"""
Test script to verify PostgreSQL scan history integration.
Run: python scripts/test_scan_history.py
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from orchestra.database import engine, SessionLocal
from orchestra.models import Base, ScanHistory
from orchestra.config import get_settings
from sqlalchemy import select
from datetime import datetime


async def test_database_connection():
    """Test database connection and table creation."""
    print("🔍 Testing PostgreSQL connection...")
    try:
        settings = get_settings()
        print(f"   Database URL: {settings.database_url}")

        # Create tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        print("   ✅ Tables created successfully")

        # Test write
        async with SessionLocal() as session:
            test_entry = ScanHistory(
                scan_mode="rule",
                file_name="test.eml",
                final_status="SAFE",
                issue_count=0,
                duration_ms=1234,
                execution_logs=["test log 1", "test log 2"],
                ai_classify="safe",
                ai_reason=None,
                ai_summary=None,
                ai_provider=None,
                ai_confidence_percent=None,
            )
            session.add(test_entry)
            await session.commit()
            print(f"   ✅ Test entry created with ID: {test_entry.id}")

            # Test read
            result = await session.execute(select(ScanHistory))
            entries = result.scalars().all()
            print(f"   ✅ Retrieved {len(entries)} entries from database")

            # Cleanup
            await session.delete(test_entry)
            await session.commit()
            print("   ✅ Test entry cleaned up")

    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

    return True


async def main():
    print("\n=== Scan History PostgreSQL Integration Test ===\n")

    success = await test_database_connection()

    if success:
        print("\n✅ All tests passed! PostgreSQL integration is ready.\n")
        print("Next steps:")
        print("1. Start the orchestrator: python orchestra/main.py")
        print("2. Upload a .eml file via the Email Scanner component")
        print("3. Verify scan results appear in the database and dashboard")
        return 0
    else:
        print("\n❌ Tests failed. Check your PostgreSQL setup.\n")
        print("Troubleshooting:")
        print("- Ensure PostgreSQL is running on localhost:5432")
        print("- Verify credentials in orchestra/config.py")
        print("- Check database 'securemail' exists and is accessible")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
