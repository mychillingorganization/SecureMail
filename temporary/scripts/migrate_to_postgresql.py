#!/usr/bin/env python3
"""
Comprehensive PostgreSQL migration script for SecureMail
Handles enum type conflicts and ensures clean migration
"""

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import subprocess
import sys

def run_migration():
    print("="*70)
    print("SecureMail PostgreSQL Migration")
    print("="*70)
    
    # Step 1: Clean up enum types if they exist (causes migration conflicts)
    print("\n[Step 1] Cleaning up conflicting enum types...")
    try:
        conn = psycopg2.connect(
            host="127.0.0.1",
            database="securemail",
            user="securemail",
            password="securemail"
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        
        with conn.cursor() as cur:
            # Drop enum types to avoid "already exists" conflicts
            for enum_type in ['emailstatus', 'verdicttype', 'entitystatus']:
                try:
                    cur.execute(f"DROP TYPE IF EXISTS {enum_type} CASCADE")
                    print(f"  ✓ Removed enum type: {enum_type}")
                except Exception as e:
                    print(f"  - {enum_type}: {e}")
        
        conn.close()
        print("  ✓ Cleanup complete")
    except psycopg2.errors.InvalidCatalogName:
        print("  - Database doesn't exist yet (will be created by migration)")
    except Exception as e:
        print(f"  ⚠ Warning: {e}")
    
    # Step 2: Run Alembic migration
    print("\n[Step 2] Running Alembic migration...")
    result = subprocess.run(
        [sys.executable, '-m', 'alembic', '-c', 'orchestra/alembic.ini', 'upgrade', 'head'],
        capture_output=True, text=True, timeout=60,
        cwd='/home/passla1/Desktop/SecureMail'
    )
    
    if result.returncode == 0:
        print("  ✓ Migration successful!")
    else:
        print(f"  ✗ Migration failed:")
        error_output = result.stderr if result.stderr else result.stdout
        # Show last part of error
        lines = error_output.split('\n')
        for line in lines[-20:]:
            if line.strip():
                print(f"    {line}")
        return False
    
    # Step 3: Verify schema
    print("\n[Step 3] Verifying schema...")
    try:
        conn = psycopg2.connect(
            host="127.0.0.1",
            database="securemail",
            user="securemail",
            password="securemail"
        )
        
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public'")
            table_count = cur.fetchone()[0]
            print(f"  ✓ Database has {table_count} tables")
            
            # List all tables
            cur.execute("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_schema='public' 
                ORDER BY table_name
            """)
            tables = [row[0] for row in cur.fetchall()]
            print(f"\n  Tables ({len(tables)}):")
            for table in tables:
                print(f"    - {table}")
        
        conn.close()
    except Exception as e:
        print(f"  ✗ Verification failed: {e}")
        return False
    
    # Step 4: Success message
    print("\n" + "="*70)
    print("✓ MIGRATION COMPLETE!")
    print("="*70)
    print("\nConnect to pgAdmin with these credentials:")
    print("  • Host: 127.0.0.1")
    print("  • Port: 5432")
    print("  • Database: securemail")
    print("  • Username: securemail")
    print("  • Password: securemail")
    print("\nYou can now browse all tables in pgAdmin!")
    print("="*70)
    
    return True

if __name__ == '__main__':
    try:
        success = run_migration()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nMigration cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
