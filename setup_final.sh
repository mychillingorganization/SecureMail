#!/bin/bash
# SecureMail PostgreSQL Setup Script
# This script must be run interactively with your sudo password

set -e

echo "=========================================="
echo "SecureMail PostgreSQL Setup"
echo "=========================================="

# Step 1: Create database as postgres superuser
echo ""
echo "[Step 1] Creating PostgreSQL database..."
echo "Enter your sudo password when prompted:"
echo ""

sudo -u postgres psql << EOF
-- Grant CREATE privilege to securemail role
ALTER ROLE securemail CREATEDB;

-- Drop existing database if it exists
DROP DATABASE IF EXISTS securemail;

-- Create fresh database
CREATE DATABASE securemail OWNER securemail;
GRANT ALL PRIVILEGES ON DATABASE securemail TO securemail;

-- Verify
\c securemail
\conninfo

EOF

echo "✓ Database created successfully"

# Step 2: Run Alembic migration
echo ""
echo "[Step 2] Running Alembic migration to create schema..."
cd "$(dirname "$0")"

python -m alembic -c orchestra/alembic.ini upgrade head

echo ""
echo "=========================================="
echo "✓ SETUP COMPLETE!"
echo "=========================================="
echo ""
echo "Connect to pgAdmin with:"
echo "  Host: 127.0.0.1"
echo "  Port: 5432"
echo "  Database: securemail"
echo "  Username: securemail"
echo "  Password: securemail"
echo ""
echo "=========================================="
