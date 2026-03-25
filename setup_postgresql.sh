#!/bin/bash
# Setup PostgreSQL database and run Alembic migration

set -e

echo "Setting up PostgreSQL database for SecureMail..."

# Create the database
echo "Creating database 'securemail'..."
sudo -u postgres psql -c "DROP DATABASE IF EXISTS securemail;" || true
sudo -u postgres psql -c "CREATE DATABASE securemail OWNER securemail;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE securemail TO securemail;"

echo "✓ Database created successfully"

# Run Alembic migration
echo "Running Alembic migration..."
cd "$(dirname "$0")"
python -m alembic -c orchestra/alembic.ini upgrade head

echo "✓ Migration completed successfully"
echo ""
echo "Connect to pgAdmin with:"
echo "  Host: 127.0.0.1"
echo "  Port: 5432"
echo "  Database: securemail"
echo "  Username: securemail"
echo "  Password: securemail"
