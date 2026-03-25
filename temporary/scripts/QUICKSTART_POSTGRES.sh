#!/bin/bash
# Quick Start Guide for PostgreSQL-Backed Email Scanner

echo "=== SecureMail: PostgreSQL Scan History Quick Start ==="
echo ""

# Check PostgreSQL
echo "✓ Step 1: Verify PostgreSQL is running..."
if psql -U securemail -d securemail -c "SELECT 1" 2>/dev/null; then
    echo "  ✅ PostgreSQL is running"
else
    echo "  ⚠️  PostgreSQL may not be running. Connection failed."
    echo "  Start it with: sudo systemctl start postgresql"
fi
echo ""

# Test database
echo "✓ Step 2: Testing database setup..."
if python scripts/test_scan_history.py 2>&1 | grep -q "All tests passed"; then
    echo "  ✅ Database is ready"
else
    echo "  ⚠️  Database test had issues. Check details above."
fi
echo ""

echo "✓ Step 3: Start the orchestrator backend"
echo "  Command: cd /home/passla1/Desktop/SecureMail && source .venv/bin/activate && python orchestra/main.py"
echo "  Runs at: http://localhost:8080"
echo ""

echo "✓ Step 4: Start the frontend (in another terminal)"
echo "  Command: cd /home/passla1/Desktop/SecureMail/UI-UX && npm run dev"
echo "  Runs at: http://localhost:5173 (or as shown in output)"
echo ""

echo "✓ Step 5: Use the scanner"
echo "  1. Open http://localhost:5173 in browser"
echo "  2. Navigate to /scanner route"
echo "  3. Upload a .eml file"
echo "  4. Choose scan mode (Rule-Based or LLM Deep Dive)"
echo "  5. Click 'Scan Email'"
echo "  6. Result is automatically saved to PostgreSQL"
echo "  7. View historical results in Dashboard"
echo ""

echo "=== Key Features ==="
echo "• All scan results persisted in PostgreSQL"
echo "• Dashboard metrics computed from real history"
echo "• Multi-device accessible via API"
echo "• Automatic polling every 10 seconds"
echo "• Full audit trail of all email scans"
echo ""

echo "=== Documentation ==="
echo "📖 See: POSTGRESQL_SCAN_HISTORY.md"
echo ""
