# PostgreSQL Scan History Integration

## Overview

This document describes how the Email Scanner component now persists scan results to PostgreSQL for historical tracking, analytics, and dashboard metrics.

## Architecture

### Data Flow

```
User uploads .eml via EmailScanner
        ↓
POST /api/v1/scan-upload or /api/v1/scan-upload-llm
        ↓
Orchestrator processes scan (rule or LLM mode)
        ↓
Returns ScanResponse with results
        ↓
EmailScanner calculates duration & calls POST /api/v1/scan-history
        ↓
Backend saves ScanHistory entry to PostgreSQL
        ↓
Dashboard fetches via GET /api/v1/scan-history
        ↓
Displays real aggregated metrics (no hardcoded values)
```

## Backend Features

### Database Model (`orchestra/models.py`)

The `ScanHistory` table stores:
- `id` (UUID): Unique identifier
- `timestamp` (DateTime): When scan was saved
- `scan_mode` (str): "rule" or "llm"
- `file_name` (str): Original .eml filename
- `final_status` (str): Result status (SAFE, SUSPICIOUS, DANGER, etc.)
- `issue_count` (int): Number of issues detected
- `duration_ms` (int): How long the scan took
- `termination_reason` (str): Why scan stopped (if applicable)
- `ai_classify`, `ai_reason`, `ai_summary`, `ai_provider`, `ai_confidence_percent`: LLM analysis details
- `execution_logs` (JSON): List of log messages from scan
- `ai_cot_steps` (JSON): LLM chain-of-thought steps

### API Endpoints

#### Save Scan Result
```
POST /api/v1/scan-history
Content-Type: application/json

{
  "scan_mode": "llm",
  "file_name": "email.eml",
  "final_status": "SAFE",
  "issue_count": 0,
  "duration_ms": 1234,
  "termination_reason": null,
  "ai_classify": "safe",
  "ai_reason": null,
  "ai_summary": null,
  "ai_provider": "Gemini",
  "ai_confidence_percent": 95,
  "execution_logs": ["log 1", "log 2"],
  "ai_cot_steps": []
}

Response (201):
{
  "id": "539890a6-8314-45ea-81a4-f09fe37303ed",
  "timestamp": "2026-03-25T12:34:56.789Z",
  ...all fields returned...
}
```

#### Fetch Scan History
```
GET /api/v1/scan-history?limit=50&scan_mode=llm

Response (200):
[
  {
    "id": "539890a6-8314-45ea-81a4-f09fe37303ed",
    "timestamp": "2026-03-25T12:34:56.789Z",
    "scan_mode": "llm",
    "file_name": "email.eml",
    "final_status": "SAFE",
    "issue_count": 0,
    "duration_ms": 1234,
    ...
  },
  ...
]
```

Query Parameters:
- `limit` (int, default=50, max=500): Maximum records to return
- `scan_mode` (str, optional): Filter by "rule" or "llm"

Results are ordered by most recent first.

## Frontend Features

### API Utility (`UI-UX/src/app/api/scanHistory.ts`)

```typescript
// Save a completed scan to the database
await saveScanToHistory({
  scan_mode: "llm",
  file_name: "email.eml",
  final_status: "SAFE",
  issue_count: 0,
  duration_ms: 1234,
  // ... all ScanResponse fields
});

// Fetch history from database
const history = await fetchScanHistory(
  50,           // limit
  "llm"         // optional scan_mode filter
);
```

### Custom React Hooks

#### `useScanHistory`
```typescript
import { useScanHistory } from "@/app/hooks/useScanHistory";

function MyComponent() {
  const { history, isLoading, error, refresh } = useScanHistory(
    50,        // limit
    "rule"     // optional scan_mode filter
  );

  // history: ScanHistoryItem[] (sorted by newest first)
  // isLoading: boolean
  // error: Error | null
  // refresh: () => Promise<void>
}
```

**Auto-polling**: Refreshes every 10 seconds automatically. Call `refresh()` manually to force immediate update.

#### `useDashboardMetrics`
```typescript
import { useDashboardMetrics } from "@/app/hooks/useDashboardMetrics";

function Dashboard() {
  const { metrics, isLoading, error, rawHistory } = useDashboardMetrics();

  const {
    totalScans,       // total number of scans in history
    avgScanDuration,  // average duration in ms (rounded)
    avgIssueCount,    // average issues per scan
    dangerousScans,   // percentage of scans with DANGER status
    lastScanTime,     // ISO timestamp of most recent scan
  } = metrics;
}
```

### EmailScanner Component Integration

The `EmailScanner` component now:
1. Tracks upload start: `const uploadStartTime = Date.now();`
2. Calculates duration: `const durationMs = Date.now() - uploadStartTime;`
3. After successful scan, calls `saveScanToHistory()` with all result fields
4. Non-blocking: if history save fails, scan results still display to user

## Configuration

### Environment Variables

Set `VITE_API_BASE_URL` in `.env` to override the default API endpoint:

```bash
# .env file in UI-UX directory
VITE_API_BASE_URL=http://localhost:8080
```

Default: `http://localhost:8080`

### Database URL

PostgreSQL connection string configured in `orchestra/config.py`:

```python
database_url: str = "postgresql+asyncpg://securemail:securemail@localhost:5432/securemail"
```

Can be overridden with environment variable:
```bash
export SECUREMAIL_DATABASE_URL="postgresql+asyncpg://user:pass@host:5432/db"
```

## Migration & Setup

### Automatic Table Creation

The orchestrator app automatically creates tables on startup via its lifespan handler:

```python
@asynccontextmanager
async def lifespan(_app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
```

Just ensure PostgreSQL is running and accessible.

### Manual Testing

Run the included test script:

```bash
python scripts/test_scan_history.py
```

Output:
```
✅ Tables created successfully
✅ Test entry created with ID: ...
✅ Retrieved 1 entries from database
✅ Test entry cleaned up

✅ All tests passed! PostgreSQL integration is ready.
```

## Running the Stack

### 1. Start PostgreSQL
```bash
# Ensure PostgreSQL is running on localhost:5432
# or configure SECUREMAIL_DATABASE_URL environment variable
```

### 2. Start Backend (Orchestrator)
```bash
cd /home/passla1/Desktop/SecureMail
source .venv/bin/activate
python orchestra/main.py
```

Orchestrator runs on: `http://localhost:8080`

### 3. Start Frontend (Dev Server)
```bash
cd UI-UX
npm run dev
```

Frontend runs on: `http://localhost:5173` (or check console output)

### 4. Use Email Scanner
- Navigate to `/scanner` route
- Upload a .eml file
- Run scan (Rule-based or LLM Deep Dive)
- Result is automatically saved to PostgreSQL
- History becomes available in Dashboard KPIs

## Monitoring Scan History

### Via PostgreSQL CLI

```bash
# Connect to PostgreSQL
psql postgresql://securemail:securemail@localhost:5432/securemail

# View all scans
SELECT id, timestamp, scan_mode, file_name, final_status, issue_count, duration_ms 
FROM scan_history 
ORDER BY timestamp DESC 
LIMIT 10;

# View LLM scans only
SELECT * FROM scan_history WHERE scan_mode = 'llm' ORDER BY timestamp DESC;

# Get statistics
SELECT 
  scan_mode, 
  COUNT(*) as total_scans,
  AVG(duration_ms) as avg_duration_ms,
  AVG(issue_count) as avg_issues,
  MAX(timestamp) as latest_scan
FROM scan_history 
GROUP BY scan_mode;
```

### Via Dashboard UI

The Dashboard component will display real metrics computed from scan history:
- **Processing Speed**: Average scan duration (replaced hardcoded value)
- **Average Issues**: Mean issue count per scan (replaced hardcoded value)
- **Error Rate**: Percentage of scans with DANGER status (replaced hardcoded value)
- **Activity Table**: Recent scans from history (replaces mock entries)
- **Latency Chart**: Volume by day from real history (replaces mock data)

## Troubleshooting

### PostgreSQL Connection Error
```
Error: could not connect to server: Connection refused
```

**Solution:**
1. Ensure PostgreSQL is running: `sudo systemctl start postgresql`
2. Verify connection string in `orchestra/config.py`
3. Check database exists: `psql -l | grep securemail`
4. Create database if missing:
   ```bash
   psql -U postgres -c "CREATE DATABASE securemail;"
   psql -U postgres -c "GRANT ALL ON DATABASE securemail TO securemail;"
   ```

### Table Doesn't Exist
```
psycopg2.errors.UndefinedTable: relation "scan_history" does not exist
```

**Solution:**
- Restart orchestrator to trigger lifespan handler
- Or manually run: `python scripts/test_scan_history.py`

### Scans Not Showing in Dashboard

**Check:**
1. Frontend is fetching: Open browser DevTools → Network tab → look for `GET /api/v1/scan-history`
2. Scans in database: Run SQL query above
3. Hook is mounted: Dashboard.tsx imports `useDashboardMetrics`
4. Frontend build succeeded: `npm run build` shows no errors

## Future Enhancements

- Add retention policy (e.g., keep last 90 days)
- Add export to CSV/JSON
- Add search/filter UI
- Add metrics API endpoints (aggregated stats)
- Add real-time WebSocket updates
- Add per-user scan history tracking (with auth)
- Add batch deletion/archival

## Files Modified

- **Backend**:
  - `orchestra/models.py` - Added ScanHistory model
  - `orchestra/schemas.py` - Added ScanHistoryCreate, ScanHistoryResponse schemas
  - `orchestra/main.py` - Added POST/GET endpoints, updated imports
  - `scripts/test_scan_history.py` - New test script

- **Frontend**:
  - `UI-UX/src/app/api/scanHistory.ts` - New API utility
  - `UI-UX/src/app/components/EmailScanner.tsx` - Added history saving
  - `UI-UX/src/app/hooks/useScanHistory.ts` - New hook for fetching
  - `UI-UX/src/app/hooks/useDashboardMetrics.ts` - New hook for KPI computation

## Summary

The PostgreSQL scan history integration provides:
- ✅ Persistent storage of all scan results
- ✅ Multi-device accessible history
- ✅ Real aggregated metrics for dashboard
- ✅ Foundation for analytics and compliance audit trails
- ✅ Scalable architecture for future features
