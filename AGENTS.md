# SecureMail Agent Handoff

Last updated: 2026-03-19

## Purpose
SecureMail is a multi-agent email security system that classifies inbound emails using protocol analysis, URL analysis, and attachment analysis, then produces a final verdict through the orchestrator.

## Source-of-Truth Order (Important)
When docs and code conflict, trust this order:
1. `docker-compose.yml` (runtime ports, wiring, env contracts)
2. `orchestra/pipeline.py` and `orchestra/main.py` (actual orchestration behavior)
3. `orchestra/risk_scorer.py` and `orchestra/early_termination.py` (decision logic)
4. Agent `main.py` files (real exposed capability)
5. `README.md` (intent and overview; may drift)

## Current Implementation Snapshot

### Implemented and usable
- **Orchestrator (`orchestra/`)**
  - FastAPI entrypoint and lifecycle setup.
  - ReAct-style flow: PERCEIVE → REASON → ACT → OBSERVE → REASON.
  - Conditional fan-out: always calls email agent, calls file/web only when needed.
  - Composite scoring and verdict generation.
- **Web Agent (`web_agent/`)**
  - URL analysis with model inference + SSL signal fusion.
  - Input validation via Pydantic schemas.
  - Health endpoint and analysis endpoints are implemented.
- **Infrastructure**
  - Compose stack includes orchestrator, email agent, file agent (stub), web agent, Redis, Postgres, Ollama, ClamAV.
- **Redis Bus (`orchestra/redis_bus.py`)**
  - Pub/sub and request-response utility is implemented and recently hardened.
  - Timeout handling now uses bounded polling with a hard deadline.
  - Request-response path validates `request_id` matching (with legacy fallback when absent).
  - Subscribe path includes safer cleanup in `finally`.

### Stubbed or incomplete
- **Email Agent (`email_agent/main.py`)** currently returns fixed/dummy analysis payloads.
- **File Agent (`stubs/file_agent_stub.py`)** is placeholder logic (fixed risk behavior).
- Empty modules:
  - `email_agent/guardrails.py`
  - `email_agent/typosquat_detector.py`
  - `email_agent/config.py`

## Runtime and Interfaces
- Orchestrator external port is **8080** in compose.
- Internal service URLs are configured via env:
  - Email agent: `http://email-agent:8000`
  - File agent: `http://file-agent:8001`
  - Web agent: `http://web-agent:8002`
- Main endpoints:
  - Orchestrator: `POST /api/v1/scan`, `GET /health`
  - Agents: `POST /api/v1/analyze`, `GET /health`
- Redis bus channel prefixes:
  - `agent:email`, `agent:file`, `agent:web`, `orchestrator`

## Decision Logic (Current)
- Composite score uses weighted sum with redistribution when an agent is absent.
- Default thresholds:
  - `SAFE` if score < 0.4
  - `SUSPICIOUS` if 0.4 <= score < 0.7
  - `MALICIOUS` if score >= 0.7
- Early termination condition:
  - SPF + DKIM + DMARC all fail **and** email confidence > 0.95.

## Known Drift / Caveats
- Some README claims are aspirational compared to current code state.
- Port examples in docs may not match compose (verify before use).
- Because email/file paths are stubbed, final orchestrator verdict quality is limited.
- Orchestrator pipeline currently uses HTTP agent calls as primary execution path; Redis bus is available utility but not the main call path in `pipeline.py`.

## Testing Status (Latest)
- `orchestra/tests/test_redis_bus.py` passes (9 tests).
- Coverage includes: connect/init guards, timeout behavior, request-id matching behavior, and legacy response compatibility.
- Existing warning: test helper uses `asyncio.get_event_loop()` pattern (non-blocking for now, but can be modernized later).

## Recommended Agent Priorities
1. Replace `email_agent/main.py` stub path with real protocol + guardrails + LLM orchestration.
2. Implement `email_agent/config.py`, `guardrails.py`, `typosquat_detector.py`.
3. Replace `stubs/file_agent_stub.py` with a real file scanning service.
4. Add contract tests to freeze request/response schemas across services.
5. Add integration tests for happy path and degraded dependency modes.

## Quick Verification Checklist
- `docker compose config` passes.
- All `/health` endpoints return healthy.
- Orchestrator always invokes email; file/web remain conditional.
- Scoring thresholds and early-termination threshold match runtime settings.
- No production execution path depends on static stub payloads.
- Redis bus request-response calls time out deterministically and do not block indefinitely.
