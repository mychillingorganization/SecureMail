"""
Centralized thresholds for orchestrator pipeline decision-making.
Defines risk interpretation, escalation rules, and issue counting logic.
"""

# ============================================================================
# Email Agent Signal Thresholds
# ============================================================================

# Email agent risk score threshold to increment issue_count
EMAIL_AGENT_SUSPICIOUS_THRESHOLD = 0.8

# Email-specific risk labels that trigger escalation
EMAIL_AGENT_MALICIOUS_LABELS = {"malicious", "phishing"}

# ============================================================================
# File Agent Signal Thresholds
# ============================================================================

# File agent risk score threshold to halt and escalate to DANGER
FILE_AGENT_MALICIOUS_RISK_SCORE = 0.7

# File agent risk levels that halt and escalate
FILE_AGENT_DANGEROUS_RISK_LEVELS = {"high", "critical"}

# File agent labels that halt and escalate
FILE_AGENT_MALICIOUS_LABELS = {"malicious", "phishing"}

# ============================================================================
# Web Agent Signal Thresholds
# ============================================================================

# Web agent risk score threshold to increment issue_count
WEB_AGENT_SUSPICIOUS_THRESHOLD = 0.5

# Web agent labels that halt and escalate
WEB_AGENT_MALICIOUS_LABELS = {"malicious", "phishing"}

# ============================================================================
# Issue Count to Verdict Mapping
# ============================================================================

# Issue count escalation levels
ISSUE_COUNT_PASS = 0        # No issues → PASS
ISSUE_COUNT_WARNING = 1     # 1 issue → WARNING
ISSUE_COUNT_DANGER = 2      # 2+ issues → DANGER

# ============================================================================
# AI Agent (LLM Deepdive) Integration
# ============================================================================

# Maximum retry attempts when calling AI Agent
AI_AGENT_RETRY_ATTEMPTS = 2

# Backoff strategy for AI Agent retries (seconds)
AI_AGENT_RETRY_BACKOFF_SECONDS = 0.5

# Request timeout for AI Agent calls (seconds) — longer than other agents
AI_AGENT_TIMEOUT_SECONDS = 180.0

# LLM escalation policy: should_escalate + confidence threshold
LLM_ESCALATION_CONFIDENCE_THRESHOLD_PERCENT = 70

# ============================================================================
# Authentication Protocol Verification Thresholds
# ============================================================================

# If SPF/DKIM/DMARC all pass, auth is safe
AUTH_REQUIRES_ALL_PASS = True

# Count auth failure as an issue
AUTH_FAILURE_IS_ISSUE = True

# ============================================================================
# Threat Intelligence Integration
# ============================================================================

# Malicious file hashes (SHA-256) that are always quarantined
# Format: comma-separated list in settings, overridable per env
THREAT_INTEL_MALICIOUS_HASHES = ""  # Populated from SECUREMAIL_THREAT_INTEL_MALICIOUS_HASHES env

# ============================================================================
# Generic Agent Timeouts
# ============================================================================

# Default timeout for email/file/web agents
DEFAULT_AGENT_TIMEOUT_SECONDS = 20.0

# ============================================================================
# CORS and API Configuration
# ============================================================================

# Allowed origins for CORS (comma-separated, set via env)
CORS_ALLOW_ORIGINS = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174,http://localhost:8080,http://127.0.0.1:8080"

# ============================================================================
# Feature Flags (Future use)
# ============================================================================

# Count file agent unavailability as an issue in pipeline
COUNT_FILE_AGENT_UNAVAILABLE_AS_ISSUE = False
