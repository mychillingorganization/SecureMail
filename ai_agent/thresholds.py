"""
Centralized thresholds and weights for AI Agent decision-making.
This file defines all risk scores, classification thresholds, and weights used by tools.py.
"""

# ============================================================================
# Signal Detection Thresholds (used by tool_*_signal functions)
# ============================================================================

# Email signal detection
EMAIL_RISK_SIGNAL_THRESHOLD = 0.5  # Email marked suspicious if risk_score >= this
EMAIL_SUSPICIOUS_LABELS = {"phishing", "malicious", "suspicious"}

# File signal detection
FILE_RISK_SIGNAL_THRESHOLD = 0.4  # Attachment item marked suspicious if risk_score >= this
FILE_SUSPICIOUS_LABELS = {"malicious", "phishing", "suspicious"}
FILE_DANGEROUS_RISK_LEVELS = {"high", "critical"}

# Web signal detection
WEB_RISK_SIGNAL_THRESHOLD = 0.5  # URL marked suspicious if risk_score >= this
WEB_SUSPICIOUS_LABELS = {"phishing", "malicious", "suspicious"}

# ============================================================================
# Authentication Penalty Weights (used in tool_risk_rollup)
# ============================================================================

# Penalty weights added to composite_risk when auth checks fail
AUTH_PENALTY_SPF_FAIL = 0.8
AUTH_PENALTY_DKIM_FAIL = 0.8
AUTH_PENALTY_DMARC_FAIL = 1.0

# ============================================================================
# Provisional Status Weights (used in tool_risk_rollup)
# ============================================================================

# Additional weight if provisionally flagged as DANGER by orchestrator
PROVISIONAL_DANGER_WEIGHT = 1.0

# ============================================================================
# Risk Rollup and Composite Risk Thresholds
# ============================================================================

# Composite risk score interpretation for final classification
COMPOSITE_RISK_DANGEROUS_THRESHOLD = 2.5  # High risk: escalate verdict
COMPOSITE_RISK_SUSPICIOUS_THRESHOLD = 1.0  # Moderate risk: flag for review

# ============================================================================
# Fallback Heuristic Thresholds (used when autonomous LLM decision fails)
# ============================================================================

# Minimum danger reasons count to escalate in fallback mode
MIN_DANGER_REASONS_TO_ESCALATE = 2

# ============================================================================
# Failure Recovery Policy
# ============================================================================

# Maximum consecutive failures before falling back to simple heuristic
MAX_AUTONOMOUS_ATTEMPTS = 3
MAX_TOOL_STEPS_PER_ATTEMPT = 6

# Backoff strategy for LLM retries (seconds)
RETRY_BACKOFF_SECONDS = 1.5

# ============================================================================
# LLM Provider Settings (Gemini)
# ============================================================================

# Temperature for deterministic outputs (low = more consistent)
LLM_TEMPERATURE = 0.2

# Request timeout for LLM API calls (seconds)
LLM_REQUEST_TIMEOUT_SECONDS = 20.0

# ============================================================================
# Multi-Tool Policy (enforced to avoid single-tool bias)
# ============================================================================

# Core signal tools that MUST be called before final synthesis
MANDATORY_SIGNAL_TOOLS = {
    "auth_summary",
    "email_signal",
    "file_signal",
    "web_signal",
}

# Synthesis tool that MUST be called after signals
MANDATORY_SYNTHESIS_TOOL = "risk_rollup"

# Minimum number of distinct tools required for valid autonomous path
MIN_TOOL_DIVERSITY = 5  # At least: 4 signals + risk_rollup (optionally url_domains)

# ============================================================================
# Classify Values (new schema contract)
# ============================================================================

CLASSIFY_SAFE = "safe"
CLASSIFY_SUSPICIOUS = "suspicious"
CLASSIFY_DANGEROUS = "dangerous"

VALID_CLASSIFY_VALUES = {CLASSIFY_SAFE, CLASSIFY_SUSPICIOUS, CLASSIFY_DANGEROUS}

# Confidence score ranges for classification (%)
DEFAULT_CONFIDENCE_SAFE = 75
DEFAULT_CONFIDENCE_SUSPICIOUS = 70
DEFAULT_CONFIDENCE_DANGEROUS = 85
