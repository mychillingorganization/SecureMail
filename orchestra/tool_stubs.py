"""
Tool Stubs — Stub implementations cho 3 công cụ trực tiếp của Orchestrator.

Khi triển khai thực tế, thay thế các hàm này bằng tích hợp thực:
- parse_eml → gọi utils.parse_eml thật
- check_auth → gọi protocol_verifier thật
- scan_hash → gọi threat_intel + VirusTotal thật

Xem AGENT_INTEGRATION_GUIDE.md để biết chi tiết.
"""

import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)


def parse_eml(file_path: str) -> dict[str, Any]:
    """
    STUB: utils.parse_eml(file_path)
    Ingests an .eml file and returns extracted components.

    Real implementation: call the actual parser at utils/parse_eml.py

    Returns:
        {
            "urls": ["http://example.com", ...],
            "content": {"subject": "...", "body_text": "...", "body_html": "..."},
            "attachments": [{"filename": "...", "hash": "sha256...", "size": 1234}, ...]
        }
    """
    logger.info(f"[STUB] parse_eml({file_path}) — returning simulated data")
    return {
        "urls": [],
        "content": {
            "subject": "[STUB] Parsed email subject",
            "body_text": "[STUB] Parsed body text",
            "body_html": None,
        },
        "attachments": [],
    }


def check_auth(headers: dict[str, Any]) -> dict[str, str]:
    """
    STUB: protocol_verifier.check_auth(headers)
    Verifies email origin protocols: SPF, DKIM, DMARC.

    Real implementation: call actual protocol verification service.

    Returns:
        {"spf": "PASS"|"FAIL", "dkim": "PASS"|"FAIL", "dmarc": "PASS"|"FAIL"}
    """
    logger.info("[STUB] check_auth() — returning simulated PASS for all protocols")

    # In stub mode, extract from headers if available, otherwise default PASS
    auth_results = headers.get("authentication_results", {})
    return {
        "spf": auth_results.get("spf", "PASS"),
        "dkim": auth_results.get("dkim", "PASS"),
        "dmarc": auth_results.get("dmarc", "PASS"),
    }


def scan_hash(hash_value: str) -> str:
    """
    STUB: threat_intel.scan_hash(hash_value)
    Queries internal databases and VirusTotal to check file hash.

    Real implementation: call actual threat intelligence API.

    Returns:
        "SAFE" | "MALICIOUS"
    """
    logger.info(f"[STUB] scan_hash({hash_value[:16]}...) — returning SAFE")
    return "SAFE"


def compute_file_hash(content: bytes) -> str:
    """Helper: compute SHA-256 hash of file content."""
    return hashlib.sha256(content).hexdigest()
