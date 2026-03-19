"""
SSL/TLS Certificate Analyzer for the SecureMail Web Agent.

This module provides cryptographic validation and phishing risk heuristics
based on certificate metadata. It is designed to be imported directly into
the FastAPI service and invoked as part of a URL analysis pipeline.

Key heuristics:
  - Newly issued certificates (< 30 days old) are HIGH risk.
  - Free CA issuers (Let's Encrypt, ZeroSSL, etc.) are flagged MEDIUM risk.
  - Certificates expiring in < 15 days are flagged MEDIUM risk.
  - SSL verification failures (self-signed, expired, name mismatch) are HIGH risk.

All I/O is synchronous (stdlib ssl + socket). Wrap calls in asyncio.to_thread()
when using from an async FastAPI context.
"""

from __future__ import annotations

import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"  # e.g. "Mar 19 12:00:00 2026 GMT"

CONNECT_TIMEOUT: float = 5.0  # seconds; prevents hanging on dead hosts

# These string fragments are matched case-insensitively against the issuer Org Name.
FREE_CA_IDENTIFIERS: tuple[str, ...] = (
    "let's encrypt",
    "zerossl",
    "trustasia",
    "buypass",
    "e1",   # Let's Encrypt intermediate CN short form
    "r3",   # Let's Encrypt intermediate
    "e5",
    "e6",
    "r10",
    "r11",
)

# Age thresholds
NEW_CERT_THRESHOLD_DAYS: int = 30   # newly minted certs → HIGH risk
EXPIRY_WARNING_THRESHOLD_DAYS: int = 15  # near expiry → MEDIUM risk

# Risk levels
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_cert_date(date_str: str) -> datetime:
    """Parse an SSL certificate date string into a timezone-aware UTC datetime.

    Args:
        date_str: Date string in the format returned by Python's ssl module,
                  e.g. ``"Mar 19 12:00:00 2026 GMT"``.

    Returns:
        A UTC-aware :class:`datetime` object.

    Raises:
        ValueError: If the string cannot be parsed.
    """
    dt = datetime.strptime(date_str, CERT_DATE_FORMAT)
    # ssl always returns GMT, so we attach UTC tzinfo explicitly.
    return dt.replace(tzinfo=timezone.utc)


def _extract_issuer_org(cert: dict[str, Any]) -> str:
    """Extract the Organisation Name ("O") from the certificate issuer field.

    Args:
        cert: Raw certificate dictionary returned by ``SSLSocket.getpeercert()``.

    Returns:
        The issuer organisation string, or ``"Unknown"`` if not present.
    """
    for rdns in cert.get("issuer", []):
        for key, value in rdns:
            if key == "organizationName":
                return value
    return "Unknown"


def _extract_common_name(cert: dict[str, Any]) -> str:
    """Extract the Common Name ("CN") from the certificate subject field.

    Args:
        cert: Raw certificate dictionary.

    Returns:
        The CN string, or ``"Unknown"`` if not present.
    """
    for rdns in cert.get("subject", []):
        for key, value in rdns:
            if key == "commonName":
                return value
    return "Unknown"


def _extract_sans(cert: dict[str, Any]) -> list[str]:
    """Extract Subject Alternative Names (SANs) from the certificate.

    Only ``DNS`` type SANs are returned; IP addresses are excluded since
    phishing domains virtually never use IP-based certs.

    Args:
        cert: Raw certificate dictionary.

    Returns:
        A list of domain strings covered by this certificate.
    """
    return [
        value
        for san_type, value in cert.get("subjectAltName", [])
        if san_type.upper() == "DNS"
    ]


def _score_risk(
    is_verified: bool,
    cert_age_days: int,
    days_to_expire: int,
    issuer_org: str,
) -> tuple[str, list[str]]:
    """Apply phishing risk heuristics and return a (risk_level, flags) tuple.

    Heuristic rules (evaluated in priority order):

    +--------------------------+-------+-----------------------------------------------+
    | Condition                | Risk  | Flag string                                   |
    +==========================+=======+===============================================+
    | SSL verification failed  | HIGH  | ``"SSL_VERIFICATION_FAILED"``                 |
    +--------------------------+-------+-----------------------------------------------+
    | cert age < 30 days       | HIGH  | ``"NEWLY_ISSUED_CERTIFICATE"``                |
    +--------------------------+-------+-----------------------------------------------+
    | Free CA issuer detected  | MED   | ``"FREE_CA_ISSUER:<orgname>"``                |
    +--------------------------+-------+-----------------------------------------------+
    | days to expire < 15      | MED   | ``"CERT_EXPIRING_SOON"``                      |
    +--------------------------+-------+-----------------------------------------------+

    Args:
        is_verified: ``True`` if the SSL handshake completed without errors.
        cert_age_days: Number of days since the certificate was issued.
        days_to_expire: Number of days until the certificate expires.
        issuer_org: Organisation name of the Certificate Authority.

    Returns:
        A tuple of (``risk_level``, ``risk_flags``).
    """
    flags: list[str] = []
    risk_level = LOW

    # --- HIGH risk conditions ---
    if not is_verified:
        flags.append("SSL_VERIFICATION_FAILED")
        risk_level = HIGH

    if cert_age_days >= 0 and cert_age_days < NEW_CERT_THRESHOLD_DAYS:
        flags.append(
            f"NEWLY_ISSUED_CERTIFICATE (age={cert_age_days}d, threshold={NEW_CERT_THRESHOLD_DAYS}d)"
        )
        risk_level = HIGH

    # --- MEDIUM risk conditions (only escalate if not already HIGH) ---
    issuer_lower = issuer_org.lower()
    if any(free_ca in issuer_lower for free_ca in FREE_CA_IDENTIFIERS):
        flags.append(f"FREE_CA_ISSUER:{issuer_org}")
        if risk_level != HIGH:
            risk_level = MEDIUM

    if days_to_expire >= 0 and days_to_expire < EXPIRY_WARNING_THRESHOLD_DAYS:
        flags.append(
            f"CERT_EXPIRING_SOON (expires_in={days_to_expire}d, threshold={EXPIRY_WARNING_THRESHOLD_DAYS}d)"
        )
        if risk_level != HIGH:
            risk_level = MEDIUM

    return risk_level, flags


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_ssl_certificate(url: str) -> dict[str, Any]:
    """Analyse the SSL/TLS certificate of the host reachable at *url*.

    This function resolves the hostname, performs a TLS handshake, extracts
    certificate metadata, and evaluates phishing risk heuristics.

    It is **synchronous** and blocking.  When calling from an ``async`` FastAPI
    route, wrap it with ``asyncio.to_thread(analyze_ssl_certificate, url)``.

    Args:
        url: The full URL whose certificate should be inspected, e.g.
             ``"https://suspicious-bank.com/login"``.  The ``https`` scheme is
             assumed when the scheme is missing or is ``http``.

    Returns:
        A dictionary with the following keys:

        .. code-block:: python

            {
                # Whether TLS verification succeeded
                "is_valid": bool,
                # Parsed from the URL
                "hostname": str,
                # Certificate metadata
                "subject_cn": str,
                "issuer_org": str,
                "not_before": str,         # ISO-8601 UTC string
                "not_after": str,          # ISO-8601 UTC string
                "certificate_age_days": int,
                "days_to_expire": int,
                "san_domains": list[str],
                # Risk evaluation
                "risk_level": str,         # "LOW" | "MEDIUM" | "HIGH"
                "risk_flags": list[str],
                # Optional error detail
                "error": str | None,
            }

    Raises:
        Nothing — all exceptions are caught and reflected in the return dict.

    Example::

        >>> result = analyze_ssl_certificate("https://example.com")
        >>> result["risk_level"]
        'LOW'
    """
    now_utc = datetime.now(tz=timezone.utc)

    # Base template – populated progressively
    result: dict[str, Any] = {
        "is_valid": False,
        "hostname": "",
        "subject_cn": "Unknown",
        "issuer_org": "Unknown",
        "not_before": None,
        "not_after": None,
        "certificate_age_days": -1,
        "days_to_expire": -1,
        "san_domains": [],
        "risk_level": HIGH,
        "risk_flags": [],
        "error": None,
    }

    # ------------------------------------------------------------------
    # 1. Parse the URL to extract the hostname
    # ------------------------------------------------------------------
    parsed = urlparse(url if "://" in url else f"https://{url}")
    hostname: str = parsed.hostname or ""
    port: int = parsed.port or (443 if parsed.scheme in ("https", "") else 80)

    if not hostname:
        result["error"] = f"Could not parse hostname from URL: {url!r}"
        result["risk_flags"].append("INVALID_URL")
        logger.warning("ssl_analyzer: invalid URL provided: %s", url)
        return result

    result["hostname"] = hostname

    # ------------------------------------------------------------------
    # 2. Perform TLS handshake and retrieve the peer certificate
    # ------------------------------------------------------------------
    raw_cert: dict[str, Any] = {}
    verification_error: str | None = None

    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                raw_cert = ssock.getpeercert()   # type: ignore[assignment]
                result["is_valid"] = True
                logger.debug("ssl_analyzer: handshake OK for %s", hostname)

    except ssl.SSLCertVerificationError as exc:
        verification_error = f"SSLCertVerificationError: {exc.reason}"
        result["risk_flags"].append("SSL_VERIFICATION_FAILED")
        logger.warning("ssl_analyzer: cert verification failed for %s — %s", hostname, exc)

        # Attempt to fetch the cert without verification to extract metadata.
        # This gives us more intelligence to return even when the cert is bad.
        fallback_ctx = ssl.create_default_context()
        fallback_ctx.check_hostname = False
        fallback_ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
                with fallback_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    raw_cert = ssock.getpeercert()  # type: ignore[assignment]
        except Exception:
            pass  # Best-effort; we'll leave raw_cert empty if this also fails.

    except ssl.SSLError as exc:
        verification_error = f"SSLError: {exc}"
        result["risk_flags"].append("SSL_ERROR")
        logger.warning("ssl_analyzer: SSL error for %s — %s", hostname, exc)

    except socket.timeout:
        result["error"] = f"Connection to {hostname}:{port} timed out (>{CONNECT_TIMEOUT}s)"
        result["risk_flags"].append("CONNECTION_TIMEOUT")
        result["risk_level"] = MEDIUM   # Timeout is not itself malicious
        logger.warning("ssl_analyzer: timeout for %s", hostname)
        return result

    except ConnectionRefusedError:
        result["error"] = f"Connection refused by {hostname}:{port}"
        result["risk_flags"].append("CONNECTION_REFUSED")
        result["risk_level"] = MEDIUM
        logger.warning("ssl_analyzer: connection refused for %s", hostname)
        return result

    except OSError as exc:
        result["error"] = f"Network error for {hostname}: {exc}"
        result["risk_flags"].append("NETWORK_ERROR")
        result["risk_level"] = MEDIUM
        logger.warning("ssl_analyzer: network error for %s — %s", hostname, exc)
        return result

    if verification_error:
        result["error"] = verification_error

    # ------------------------------------------------------------------
    # 3. Extract certificate fields (if we managed to get the cert)
    # ------------------------------------------------------------------
    if raw_cert:
        try:
            not_before_str: str = raw_cert.get("notBefore", "")
            not_after_str: str = raw_cert.get("notAfter", "")

            not_before: datetime = _parse_cert_date(not_before_str)
            not_after: datetime = _parse_cert_date(not_after_str)

            cert_age_days: int = (now_utc - not_before).days
            days_to_expire: int = (not_after - now_utc).days

            result["not_before"] = not_before.isoformat()
            result["not_after"] = not_after.isoformat()
            result["certificate_age_days"] = cert_age_days
            result["days_to_expire"] = days_to_expire
            result["subject_cn"] = _extract_common_name(raw_cert)
            result["issuer_org"] = _extract_issuer_org(raw_cert)
            result["san_domains"] = _extract_sans(raw_cert)

        except (ValueError, KeyError) as exc:
            logger.error(
                "ssl_analyzer: failed to parse certificate fields for %s — %s",
                hostname,
                exc,
            )
            result["risk_flags"].append(f"CERT_PARSE_ERROR:{exc}")

    # ------------------------------------------------------------------
    # 4. Apply heuristic risk scoring
    # ------------------------------------------------------------------
    computed_risk_level, heuristic_flags = _score_risk(
        is_verified=result["is_valid"],
        cert_age_days=result["certificate_age_days"],
        days_to_expire=result["days_to_expire"],
        issuer_org=result["issuer_org"],
    )

    # Merge heuristic flags with any connection-phase flags already recorded.
    result["risk_flags"].extend(
        flag for flag in heuristic_flags if flag not in result["risk_flags"]
    )

    # Use heuristic result. The initial HIGH is a conservative default for the
    # unanalyzed state; once _score_risk runs with full cert context, its
    # output is authoritative. This correctly downgrades to MEDIUM for cases
    # like valid certs from free CAs (Let's Encrypt, etc.) instead of
    # incorrectly leaving risk at HIGH.
    result["risk_level"] = computed_risk_level

    logger.info(
        "ssl_analyzer: %s → risk=%s, flags=%s",
        hostname,
        result["risk_level"],
        result["risk_flags"],
    )

    return result
