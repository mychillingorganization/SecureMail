"""
Web Agent — FastAPI service for phishing URL detection.

Endpoints:
  GET  /health           — liveness probe
  POST /api/v1/analyze   — bulk URL analysis, returns risk scores
  POST /api/v1/analyze-urls-json — analyze urls.json payload directly

The model and lists are loaded once during the FastAPI lifespan so that
startup side-effects (remote blacklist fetch, model deserialization) never
block at import time.
"""

import asyncio
import ipaddress
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from typing import Annotated, Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from config import THREAT_LIST_REFRESH_INTERVAL
from feature_extractor import (
    HTML_DEFAULT_FEATURES,
    extract_html_features,
    extract_url_features,
    fetch_url_context,
)
from lists import is_blacklisted, is_whitelisted, load_lists, refresh_lists, _refresh_stats
from model import MODEL_PATH, PhishingModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Singleton model — populated during lifespan ───────────────────────────────
_model: PhishingModel | None = None

# Background refresh task (if enabled)
_refresh_task: asyncio.Task | None = None

_HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def _hostname_validation_error(hostname: str | None) -> str | None:
    """Return a concrete hostname validation error, or ``None`` when valid.

    Accepts:
    - Valid DNS hostnames (including IDN domains after IDNA conversion)
    - Valid IPv4 / IPv6 literals
    """
    if not hostname:
        return "hostname is missing"

    candidate = hostname.strip().rstrip(".")
    if not candidate or len(candidate) > 253:
        return "hostname is empty or too long"

    # Accept direct IP literals.
    try:
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        pass

    # Reject obvious malformed cases early.
    if " " in candidate or ".." in candidate:
        return "hostname contains spaces or empty labels"

    try:
        ascii_host = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return "hostname IDNA encoding failed"

    labels = ascii_host.split(".")
    if any(not label for label in labels):
        return "hostname contains empty labels"

    if not all(_HOSTNAME_LABEL_RE.fullmatch(label) is not None for label in labels):
        return "hostname label format is invalid"

    return None


def _is_valid_hostname(hostname: str | None) -> bool:
    return _hostname_validation_error(hostname) is None


def _normalize_and_validate_urls(urls: list[str]) -> list[str]:
    """Normalize URLs and enforce strict scheme/hostname validation.

    Raises:
        HTTPException: 422 if any URL is malformed.
    """
    normalized_urls: list[str] = []

    def _raise_invalid_url(
        index: int,
        raw_url: str,
        normalized_url: str | None,
        code: str,
        reason: str,
    ) -> None:
        raise HTTPException(
            status_code=422,
            detail={
                "code": code,
                "index": index,
                "url": raw_url,
                "normalized_url": normalized_url,
                "reason": reason,
            },
        )

    for index, raw_url in enumerate(urls):
        normalized_input = str(raw_url).strip()
        if not normalized_input:
            _raise_invalid_url(
                index=index,
                raw_url=str(raw_url),
                normalized_url=None,
                code="invalid_url_empty",
                reason="empty URL is not allowed",
            )

        normalized_url = (
            normalized_input
            if normalized_input.startswith(("http://", "https://"))
            else f"https://{normalized_input}"
        )

        parsed = urlparse(normalized_url)
        if parsed.scheme not in {"http", "https"}:
            _raise_invalid_url(
                index=index,
                raw_url=normalized_input,
                normalized_url=normalized_url,
                code="invalid_url_scheme",
                reason="scheme must be http/https",
            )

        hostname_error = _hostname_validation_error(parsed.hostname)
        if hostname_error is not None:
            _raise_invalid_url(
                index=index,
                raw_url=normalized_input,
                normalized_url=normalized_url,
                code="invalid_url_hostname",
                reason=hostname_error,
            )

        normalized_urls.append(normalized_url)

    return normalized_urls

async def _run_background_refresh_loop() -> None:
    """Background task for periodic threat list refresh.
    
    Runs at the configured interval (THREAT_LIST_REFRESH_INTERVAL seconds).
    Catches and logs all exceptions to prevent the task from dying.
    """
    if THREAT_LIST_REFRESH_INTERVAL <= 0:
        logger.info("Threat list refresh is disabled (THREAT_LIST_REFRESH_INTERVAL <= 0)")
        return
    
    logger.info(
        "Background refresh task started — will refresh every %d seconds",
        THREAT_LIST_REFRESH_INTERVAL,
    )
    
    while True:
        try:
            await asyncio.sleep(THREAT_LIST_REFRESH_INTERVAL)
            logger.debug("Triggering scheduled threat list refresh …")
            result = await refresh_lists(force=False)
            if result["status"] == "success":
                logger.info("Scheduled refresh succeeded: %s", result["message"])
            else:
                logger.warning("Scheduled refresh failed: %s", result["message"])
        except asyncio.CancelledError:
            logger.info("Background refresh task cancelled (shutdown)")
            raise
        except Exception as exc:
            logger.exception("Background refresh task encountered unexpected error: %s", exc)
            # Continue running despite error (avoid task death)
            await asyncio.sleep(5)  # Brief pause before retry


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the XGBoost model and threat lists on startup; clean up on shutdown.
    
    Model and lists are loaded with graceful degradation:
    - If model fails to load, service runs in degraded mode (returns 503 errors).
    - If lists fail to load, service continues with empty lists (logs warning).
    
    Also starts a background task for periodic threat list refresh (if enabled).
    """
    global _model, _refresh_task
    
    # Load model with fallback to degraded mode
    logger.info("Web Agent starting — loading model from '%s' …", MODEL_PATH)
    try:
        _model = PhishingModel(MODEL_PATH)
        logger.info("Model loaded successfully.")
    except FileNotFoundError as e:
        logger.error(
            "Model file not found: %s — running in degraded mode (returning 503 errors)",
            e,
        )
        _model = None  # Graceful fallback: model stays None, health check returns degraded
    except Exception as e:
        logger.error(
            "Failed to load model: %s — running in degraded mode (returning 503 errors)",
            e,
        )
        _model = None  # Graceful fallback

    # Load threat lists with non-fatal error handling
    logger.info("Loading whitelist / blacklist …")
    try:
        await load_lists()
        logger.info("Threat lists loaded successfully.")
    except Exception as e:
        logger.warning(
            "Failed to load threat lists: %s — continuing with empty lists", e
        )
    
    # Start background refresh task (if configured)
    if THREAT_LIST_REFRESH_INTERVAL > 0:
        _refresh_task = asyncio.create_task(_run_background_refresh_loop())
        logger.info("Background refresh task created (interval: %ds)", THREAT_LIST_REFRESH_INTERVAL)
    else:
        logger.info("Background refresh task not started (disabled via config)")
    
    if _model is None:
        logger.warning(
            "Web Agent is ready BUT IN DEGRADED MODE (model not loaded). "
            "Health check will return status='degraded'."
        )
    else:
        logger.info("Web Agent is ready.")
    
    yield
    
    # Cancel background refresh task on shutdown
    if _refresh_task is not None:
        logger.info("Cancelling background refresh task …")
        _refresh_task.cancel()
        try:
            await _refresh_task
        except asyncio.CancelledError:
            logger.info("Background refresh task cancelled.")
    
    logger.info("Web Agent shutting down.")


app = FastAPI(
    title="Web Agent API",
    description="Phishing URL detection powered by XGBoost (SecureMail pipeline)",
    version="1.1.0",
    lifespan=lifespan,
)

MAX_URLS_PER_REQUEST = int(os.getenv("WEB_AGENT_MAX_URLS_PER_REQUEST", "100"))
MAX_URL_LENGTH = int(os.getenv("WEB_AGENT_MAX_URL_LENGTH", "2048"))

# ── Schemas ───────────────────────────────────────────────────────────────────


class AnalyzeRequest(BaseModel):
    email_id: str = "unknown"
    urls: list[Annotated[str, Field(min_length=1, max_length=MAX_URL_LENGTH)]] = Field(
        default_factory=list,
        max_length=MAX_URLS_PER_REQUEST,
    )


class AnalyzeUrlsJsonRequest(BaseModel):
    email_id: str = "unknown"
    urls_json: dict[str, Any]


class URLResult(BaseModel):
    url: str
    input_url: str
    risk_score: float
    confidence: float
    label: str              # "phishing" | "safe"
    source: str             # "model" | "blacklist" | "whitelist" | "error"
    html_features_used: bool
    redirection_chain: list[str]


class AnalyzeResponse(BaseModel):
    email_id: str
    risk_score: float       # max risk across all URLs
    confidence: float       # mean confidence across all URLs
    label: str              # "phishing" | "safe"
    checks: dict[str, Any]
    reasoning_trace: list[str]
    processing_time_ms: float


# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.get("/health")
async def health_check() -> dict[str, Any]:
    model_loaded = _model is not None
    return {
        "status": "ok" if model_loaded else "degraded",
        "service": "web-agent",
        "model_loaded": model_loaded,
    }


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze_urls(request: AnalyzeRequest) -> AnalyzeResponse:
    normalized_urls = _normalize_and_validate_urls(request.urls)
    normalized_request = AnalyzeRequest(email_id=request.email_id, urls=normalized_urls)
    return await _run_analysis(normalized_request)


@app.post("/api/v1/analyze-urls-json", response_model=AnalyzeResponse)
async def analyze_urls_json(request: AnalyzeUrlsJsonRequest) -> AnalyzeResponse:
    raw_urls = request.urls_json.get("urls")
    if not isinstance(raw_urls, list):
        raise HTTPException(status_code=422, detail="urls_json.urls must be a list of strings")
    if any(not isinstance(item, str) for item in raw_urls):
        raise HTTPException(status_code=422, detail="urls_json.urls must contain only strings")

    urls = [item.strip() for item in raw_urls if item.strip()]
    if len(urls) > MAX_URLS_PER_REQUEST:
        raise HTTPException(
            status_code=422,
            detail=f"Too many URLs in urls_json.urls (max {MAX_URLS_PER_REQUEST})",
        )

    normalized_urls = _normalize_and_validate_urls(urls)

    normalized_request = AnalyzeRequest(email_id=request.email_id, urls=normalized_urls)
    return await _run_analysis(normalized_request)


class RefreshListsRequest(BaseModel):
    force: bool = Field(
        default=False,
        description="If true, refresh immediately even if a recent refresh was attempted"
    )


class RefreshListsResponse(BaseModel):
    status: str  # "success" or "failed"
    message: str
    stats: dict[str, Any]
    elapsed_seconds: float


@app.post("/api/v1/refresh-lists", response_model=RefreshListsResponse)
async def refresh_lists_endpoint(request: RefreshListsRequest) -> RefreshListsResponse:
    """Manually trigger a refresh of threat lists (whitelist + blacklist).
    
    Fetches from configured sources with exponential backoff retry logic.
    On failure, the previous lists are retained (atomic rollback).
    
    Args:
        force: If true, skip any cooldown and refresh immediately.
    
    Returns:
        Status, message, current stats, and elapsed time.
    """
    result = await refresh_lists(force=request.force)
    
    # Convert status to HTTP response
    status_code = 200 if result["status"] == "success" else 200  # Always 200 for non-blocking updates
    
    return RefreshListsResponse(
        status=result["status"],
        message=result["message"],
        stats=result["stats"],
        elapsed_seconds=result["elapsed_seconds"],
    )


@app.get("/api/v1/refresh-stats")
async def get_refresh_stats() -> dict[str, Any]:
    """Get statistics about threat list refresh operations.
    
    Returns current counts, last refresh time, and error information.
    """
    return _refresh_stats.to_dict()


async def _run_analysis(request: AnalyzeRequest) -> AnalyzeResponse:
    if _model is None:
        raise HTTPException(status_code=503, detail="Model not initialised yet")

    start = time.time()
    traces: list[str] = [
        f"Received {len(request.urls)} URL(s) for email {request.email_id}"
    ]

    # Analyse all URLs concurrently (per-item errors are handled in _analyse_url)
    url_results: list[dict[str, Any]] = await asyncio.gather(
        *[_analyse_url(url) for url in request.urls]
    )

    if url_results:
        overall_risk = max(r["risk_score"] for r in url_results)
        overall_confidence = sum(r["confidence"] for r in url_results) / len(url_results)
    else:
        overall_risk = 0.0
        overall_confidence = 0.0

    overall_label = "phishing" if overall_risk >= 0.5 else "safe"
    traces.append(f"Analysed {len(url_results)} URL(s)")
    traces.append(f"Highest risk: {overall_risk:.4f} → verdict: {overall_label}")

    return AnalyzeResponse(
        email_id=request.email_id,
        risk_score=round(overall_risk, 4),
        confidence=round(overall_confidence, 4),
        label=overall_label,
        checks={"url_analysis": url_results},
        reasoning_trace=traces,
        processing_time_ms=round((time.time() - start) * 1000, 2),
    )


# ── Per-URL analysis pipeline ─────────────────────────────────────────────────


async def _analyse_url(url: str) -> dict:
    """Full analysis pipeline for a single URL.

    Priority order:
            1. Blacklist  — immediate PHISHING verdict.
            2. Whitelist  — immediate SAFE verdict.
      3. Feature extraction + XGBoost inference.
    """
    try:
        # ── Step 0: Normalize + validate input URL ─────────────────────────
        normalized_input = str(url).strip()
        if not normalized_input:
            return {
                "url": url, "input_url": url,
                "risk_score": 0.5, "confidence": 0.0,
                "label": "phishing", "source": "error",
                "html_features_used": False,
                "redirection_chain": [url],
            }

        normalized_url = (
            normalized_input
            if normalized_input.startswith(("http://", "https://"))
            else f"https://{normalized_input}"
        )

        parsed = urlparse(normalized_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or not _is_valid_hostname(parsed.hostname)
        ):
            logger.info("Invalid URL rejected before list/model checks: %s", url)
            return {
                "url": normalized_url, "input_url": url,
                "risk_score": 0.5, "confidence": 0.0,
                "label": "phishing", "source": "error",
                "html_features_used": False,
                "redirection_chain": [normalized_url],
            }

        # ── Step 1: Blacklist fast-path (normalized URL) ───────────────────
        if is_blacklisted(normalized_url):
            logger.info("URL blacklisted: %s", url)
            return {
                "url": normalized_url, "input_url": url,
                "risk_score": 0.99, "confidence": 0.98,
                "label": "phishing", "source": "blacklist",
                "html_features_used": False,
                "redirection_chain": [normalized_url],
            }

        # ── Step 2: Whitelist fast-path (normalized URL) ───────────────────
        if is_whitelisted(normalized_url):
            logger.info("URL whitelisted: %s", url)
            return {
                "url": normalized_url, "input_url": url,
                "risk_score": 0.01, "confidence": 0.98,
                "label": "safe", "source": "whitelist",
                "html_features_used": False,
                "redirection_chain": [normalized_url],
            }

        # ── Step 3: Resolve URL and fetch HTML context ─────────────────────
        fetched_url, html_content, redirection_chain = await fetch_url_context(normalized_url)
        analysis_url = fetched_url or normalized_url

        # ── Step 4: Re-check lists on resolved URL and intermediate redirects ──
        for chain_url in redirection_chain:
            if chain_url != normalized_url and is_blacklisted(chain_url):
                logger.info("Redirect chain URL blacklisted: %s -> ... -> %s", url, chain_url)
                return {
                    "url": analysis_url, "input_url": url,
                    "risk_score": 0.99, "confidence": 0.98,
                    "label": "phishing", "source": "blacklist",
                    "html_features_used": False,
                    "redirection_chain": redirection_chain,
                }

        if is_whitelisted(analysis_url):
            logger.info("Resolved URL whitelisted: %s -> %s", url, analysis_url)
            return {
                "url": analysis_url, "input_url": url,
                "risk_score": 0.01, "confidence": 0.98,
                "label": "safe", "source": "whitelist",
                "html_features_used": False,
                "redirection_chain": redirection_chain,
            }

        # ── Step 5: Feature extraction ─────────────────────────────────────
        url_features = extract_url_features(analysis_url)
        html_used = html_content is not None
        html_features = (
            extract_html_features(html_content) if html_used else dict(HTML_DEFAULT_FEATURES)
        )
        all_features = {**url_features, **html_features}

        # ── Step 6: XGBoost inference ──────────────────────────────────────
        model_result = _model.predict(all_features)  # type: ignore[union-attr]
        final_risk: float = model_result["risk_score"]
        confidence: float = model_result["confidence"]
        final_label: str = model_result["label"]

        logger.info(
            "URL scored: %s → risk=%.4f label=%s html=%s",
            analysis_url,
            final_risk,
            final_label,
            html_used,
        )

        return {
            "url": analysis_url,
            "input_url": url,
            "risk_score": round(final_risk, 4),
            "confidence": round(confidence, 4),
            "label": final_label,
            "source": "model",
            "html_features_used": html_used,
            "redirection_chain": redirection_chain,
        }

    except Exception:
        logger.exception("Per-URL analysis failed for '%s'", url)
        return {
            "url": url, "input_url": url,
            "risk_score": 0.5, "confidence": 0.0,
            "label": "phishing", "source": "error",
            "html_features_used": False,
            "redirection_chain": [url],
        }
