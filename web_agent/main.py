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
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from feature_extractor import (
    HTML_DEFAULT_FEATURES,
    extract_html_features,
    extract_url_features,
    fetch_url_context,
)
from lists import is_blacklisted, is_whitelisted, load_lists
from model import MODEL_PATH, PhishingModel
from ssl_analyzer import analyze_ssl_certificate

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Singleton model — populated during lifespan ───────────────────────────────
_model: PhishingModel | None = None

# SSL risk → additive score boost applied on top of the XGBoost inference score.
# Keeps the two signals clearly separated and auditable.
_SSL_BOOST: dict[str, float] = {
    "HIGH":    0.20,
    "MEDIUM":  0.08,
    "LOW":     0.00,
    "SKIPPED": 0.00,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the XGBoost model and threat lists on startup; clean up on shutdown."""
    global _model
    logger.info("Web Agent starting — loading model from '%s' …", MODEL_PATH)
    _model = PhishingModel(MODEL_PATH)

    logger.info("Loading whitelist / blacklist …")
    await load_lists()
    logger.info("Web Agent is ready.")
    yield
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
    ssl_valid: bool
    ssl_risk_level: str     # "LOW" | "MEDIUM" | "HIGH" | "SKIPPED"
    ssl_risk_flags: list[str]


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
    return {
        "status": "ok",
        "service": "web-agent",
        "model_loaded": _model is not None,
    }


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze_urls(request: AnalyzeRequest) -> AnalyzeResponse:
    return await _run_analysis(request)


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

    normalized_request = AnalyzeRequest(email_id=request.email_id, urls=urls)
    return await _run_analysis(normalized_request)


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


# Shared sentinel returned by fast-path branches (no SSL analysis performed).
_SSL_SKIPPED: dict[str, Any] = {
    "ssl_valid": False,
    "ssl_risk_level": "SKIPPED",
    "ssl_risk_flags": [],
}


async def _analyse_url(url: str) -> dict:
    """Full analysis pipeline for a single URL.

    Priority order:
      1. Blacklist  — immediate PHISHING verdict, SSL SKIPPED.
      2. Whitelist  — immediate SAFE verdict,     SSL SKIPPED.
      3. Feature extraction + XGBoost inference.
      4. SSL certificate analysis (asyncio.to_thread — non-blocking).
      5. SSL risk score boost applied to ML score.
    """
    try:
        # ── Step 1: Blacklist fast-path (raw URL) ──────────────────────────
        if is_blacklisted(url):
            logger.info("URL blacklisted: %s", url)
            return {
                "url": url, "input_url": url,
                "risk_score": 0.99, "confidence": 0.98,
                "label": "phishing", "source": "blacklist",
                "html_features_used": False,
                "redirection_chain": [url],
                **_SSL_SKIPPED,
            }

        # ── Step 2: Whitelist fast-path (raw URL) ──────────────────────────
        if is_whitelisted(url):
            logger.info("URL whitelisted: %s", url)
            return {
                "url": url, "input_url": url,
                "risk_score": 0.01, "confidence": 0.98,
                "label": "safe", "source": "whitelist",
                "html_features_used": False,
                "redirection_chain": [url],
                **_SSL_SKIPPED,
            }

        # ── Step 3: Resolve URL and fetch HTML context ─────────────────────
        fetched_url, html_content, redirection_chain = await fetch_url_context(url)
        analysis_url = fetched_url or url

        # ── Step 4: Re-check lists on resolved URL and intermediate redirects ──
        for chain_url in redirection_chain:
            if chain_url != url and is_blacklisted(chain_url):
                logger.info("Redirect chain URL blacklisted: %s -> ... -> %s", url, chain_url)
                return {
                    "url": analysis_url, "input_url": url,
                    "risk_score": 0.99, "confidence": 0.98,
                    "label": "phishing", "source": "blacklist",
                    "html_features_used": False,
                    "redirection_chain": redirection_chain,
                    **_SSL_SKIPPED,
                }

        if is_whitelisted(analysis_url):
            logger.info("Resolved URL whitelisted: %s -> %s", url, analysis_url)
            return {
                "url": analysis_url, "input_url": url,
                "risk_score": 0.01, "confidence": 0.98,
                "label": "safe", "source": "whitelist",
                "html_features_used": False,
                "redirection_chain": redirection_chain,
                **_SSL_SKIPPED,
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
        base_risk: float = model_result["risk_score"]
        confidence: float = model_result["confidence"]
        label: str = model_result["label"]

        # ── Step 7: SSL certificate analysis (non-blocking via thread) ──────
        ssl_result = await _analyse_ssl(analysis_url)
        ssl_boost = _SSL_BOOST.get(ssl_result["ssl_risk_level"], 0.0)
        final_risk = min(1.0, base_risk + ssl_boost)

        # Re-evaluate label after SSL boost
        final_label = "phishing" if final_risk >= 0.5 else label

        logger.info(
            "URL scored: %s → base_risk=%.4f ssl=%s boost=%.2f final_risk=%.4f label=%s html=%s",
            analysis_url,
            base_risk,
            ssl_result["ssl_risk_level"],
            ssl_boost,
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
            **ssl_result,
        }

    except Exception:
        logger.exception("Per-URL analysis failed for '%s'", url)
        return {
            "url": url, "input_url": url,
            "risk_score": 0.5, "confidence": 0.0,
            "label": "phishing", "source": "error",
            "html_features_used": False,
            "redirection_chain": [url],
            "ssl_valid": False,
            "ssl_risk_level": "SKIPPED",
            "ssl_risk_flags": ["ANALYSIS_PIPELINE_ERROR"],
        }


async def _analyse_ssl(url: str) -> dict[str, Any]:
    """Run SSL certificate analysis in a thread pool (non-blocking).

    Returns a dict with ``ssl_valid``, ``ssl_risk_level``, ``ssl_risk_flags``
    keys, safe to unpack directly into the URL result dict.

    Never raises — all errors are caught and returned as MEDIUM risk.
    """
    try:
        raw = await asyncio.to_thread(analyze_ssl_certificate, url)
        return {
            "ssl_valid": raw["is_valid"],
            "ssl_risk_level": raw["risk_level"],
            "ssl_risk_flags": raw["risk_flags"],
        }
    except Exception as exc:
        logger.warning("SSL analysis raised unexpectedly for %s: %s", url, exc)
        return {
            "ssl_valid": False,
            "ssl_risk_level": "MEDIUM",
            "ssl_risk_flags": [f"SSL_ANALYSIS_EXCEPTION:{type(exc).__name__}"],
        }
