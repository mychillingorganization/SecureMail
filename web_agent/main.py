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
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from feature_extractor import (
    HTML_DEFAULT_FEATURES,
    extract_html_features,
    extract_url_features,
    fetch_html,
    fetch_url_context,
)
from lists import is_blacklisted, is_whitelisted, load_lists
from model import MODEL_PATH, PhishingModel
from visual_analyzer import VisualAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Singleton model — populated during lifespan ───────────────────────────────
_model: PhishingModel | None = None
_visual_analyzer: VisualAnalyzer | None = None
_db_session_factory: sessionmaker | None = None

Base = declarative_base()


class Favicon(Base):
    __tablename__ = "favicons"

    id = Column(String, primary_key=True)
    brand_name = Column(String, nullable=False)
    phash_value = Column(String, nullable=False)
    valid_domains = Column(JSONB)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the XGBoost model and threat lists on startup; clean up on shutdown."""
    global _db_session_factory, _model, _visual_analyzer
    logger.info("Web Agent starting — loading model from '%s' …", MODEL_PATH)
    _model = PhishingModel(MODEL_PATH)
    _visual_analyzer = VisualAnalyzer(Favicon)

    postgres_url = os.getenv("POSTGRES_URL")
    if postgres_url:
        sync_url = postgres_url.replace("+asyncpg", "+psycopg2")
        engine = create_engine(sync_url, pool_pre_ping=True)
        _db_session_factory = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
        logger.info("VisualAnalyzer DB session is enabled")
    else:
        _db_session_factory = None
        logger.warning("POSTGRES_URL not set for web-agent; visual brand matching disabled")

    logger.info("Loading whitelist / blacklist …")
    await load_lists()
    logger.info("Web Agent is ready.")
    yield
    logger.info("Web Agent shutting down.")


app = FastAPI(
    title="Web Agent API",
    description="Phishing URL detection powered by XGBoost (SecureMail pipeline)",
    version="1.0.0",
    lifespan=lifespan,
)

# ── Schemas ───────────────────────────────────────────────────────────────────


class AnalyzeRequest(BaseModel):
    email_id: str = "unknown"
    urls: list[str] = Field(default_factory=list)


class AnalyzeUrlsJsonRequest(BaseModel):
    email_id: str = "unknown"
    urls_json: dict[str, Any]


class URLResult(BaseModel):
    url: str
    risk_score: float
    confidence: float
    label: str  # "phishing" | "safe"
    source: str  # "model" | "blacklist" | "whitelist"
    html_features_used: bool
    visual_analysis: dict[str, str]


class AnalyzeResponse(BaseModel):
    email_id: str
    risk_score: float  # max risk across all URLs
    confidence: float  # mean confidence across all URLs
    label: str  # "phishing" | "safe"
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

    normalized_request = AnalyzeRequest(email_id=request.email_id, urls=urls)
    return await _run_analysis(normalized_request)


async def _run_analysis(request: AnalyzeRequest) -> AnalyzeResponse:
    if _model is None:
        raise HTTPException(status_code=503, detail="Model not initialised yet")

    start = time.time()
    traces: list[str] = [
        f"Received {len(request.urls)} URL(s) for email {request.email_id}"
    ]

    # Analyse all URLs concurrently
    url_results: list[dict] = await asyncio.gather(
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
      1. Blacklist — immediate PHISHING verdict (skips model).
      2. Whitelist — immediate SAFE verdict (skips model).
      3. Feature extraction + XGBoost inference.
    """
    fetched_url, html_content = await fetch_url_context(url)
    analysis_url = fetched_url or url

    # 1. Blacklist fast-path (raw + resolved URL)
    if is_blacklisted(url) or is_blacklisted(analysis_url):
        logger.info("URL blacklisted: %s", url)
        return {
            "url": analysis_url,
            "input_url": url,
            "risk_score": 0.99,
            "confidence": 0.98,
            "label": "phishing",
            "source": "blacklist",
            "html_features_used": False,
            "visual_analysis": {"verdict": "UNKNOWN"},
        }

    # 2. Whitelist fast-path (raw + resolved URL)
    if is_whitelisted(url) or is_whitelisted(analysis_url):
        logger.info("URL whitelisted: %s", url)
        return {
            "url": analysis_url,
            "input_url": url,
            "risk_score": 0.01,
            "confidence": 0.98,
            "label": "safe",
            "source": "whitelist",
            "html_features_used": False,
            "visual_analysis": {"verdict": "UNKNOWN"},
        }

    # 3. Feature extraction
    url_features = extract_url_features(analysis_url)
    html_used = html_content is not None
    html_features = (
        extract_html_features(html_content) if html_used else dict(HTML_DEFAULT_FEATURES)
    )

    all_features = {**url_features, **html_features}

    # 4. Model inference (model is never None here — checked at endpoint level)
    result = _model.predict(all_features)  # type: ignore[union-attr]

    visual_analysis = await _evaluate_visual(analysis_url)

    logger.info(
        "URL scored: %s → risk=%.4f label=%s html=%s",
        analysis_url,
        result["risk_score"],
        result["label"],
        html_used,
    )

    return {
        "url": analysis_url,
        "input_url": url,
        "risk_score": result["risk_score"],
        "confidence": result["confidence"],
        "label": result["label"],
        "source": "model",
        "html_features_used": html_used,
        "visual_analysis": visual_analysis,
    }


async def _evaluate_visual(url: str) -> dict[str, str]:
    if _visual_analyzer is None or _db_session_factory is None:
        return {"verdict": "UNKNOWN"}

    def _run() -> dict[str, str]:
        with _db_session_factory() as session:
            return _visual_analyzer.evaluate_visual_risk(session, url)

    try:
        return await asyncio.to_thread(_run)
    except Exception:
        logger.exception("Visual analysis failed for URL: %s", url)
        return {"verdict": "UNKNOWN"}
