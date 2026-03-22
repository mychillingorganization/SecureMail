from __future__ import annotations

import math
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel
from scipy.sparse import hstack


def _extract_extra_features(text: str) -> list[float]:
    lowered = text.lower()
    return [
        float(len(text)),
        float(len(re.findall(r"http[s]?://", text))),
        float(int(bool(re.search(r"urgent|money|bank|transfer|account|verify|login", lowered)))),
        float(sum(ch.isdigit() for ch in text)),
        float(text.count("!")),
        float(int(bool(re.search(r"[A-Z]{5,}", text)))),
    ]


class AnalyzeRequest(BaseModel):
    email_id: str = "unknown-uuid"
    headers: dict[str, Any] | None = None
    body_text: str = ""
    subject: str | None = None
    timestamp: str | None = None


class _EmailModelRuntime:
    def __init__(self) -> None:
        self.ready = False
        self.error: str | None = None
        self.model = None
        self.tfidf = None
        self.scaler = None

    def load(self) -> None:
        base_dir = Path(__file__).resolve().parent / "model_svm_email"
        model_path = base_dir / "svm_model.pkl"
        tfidf_path = base_dir / "tfidf.pkl"
        scaler_path = base_dir / "scaler.pkl"

        self.model = joblib.load(model_path)
        self.tfidf = joblib.load(tfidf_path)
        self.scaler = joblib.load(scaler_path)
        self.ready = True
        self.error = None

    def predict(self, subject: str, body_text: str) -> tuple[float, float, str]:
        if not self.ready or self.model is None or self.tfidf is None or self.scaler is None:
            raise RuntimeError(self.error or "Model chưa sẵn sàng")

        full_text = f"{subject} {body_text}".strip()
        text_vec = self.tfidf.transform([full_text])
        extra = np.array([_extract_extra_features(full_text)])
        extra_scaled = self.scaler.transform(extra)
        final = hstack([text_vec, extra_scaled])

        pred = int(self.model.predict(final)[0])
        raw_score = float(self.model.decision_function(final)[0])
        confidence = 1.0 / (1.0 + math.exp(-raw_score))
        risk_score = confidence if pred == 1 else 1.0 - confidence
        label = "phishing" if pred == 1 else "safe"
        return risk_score, confidence, label


runtime = _EmailModelRuntime()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        runtime.load()
    except Exception as exc:  # pragma: no cover - depends on external model artifacts
        runtime.ready = False
        runtime.error = f"Model load failed: {type(exc).__name__}: {exc}"
    yield


app = FastAPI(
    title="Email Agent API",
    description="Email risk analysis via SVM model with safe fallback mode",
    lifespan=lifespan,
)


@app.get("/health")
async def health_check() -> dict[str, Any]:
    return {
        "status": "ok" if runtime.ready else "degraded",
        "service": "email-agent",
        "model_loaded": runtime.ready,
        "model_error": runtime.error,
    }


def _fallback_predict(subject: str, body_text: str) -> tuple[float, float, str, str]:
    full_text = f"{subject} {body_text}".lower()
    suspicious_keywords = ["urgent", "verify", "password", "login", "bank", "transfer", "click"]
    score = 0.2
    if any(keyword in full_text for keyword in suspicious_keywords):
        score = 0.75
    label = "phishing" if score >= 0.6 else "safe"
    confidence = 0.55 if label == "safe" else 0.7
    return score, confidence, label, "fallback-heuristic"


@app.post("/api/v1/analyze")
async def analyze_email(request: AnalyzeRequest) -> dict[str, Any]:
    start = time.perf_counter()
    subject = request.subject or ""
    body_text = request.body_text or ""
    reasoning_trace = ["Receive request", "Run content risk analysis"]

    if runtime.ready:
        risk_score, confidence, label = runtime.predict(subject, body_text)
        source = "svm-model"
        reasoning_trace.append("Model loaded: SVM prediction complete")
    else:
        risk_score, confidence, label, source = _fallback_predict(subject, body_text)
        reasoning_trace.append(f"Model unavailable: use fallback ({runtime.error})")

    processing_time_ms = round((time.perf_counter() - start) * 1000, 2)
    return {
        "email_id": request.email_id,
        "risk_score": round(float(risk_score), 4),
        "confidence": round(float(confidence), 4),
        "label": label,
        "checks": {
            "model": {
                "loaded": runtime.ready,
                "source": source,
                "error": runtime.error,
            },
            "spf": {"pass": None, "detail": "Handled in orchestrator protocol step"},
            "dkim": {"pass": None, "detail": "Handled in orchestrator protocol step"},
            "dmarc": {"pass": None, "detail": "Handled in orchestrator protocol step"},
        },
        "reasoning_trace": reasoning_trace,
        "processing_time_ms": processing_time_ms,
    }
