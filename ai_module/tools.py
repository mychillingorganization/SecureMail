from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from ai_module.schemas import AnalyzeRequest
from ai_module import thresholds


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def tool_auth_summary(payload: AnalyzeRequest, _args: dict[str, Any]) -> dict[str, Any]:
    spf = bool(payload.auth.get("spf", {}).get("pass", False))
    dkim = bool(payload.auth.get("dkim", {}).get("pass", False))
    dmarc = bool(payload.auth.get("dmarc", {}).get("pass", False))
    return {
        "spf_pass": spf,
        "dkim_pass": dkim,
        "dmarc_pass": dmarc,
        "auth_all_pass": spf and dkim and dmarc,
    }


def tool_email_signal(payload: AnalyzeRequest, _args: dict[str, Any]) -> dict[str, Any]:
    risk = _safe_float(payload.email_agent.get("risk_score", 0.0))
    label = str(payload.email_agent.get("label", "unknown")).lower()
    return {
        "risk_score": risk,
        "label": label,
        "is_suspicious": risk >= thresholds.EMAIL_RISK_SIGNAL_THRESHOLD or label in thresholds.EMAIL_SUSPICIOUS_LABELS,
    }


def tool_file_signal(payload: AnalyzeRequest, _args: dict[str, Any]) -> dict[str, Any]:
    requested_indices_raw = _args.get("file_indices") if isinstance(_args, dict) else None
    requested_indices: set[int] | None = None
    if isinstance(requested_indices_raw, list):
        normalized: set[int] = set()
        for item in requested_indices_raw:
            try:
                idx = int(item)
            except (TypeError, ValueError):
                continue
            if 0 <= idx < len(payload.file_module):
                normalized.add(idx)
        requested_indices = normalized

    suspicious = []
    scanned_indices: list[int] = []
    for idx, item in enumerate(payload.file_module):
        if requested_indices is not None and idx not in requested_indices:
            continue

        scanned_indices.append(idx)
        risk = _safe_float(item.get("risk_score", 0.0))
        label = str(item.get("label", "safe")).lower()
        level = str(item.get("risk_level", "")).lower()
        if risk >= thresholds.FILE_RISK_SIGNAL_THRESHOLD or label in thresholds.FILE_SUSPICIOUS_LABELS or level in thresholds.FILE_DANGEROUS_RISK_LEVELS:
            suspicious.append({
                "index": idx,
                "risk_score": risk,
                "label": label,
                "risk_level": level,
            })
    return {
        "attachment_count": len(payload.file_module),
        "scanned_attachment_count": len(scanned_indices),
        "scanned_indices": sorted(scanned_indices),
        "suspicious_count": len(suspicious),
        "suspicious_items": suspicious,
    }


def tool_web_signal(payload: AnalyzeRequest, _args: dict[str, Any]) -> dict[str, Any]:
    requested_urls = _args.get("urls") if isinstance(_args, dict) else None
    scoped_urls = payload.urls
    if isinstance(requested_urls, list) and requested_urls:
        requested_set = {str(item).strip() for item in requested_urls if str(item).strip()}
        scoped_urls = [url for url in payload.urls if url in requested_set]

    risk = _safe_float(payload.web_module.get("risk_score", 0.0))
    label = str(payload.web_module.get("label", "unknown")).lower()
    return {
        "risk_score": risk,
        "label": label,
        "scanned_url_count": len(scoped_urls),
        "scanned_urls": scoped_urls,
        "is_suspicious": risk >= thresholds.WEB_RISK_SIGNAL_THRESHOLD or label in thresholds.WEB_SUSPICIOUS_LABELS,
    }


def tool_url_domains(payload: AnalyzeRequest, _args: dict[str, Any]) -> dict[str, Any]:
    requested_urls = _args.get("urls") if isinstance(_args, dict) else None
    source_urls = payload.urls
    if isinstance(requested_urls, list) and requested_urls:
        requested_set = {str(item).strip() for item in requested_urls if str(item).strip()}
        source_urls = [url for url in payload.urls if url in requested_set]

    domains: list[str] = []
    for raw in source_urls:
        parsed = urlparse(raw)
        domain = (parsed.netloc or parsed.path).strip().lower()
        if domain:
            domains.append(domain)
    uniq = sorted(set(domains))
    return {
        "url_count": len(source_urls),
        "scanned_urls": source_urls,
        "domains": uniq,
    }


def tool_risk_rollup(payload: AnalyzeRequest, _args: dict[str, Any]) -> dict[str, Any]:
    base_score = int(payload.issue_count)
    risk = float(base_score)
    if not bool(payload.auth.get("spf", {}).get("pass", False)):
        risk += thresholds.AUTH_PENALTY_SPF_FAIL
    if not bool(payload.auth.get("dkim", {}).get("pass", False)):
        risk += thresholds.AUTH_PENALTY_DKIM_FAIL
    if not bool(payload.auth.get("dmarc", {}).get("pass", False)):
        risk += thresholds.AUTH_PENALTY_DMARC_FAIL

    email_risk = _safe_float(payload.email_agent.get("risk_score", 0.0))
    web_risk = _safe_float(payload.web_module.get("risk_score", 0.0))
    risk += email_risk + web_risk

    for item in payload.file_module:
        risk += _safe_float(item.get("risk_score", 0.0))

    if payload.provisional_final_status == "DANGER":
        risk += thresholds.PROVISIONAL_DANGER_WEIGHT

    return {
        "composite_risk": round(risk, 4),
        "provisional_final_status": payload.provisional_final_status,
        "issue_count": payload.issue_count,
    }


TOOLS = {
    "auth_summary": tool_auth_summary,
    "email_signal": tool_email_signal,
    "file_signal": tool_file_signal,
    "web_signal": tool_web_signal,
    "url_domains": tool_url_domains,
    "risk_rollup": tool_risk_rollup,
}
