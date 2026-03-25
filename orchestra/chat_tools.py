from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
import hashlib
import re
from typing import Any

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from orchestra.models import (
    AiAnalysis,
    Email,
    File,
    FileAnalysis,
    FileStaticAnalysis,
    FileXgboostResults,
    RiskLevel,
    ScanHistory,
    Url,
    UrlAnalysis,
    VerdictType,
)
from orchestra.clients import AgentClient


URL_PATTERN = re.compile(r"https?://[^\s]+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}(?:/[\w\-./?%&=+#:]*)?\b",
    re.IGNORECASE,
)
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
EMAIL_CONTENT_PATTERN = re.compile(r"(?:check|scan|analy[sz]e)\s+(?:e?mail)\s+content\s*[:\-]?\s*(.*)", re.IGNORECASE)
AUTH_MENTION_PATTERN = re.compile(r"spf|dkim|dmarc|authentication", re.IGNORECASE)


def _hash_url(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8", errors="ignore")).hexdigest()


def _extract_target(message: str) -> tuple[str | None, str | None]:
    url_match = URL_PATTERN.search(message)
    if url_match:
        raw = url_match.group(0).rstrip(".,;:)]}\"'")
        return "url", raw

    domain_match = DOMAIN_PATTERN.search(message)
    if domain_match:
        raw = domain_match.group(0).rstrip(".,;:)]}\"'")
        if raw:
            if not raw.lower().startswith(("http://", "https://")):
                raw = f"https://{raw}"
            return "url", raw

    hash_match = SHA256_PATTERN.search(message)
    if hash_match:
        return "file_hash", hash_match.group(0).lower()

    return None, None


async def _check_url_reputation(session: AsyncSession, message: str, settings_obj: Any) -> dict[str, Any]:
    entity_type, target_value = _extract_target(message)
    if entity_type != "url" or not target_value:
        raise ValueError("Please provide a valid URL (http/https).")

    url_hash = _hash_url(target_value)
    row = await session.get(Url, url_hash)

    latest_analysis_stmt = (
        select(
            UrlAnalysis.label,
            UrlAnalysis.risk_score,
            UrlAnalysis.confidence,
            UrlAnalysis.phishing_indicators,
            UrlAnalysis.brand_target,
        )
        .where(UrlAnalysis.url_hash == url_hash)
        .order_by(UrlAnalysis.detected_at.desc())
        .limit(1)
    )
    latest_analysis = (await session.execute(latest_analysis_stmt)).one_or_none()

    latest_label = latest_analysis[0] if latest_analysis is not None else None
    latest_risk_score = float(latest_analysis[1]) if latest_analysis is not None and latest_analysis[1] is not None else None
    latest_confidence = float(latest_analysis[2]) if latest_analysis is not None and latest_analysis[2] is not None else None
    phishing_indicators = latest_analysis[3] if latest_analysis is not None else None
    brand_target = latest_analysis[4] if latest_analysis is not None else None

    verdict = "unknown"
    if row is not None and getattr(row, "is_blacklisted", False):
        verdict = "phishing"
    elif row is not None and getattr(row, "is_whitelisted", False):
        verdict = "safe"
    elif isinstance(latest_label, str) and latest_label.lower() in {"malicious", "suspicious"}:
        verdict = "phishing"
    elif isinstance(latest_label, str) and latest_label.lower() == "safe":
        verdict = "safe"

    indicators_count = 0
    if isinstance(phishing_indicators, dict):
        indicators_count = len(phishing_indicators)
    elif isinstance(phishing_indicators, list):
        indicators_count = len(phishing_indicators)

    # Live scan the URL with web-agent, then pass result to ai-agent for final confidence/classification.
    web_client = AgentClient(settings_obj.web_agent_url, settings_obj.request_timeout_seconds)
    ai_client = AgentClient(settings_obj.ai_agent_url, settings_obj.ai_agent_timeout_seconds)

    web_result = await web_client.analyze({
        "email_id": "chat-url-check",
        "urls": [target_value],
    })

    web_label = str(web_result.get("label", "unknown")).lower()
    web_risk_score = web_result.get("risk_score")
    web_confidence = web_result.get("confidence")

    provisional_status = "PASS"
    issue_count = 0
    termination_reason = None
    if bool(getattr(row, "is_blacklisted", False)) or web_label == "phishing":
        provisional_status = "DANGER"
        issue_count = 2
        termination_reason = "URL is blacklisted or detected as phishing by web model"

    ai_payload = {
        "subject": "Chat URL check",
        "sender": "chat-user",
        "auth": {},
        "email_agent": {},
        "file_agent": [],
        "web_agent": web_result,
        "issue_count": issue_count,
        "provisional_final_status": provisional_status,
        "termination_reason": termination_reason,
        "urls": [target_value],
    }
    ai_result = await ai_client.analyze(ai_payload)

    return {
        "entity_type": "url",
        "target": target_value,
        "url_hash": url_hash,
        "verdict": verdict,
        "status": str(getattr(row, "status", "unknown")) if row is not None else "unknown",
        "is_blacklisted": bool(getattr(row, "is_blacklisted", False)) if row is not None else False,
        "is_whitelisted": bool(getattr(row, "is_whitelisted", False)) if row is not None else False,
        "latest_analysis_label": latest_label,
        "latest_risk_score": latest_risk_score,
        "latest_confidence": latest_confidence,
        "brand_target": brand_target,
        "indicator_count": indicators_count,
        "web_label": web_label,
        "web_risk_score": web_risk_score,
        "web_confidence": web_confidence,
        "ai_classify": ai_result.get("classify"),
        "ai_reason": ai_result.get("reason"),
        "ai_confidence_percent": ai_result.get("confidence_percent"),
        "ai_provider": ai_result.get("provider"),
        "signals_used": ["list_flags", "url_model_live_scan", "ai_fusion", "content_indicators"],
    }


async def _check_file_hash_reputation(session: AsyncSession, message: str) -> dict[str, Any]:
    entity_type, target_value = _extract_target(message)
    if entity_type != "file_hash" or not target_value:
        raise ValueError("Please provide a valid SHA-256 file hash.")

    file_hash = target_value
    file_row = await session.get(File, file_hash)

    latest_file_risk_stmt = (
        select(FileXgboostResults.risk_level, FileXgboostResults.confidence)
        .join(FileAnalysis, FileAnalysis.analysis_id == FileXgboostResults.file_analysis_id)
        .where(FileAnalysis.file_hash == file_hash)
        .order_by(FileXgboostResults.created_at.desc())
        .limit(1)
    )
    latest_file_risk = (await session.execute(latest_file_risk_stmt)).one_or_none()

    latest_static_stmt = (
        select(
            FileStaticAnalysis.has_macros,
            FileStaticAnalysis.obfuscation_score,
            FileStaticAnalysis.packing_detected,
            FileStaticAnalysis.suspicious_imports,
        )
        .join(FileAnalysis, FileAnalysis.analysis_id == FileStaticAnalysis.file_analysis_id)
        .where(FileAnalysis.file_hash == file_hash)
        .order_by(FileStaticAnalysis.created_at.desc())
        .limit(1)
    )
    latest_static = (await session.execute(latest_static_stmt)).one_or_none()

    verdict = "unknown"
    status_str = str(getattr(file_row, "status", "unknown")) if file_row is not None else "unknown"
    if status_str in {"EntityStatus.malicious", "malicious"}:
        verdict = "phishing"
    elif status_str in {"EntityStatus.benign", "benign"}:
        verdict = "safe"
    elif latest_file_risk is not None and latest_file_risk[0] == RiskLevel.high:
        verdict = "phishing"
    elif latest_file_risk is not None and latest_file_risk[0] == RiskLevel.low:
        verdict = "safe"

    risk_level = latest_file_risk[0].value if latest_file_risk is not None and hasattr(latest_file_risk[0], "value") else None
    confidence = float(latest_file_risk[1]) if latest_file_risk is not None and latest_file_risk[1] is not None else None

    has_macros = latest_static[0] if latest_static is not None else None
    obfuscation_score = float(latest_static[1]) if latest_static is not None and latest_static[1] is not None else None
    packing_detected = latest_static[2] if latest_static is not None else None
    suspicious_imports = latest_static[3] if latest_static is not None else None
    suspicious_imports_count = len(suspicious_imports) if isinstance(suspicious_imports, dict) else None

    return {
        "entity_type": "file_hash",
        "target": file_hash,
        "verdict": verdict,
        "status": status_str,
        "latest_risk_level": risk_level,
        "latest_confidence": confidence,
        "has_macros": has_macros,
        "obfuscation_score": obfuscation_score,
        "packing_detected": packing_detected,
        "suspicious_imports_count": suspicious_imports_count,
        "signals_used": ["file_status", "xgboost_risk", "static_indicators"],
    }


async def _read_only_policy_message(_: AsyncSession, message: str) -> dict[str, Any]:
    return {
        "scope": "read-only",
        "requested": message,
        "allowed": ["check URL safety", "check file hash safety", "show summaries/statistics"],
        "blocked": ["add/remove blacklist", "add/remove whitelist"],
        "note": "Blacklist/whitelist changes must be done from the dedicated management module.",
    }


def _extract_email_content(message: str) -> str:
    matched = EMAIL_CONTENT_PATTERN.search(message)
    if matched:
        content = (matched.group(1) or "").strip()
        if content:
            return content

    # Fallback: if user writes content marker without check/scan verbs.
    lower = message.lower()
    for marker in ["email content", "mail content", "email body", "mail body"]:
        idx = lower.find(marker)
        if idx >= 0:
            tail = message[idx + len(marker) :].lstrip(" :-\n\t")
            if tail.strip():
                return tail.strip()

    raise ValueError("Please provide the email body text after 'check email content:' or 'check mail content:'.")


def _extract_urls_from_text(content: str, limit: int = 5) -> list[str]:
    if not content.strip():
        return []

    urls: list[str] = []
    seen: set[str] = set()
    for matched in URL_PATTERN.finditer(content):
        raw = matched.group(0).rstrip(".,;:)]}\"'")
        if not raw:
            continue
        key = raw.lower()
        if key in seen:
            continue
        seen.add(key)
        urls.append(raw)
        if len(urls) >= max(1, min(limit, 10)):
            break

    if len(urls) < max(1, min(limit, 10)):
        for matched in DOMAIN_PATTERN.finditer(content):
            raw = matched.group(0).rstrip(".,;:)]}\"'")
            if not raw:
                continue
            normalized = raw if raw.lower().startswith(("http://", "https://")) else f"https://{raw}"
            key = normalized.lower()
            if key in seen:
                continue
            seen.add(key)
            urls.append(normalized)
            if len(urls) >= max(1, min(limit, 10)):
                break

    return urls


def _extract_email_content_for_hybrid(message: str) -> str:
    try:
        return _extract_email_content(message)
    except ValueError:
        fallback = message.strip()
        if not fallback:
            raise
        return fallback


def _has_descriptive_text_with_url(message: str) -> bool:
    stripped = URL_PATTERN.sub(" ", message)
    stripped = DOMAIN_PATTERN.sub(" ", stripped)
    words = [word for word in re.split(r"\s+", stripped.strip()) if word]
    return len(words) >= 4


async def _collect_url_signals_for_content(session: AsyncSession, urls: list[str], settings_obj: Any) -> list[dict[str, Any]]:
    if not urls:
        return []

    web_client = AgentClient(settings_obj.web_agent_url, settings_obj.request_timeout_seconds)

    async def _scan_one(target_url: str) -> dict[str, Any]:
        url_hash = _hash_url(target_url)
        row = await session.get(Url, url_hash)

        latest_analysis_stmt = (
            select(
                UrlAnalysis.label,
                UrlAnalysis.risk_score,
                UrlAnalysis.confidence,
                UrlAnalysis.phishing_indicators,
                UrlAnalysis.brand_target,
            )
            .where(UrlAnalysis.url_hash == url_hash)
            .order_by(UrlAnalysis.detected_at.desc())
            .limit(1)
        )
        latest_analysis = (await session.execute(latest_analysis_stmt)).one_or_none()

        latest_label = latest_analysis[0] if latest_analysis is not None else None
        latest_risk_score = float(latest_analysis[1]) if latest_analysis is not None and latest_analysis[1] is not None else None
        latest_confidence = float(latest_analysis[2]) if latest_analysis is not None and latest_analysis[2] is not None else None
        phishing_indicators = latest_analysis[3] if latest_analysis is not None else None
        brand_target = latest_analysis[4] if latest_analysis is not None else None

        verdict = "unknown"
        if row is not None and getattr(row, "is_blacklisted", False):
            verdict = "phishing"
        elif row is not None and getattr(row, "is_whitelisted", False):
            verdict = "safe"
        elif isinstance(latest_label, str) and latest_label.lower() in {"malicious", "suspicious"}:
            verdict = "phishing"
        elif isinstance(latest_label, str) and latest_label.lower() == "safe":
            verdict = "safe"

        indicators_count = 0
        if isinstance(phishing_indicators, dict):
            indicators_count = len(phishing_indicators)
        elif isinstance(phishing_indicators, list):
            indicators_count = len(phishing_indicators)

        web_result = await web_client.analyze({
            "email_id": "chat-email-content-url-check",
            "urls": [target_url],
        })
        web_label = str(web_result.get("label", "unknown")).lower()
        web_risk_score = web_result.get("risk_score")
        web_confidence = web_result.get("confidence")

        if verdict == "unknown" and web_label == "phishing":
            verdict = "phishing"
        elif verdict == "unknown" and web_label == "safe":
            verdict = "safe"

        return {
            "target": target_url,
            "url_hash": url_hash,
            "verdict": verdict,
            "status": str(getattr(row, "status", "unknown")) if row is not None else "unknown",
            "is_blacklisted": bool(getattr(row, "is_blacklisted", False)) if row is not None else False,
            "is_whitelisted": bool(getattr(row, "is_whitelisted", False)) if row is not None else False,
            "latest_analysis_label": latest_label,
            "latest_risk_score": latest_risk_score,
            "latest_confidence": latest_confidence,
            "brand_target": brand_target,
            "indicator_count": indicators_count,
            "web_label": web_label,
            "web_risk_score": web_risk_score,
            "web_confidence": web_confidence,
        }

    return await asyncio.gather(*[_scan_one(url) for url in urls])


async def _check_email_content_ai(session: AsyncSession, message: str, settings_obj: Any) -> dict[str, Any]:
    content = _extract_email_content(message)
    urls = _extract_urls_from_text(content)

    ai_client = AgentClient(settings_obj.ai_agent_url, settings_obj.ai_agent_timeout_seconds)
    content_payload = {
        "subject": "Chat email-content check",
        "sender": "chat-user",
        "auth": {},
        "email_agent": {
            "email_content": content,
            "source": "chat_manual_input",
        },
        "file_agent": [],
        "web_agent": {},
        "issue_count": 0,
        "provisional_final_status": "PASS",
        "termination_reason": None,
        "urls": urls,
    }

    if urls:
        content_ai_result, url_signals = await asyncio.gather(
            ai_client.analyze(content_payload),
            _collect_url_signals_for_content(session, urls, settings_obj),
        )

        dangerous_url_count = sum(1 for item in url_signals if str(item.get("verdict", "")).lower() == "phishing")
        suspicious_url_count = sum(
            1
            for item in url_signals
            if str(item.get("latest_analysis_label", "")).lower() == "suspicious"
        )

        combined_payload = {
            "subject": "Chat email-content + URL combined check",
            "sender": "chat-user",
            "auth": {},
            "email_agent": {
                "email_content": content,
                "source": "chat_manual_input",
                "content_ai": {
                    "classify": content_ai_result.get("classify"),
                    "reason": content_ai_result.get("reason"),
                    "confidence_percent": content_ai_result.get("confidence_percent"),
                },
            },
            "file_agent": [],
            "web_agent": {
                "url_signals": url_signals,
                "url_count": len(urls),
                "dangerous_url_count": dangerous_url_count,
                "suspicious_url_count": suspicious_url_count,
            },
            "issue_count": 2 if dangerous_url_count > 0 else (1 if suspicious_url_count > 0 else 0),
            "provisional_final_status": (
                "DANGER"
                if dangerous_url_count > 0
                else ("WARNING" if suspicious_url_count > 0 else "PASS")
            ),
            "termination_reason": (
                "Embedded URL(s) detected as phishing"
                if dangerous_url_count > 0
                else ("Embedded URL(s) look suspicious" if suspicious_url_count > 0 else None)
            ),
            "urls": urls,
        }

        try:
            ai_result = await ai_client.analyze(combined_payload)
        except Exception:
            ai_result = content_ai_result
            ai_result["summary"] = str(ai_result.get("summary") or ai_result.get("reason") or "").strip()
            ai_result["summary"] = (
                (ai_result["summary"] + " ").strip()
                + f"URL checks completed for {len(urls)} URL(s); dangerous={dangerous_url_count}, suspicious={suspicious_url_count}."
            )
    else:
        url_signals = []
        ai_result = await ai_client.analyze(content_payload)

    raw_reason = str(ai_result.get("reason") or "").strip()
    raw_summary = str(ai_result.get("summary") or "").strip()

    clean_reason = raw_reason if raw_reason else "Content-only check indicates suspicious/phishing language patterns."
    clean_summary = raw_summary if raw_summary else clean_reason

    return {
        "entity_type": "email_content",
        "content_preview": content[:280],
        "embedded_url_count": len(urls),
        "embedded_urls": urls,
        "url_signals": url_signals,
        "hybrid_mode": bool(urls),
        "classify": ai_result.get("classify"),
        "reason": clean_reason,
        "summary": clean_summary,
        "confidence_percent": ai_result.get("confidence_percent"),
        "provider": ai_result.get("provider"),
        "risk_factors": ai_result.get("risk_factors") or [],
        "tool_trace": ai_result.get("tool_trace") or [],
        "auth_evaluated": False,
    }


async def _check_email_content_url_hybrid(session: AsyncSession, message: str, settings_obj: Any) -> dict[str, Any]:
    content = _extract_email_content_for_hybrid(message)
    urls = _extract_urls_from_text(content)

    if not urls:
        entity_type, target_value = _extract_target(message)
        if entity_type == "url" and target_value:
            urls = [target_value]

    if not urls:
        return await _check_email_content_ai(session, message, settings_obj)

    url_signals = await _collect_url_signals_for_content(session, urls, settings_obj)

    dangerous_url_count = sum(1 for item in url_signals if str(item.get("verdict", "")).lower() == "phishing")
    suspicious_url_count = sum(
        1
        for item in url_signals
        if str(item.get("latest_analysis_label", "")).lower() == "suspicious"
    )

    ai_client = AgentClient(settings_obj.ai_agent_url, settings_obj.ai_agent_timeout_seconds)
    
    combined_payload = {
        "subject": "Chat email-content + URL combined check",
        "sender": "chat-user",
        "auth": {},
        "email_agent": {
            "email_content": content,
            "source": "chat_manual_input",
        },
        "file_agent": [],
        "web_agent": {
            "url_signals": url_signals,
            "url_count": len(urls),
            "dangerous_url_count": dangerous_url_count,
            "suspicious_url_count": suspicious_url_count,
        },
        "issue_count": 2 if dangerous_url_count > 0 else (1 if suspicious_url_count > 0 else 0),
        "provisional_final_status": (
            "DANGER"
            if dangerous_url_count > 0
            else ("WARNING" if suspicious_url_count > 0 else "PASS")
        ),
        "termination_reason": (
            "Embedded URL(s) detected as phishing"
            if dangerous_url_count > 0
            else ("Embedded URL(s) look suspicious" if suspicious_url_count > 0 else None)
        ),
        "urls": urls,
    }

    try:
        ai_result = await ai_client.analyze(combined_payload)
    except Exception as e:
        ai_result = {
            "classify": "unknown",
            "reason": f"Hybrid check completed with error: {str(e)}",
            "summary": f"URL checks: dangerous={dangerous_url_count}, suspicious={suspicious_url_count}",
            "confidence_percent": 0,
        }

    raw_reason = str(ai_result.get("reason") or "").strip()
    raw_summary = str(ai_result.get("summary") or "").strip()

    clean_reason = raw_reason if raw_reason else "Hybrid content+URL check indicates suspicious/phishing patterns."
    clean_summary = raw_summary if raw_summary else clean_reason

    return {
        "entity_type": "email_content",
        "content_preview": content[:280],
        "embedded_url_count": len(urls),
        "embedded_urls": urls,
        "url_signals": url_signals,
        "hybrid_mode": True,
        "classify": ai_result.get("classify"),
        "reason": clean_reason,
        "summary": clean_summary,
        "confidence_percent": ai_result.get("confidence_percent"),
        "provider": ai_result.get("provider"),
        "risk_factors": ai_result.get("risk_factors") or [],
        "tool_trace": ai_result.get("tool_trace") or [],
        "auth_evaluated": False,
    }


async def _kpi_summary(session: AsyncSession, days: int = 7) -> dict[str, Any]:
    cutoff = datetime.utcnow() - timedelta(days=max(1, min(days, 90)))

    stmt = select(
        func.count(ScanHistory.id),
        func.sum(case((ScanHistory.final_status == "PASS", 1), else_=0)),
        func.avg(ScanHistory.issue_count),
        func.avg(ScanHistory.duration_ms),
    ).where(ScanHistory.timestamp >= cutoff)

    total, passed, avg_issues, avg_duration = (await session.execute(stmt)).one()
    total = int(total or 0)
    passed = int(passed or 0)
    danger = max(total - passed, 0)

    return {
        "window_days": days,
        "total_scans": total,
        "pass_count": passed,
        "danger_or_warning_count": danger,
        "pass_rate_percent": round((passed / total) * 100, 2) if total > 0 else 0.0,
        "avg_issue_count": round(float(avg_issues or 0.0), 3),
        "avg_duration_ms": round(float(avg_duration or 0.0), 2),
    }


async def _risky_senders_domains(session: AsyncSession, limit: int = 5) -> dict[str, Any]:
    safe_limit = max(1, min(limit, 20))

    senders_stmt = (
        select(Email.sender, func.count(Email.id).label("count"))
        .where(Email.final_verdict != VerdictType.safe)
        .where(Email.sender.is_not(None))
        .group_by(Email.sender)
        .order_by(func.count(Email.id).desc())
        .limit(safe_limit)
    )
    sender_rows = (await session.execute(senders_stmt)).all()

    domains_stmt = (
        select(Url.raw_url, func.count(UrlAnalysis.url_analysis_id).label("count"))
        .join(UrlAnalysis, UrlAnalysis.url_hash == Url.url_hash)
        .where(UrlAnalysis.label != "safe")
        .group_by(Url.raw_url)
        .order_by(func.count(UrlAnalysis.url_analysis_id).desc())
        .limit(safe_limit)
    )
    domain_rows = (await session.execute(domains_stmt)).all()

    return {
        "top_senders": [{"sender": sender or "unknown", "count": int(count)} for sender, count in sender_rows],
        "top_risky_urls": [{"url": url, "count": int(count)} for url, count in domain_rows],
    }


async def _top_senders_receivers(session: AsyncSession, days: int = 7, limit: int = 5) -> dict[str, Any]:
    cutoff = datetime.utcnow() - timedelta(days=max(1, min(days, 90)))
    safe_limit = max(1, min(limit, 20))

    senders_stmt = (
        select(Email.sender, func.count(Email.id).label("count"))
        .where(Email.sender.is_not(None))
        .where(Email.processed_at >= cutoff)
        .group_by(Email.sender)
        .order_by(func.count(Email.id).desc())
        .limit(safe_limit)
    )
    sender_rows = (await session.execute(senders_stmt)).all()

    receivers_stmt = (
        select(Email.receiver, func.count(Email.id).label("count"))
        .where(Email.receiver.is_not(None))
        .where(Email.processed_at >= cutoff)
        .group_by(Email.receiver)
        .order_by(func.count(Email.id).desc())
        .limit(safe_limit)
    )
    receiver_rows = (await session.execute(receivers_stmt)).all()

    return {
        "window_days": days,
        "top_senders": [{"sender": sender or "unknown", "count": int(count)} for sender, count in sender_rows],
        "top_receivers": [{"receiver": receiver or "unknown", "count": int(count)} for receiver, count in receiver_rows],
    }


async def _file_risk_summary(session: AsyncSession, days: int = 7) -> dict[str, Any]:
    cutoff = datetime.utcnow() - timedelta(days=max(1, min(days, 90)))
    stmt = select(
        func.sum(case((FileXgboostResults.risk_level == RiskLevel.high, 1), else_=0)),
        func.sum(case((FileXgboostResults.risk_level == RiskLevel.medium, 1), else_=0)),
        func.sum(case((FileXgboostResults.risk_level == RiskLevel.low, 1), else_=0)),
    ).where(FileXgboostResults.created_at >= cutoff)

    high_count, medium_count, low_count = (await session.execute(stmt)).one()

    return {
        "window_days": days,
        "high_risk_count": int(high_count or 0),
        "medium_risk_count": int(medium_count or 0),
        "low_risk_count": int(low_count or 0),
    }


async def _url_threat_summary(session: AsyncSession, days: int = 7) -> dict[str, Any]:
    cutoff = datetime.utcnow() - timedelta(days=max(1, min(days, 90)))
    stmt = select(
        func.sum(case((UrlAnalysis.label == "malicious", 1), else_=0)),
        func.sum(case((UrlAnalysis.label == "suspicious", 1), else_=0)),
        func.sum(case((UrlAnalysis.label == "safe", 1), else_=0)),
    ).where(UrlAnalysis.created_at >= cutoff)

    malicious_count, suspicious_count, safe_count = (await session.execute(stmt)).one()

    return {
        "window_days": days,
        "malicious_count": int(malicious_count or 0),
        "suspicious_count": int(suspicious_count or 0),
        "safe_count": int(safe_count or 0),
    }


async def _ai_confidence_summary(session: AsyncSession, days: int = 7) -> dict[str, Any]:
    cutoff = datetime.utcnow() - timedelta(days=max(1, min(days, 90)))

    stmt = select(
        func.avg(AiAnalysis.confidence_percent),
        func.sum(case((AiAnalysis.classification == "dangerous", 1), else_=0)),
        func.sum(case((AiAnalysis.classification == "suspicious", 1), else_=0)),
        func.sum(case((AiAnalysis.classification == "safe", 1), else_=0)),
    ).where(AiAnalysis.created_at >= cutoff)

    avg_conf, dangerous_count, suspicious_count, safe_count = (await session.execute(stmt)).one()

    return {
        "window_days": days,
        "average_confidence_percent": round(float(avg_conf or 0.0), 2),
        "dangerous_count": int(dangerous_count or 0),
        "suspicious_count": int(suspicious_count or 0),
        "safe_count": int(safe_count or 0),
    }


def infer_tool_name(message: str) -> str | None:
    text = message.lower()
    has_email_content_marker = any(token in text for token in ["email content", "mail content", "email body", "mail body"])
    entity_type, _ = _extract_target(message)
    if has_email_content_marker and any(token in text for token in ["check", "scan", "analyze", "analyse", "is"]):
        if entity_type == "url":
            return "check_email_content_url_hybrid"
        return "check_email_content_ai"
    if has_email_content_marker:
        if entity_type == "url":
            return "check_email_content_url_hybrid"
        return "check_email_content_ai"
    check_intent = any(
        token in text
        for token in ["check", "is", "safe", "phishing", "malicious", "verify", "status", "risk", "scan", "analyze"]
    )

    if any(token in text for token in ["blacklist", "whitelist"]) and any(
        token in text for token in ["add", "remove", "delete", "insert", "allow", "block", "unblock", "delist"]
    ):
        return "read_only_policy"
    if entity_type == "url" and check_intent:
        if _has_descriptive_text_with_url(message):
            return "check_email_content_url_hybrid"
        return "check_url_reputation"
    if entity_type == "file_hash" and check_intent:
        return "check_file_hash_reputation"
    if any(
        token in text
        for token in [
            "most sender",
            "most receiver",
            "top sender",
            "top receiver",
            "sender stats",
            "receiver stats",
            "communication stats",
        ]
    ):
        return "top_senders_receivers"
    if any(token in text for token in ["kpi", "pass rate", "overview", "summary", "total scan"]):
        return "kpi_summary"
    if any(token in text for token in ["sender", "domain", "top risky", "risky sender"]):
        return "risky_senders_domains"
    if any(token in text for token in ["attachment", "file risk", "xgboost", "file summary"]):
        return "file_risk_summary"
    if any(token in text for token in ["url", "web threat", "phishing link", "link risk"]):
        return "url_threat_summary"
    if any(token in text for token in ["confidence", "ai confidence", "classification"]):
        return "ai_confidence_summary"
    return None


def infer_attachment_scan_intent(message: str) -> bool:
    text = message.strip().lower()
    if not text:
        return False

    scan_terms = [
        "scan",
        "analyze",
        "analyse",
        "inspect",
        "check",
        "triage",
        "verdict",
        "risk",
        "safe",
        "unsafe",
        "malicious",
        "phishing",
    ]
    question_phrases = [
        "is this safe",
        "is it safe",
        "is this file safe",
        "is this malicious",
        "is this phishing",
        "can you check this",
    ]

    if any(phrase in text for phrase in question_phrases):
        return True
    return any(term in text for term in scan_terms)


def detect_chat_intent(message: str, has_pending_attachment: bool = False) -> dict[str, Any]:
    message_text = message.strip()
    detected_tool = infer_tool_name(message_text)

    should_trigger_attachment_scan = False
    reason = "No attachment scan intent detected"
    if has_pending_attachment:
        should_trigger_attachment_scan = infer_attachment_scan_intent(message_text)
        reason = (
            "Attachment scan intent detected"
            if should_trigger_attachment_scan
            else "Attachment is pending but message did not request a scan"
        )
    elif detected_tool:
        reason = f"Detected tool: {detected_tool}"

    return {
        "detected_tool": detected_tool,
        "should_trigger_attachment_scan": should_trigger_attachment_scan,
        "reason": reason,
    }


def infer_days(message: str, fallback: int = 7) -> int:
    text = message.lower()
    for token in ["30 day", "30d", "month"]:
        if token in text:
            return 30
    for token in ["14 day", "2 week", "14d"]:
        if token in text:
            return 14
    for token in ["24h", "1 day", "today"]:
        if token in text:
            return 1
    return fallback


async def run_tool(tool_name: str, session: AsyncSession, message: str, settings_obj: Any | None = None) -> dict[str, Any]:
    days = infer_days(message)

    if tool_name == "read_only_policy":
        return await _read_only_policy_message(session, message)
    if tool_name == "check_email_content_ai":
        if settings_obj is None:
            raise ValueError("AI settings are required for email content checks")
        return await _check_email_content_ai(session, message, settings_obj)
    if tool_name == "check_email_content_url_hybrid":
        if settings_obj is None:
            raise ValueError("AI settings are required for hybrid content+URL checks")
        return await _check_email_content_url_hybrid(session, message, settings_obj)
    if tool_name == "check_url_reputation":
        if settings_obj is None:
            raise ValueError("Settings are required for URL reputation checks")
        return await _check_url_reputation(session, message, settings_obj)
    if tool_name == "check_file_hash_reputation":
        return await _check_file_hash_reputation(session, message)
    if tool_name == "top_senders_receivers":
        return await _top_senders_receivers(session, days)
    if tool_name == "kpi_summary":
        return await _kpi_summary(session, days)
    if tool_name == "risky_senders_domains":
        return await _risky_senders_domains(session)
    if tool_name == "file_risk_summary":
        return await _file_risk_summary(session, days)
    if tool_name == "url_threat_summary":
        return await _url_threat_summary(session, days)
    if tool_name == "ai_confidence_summary":
        return await _ai_confidence_summary(session, days)

    raise ValueError(f"Unsupported tool: {tool_name}")


def summarize_tool_result(tool_name: str, data: dict[str, Any]) -> str:
    if tool_name in {"check_email_content_ai", "check_email_content_url_hybrid"}:
        url_count = int(data.get("embedded_url_count") or 0)
        url_signals = data.get("url_signals") if isinstance(data.get("url_signals"), list) else []
        phishing_urls = sum(1 for item in url_signals if isinstance(item, dict) and str(item.get("verdict", "")).lower() == "phishing")
        suspicious_urls = sum(
            1
            for item in url_signals
            if isinstance(item, dict) and str(item.get("latest_analysis_label", "")).lower() == "suspicious"
        )

        lines = [
            "Email Content Check",
            f"- Classification: {data.get('classify', 'unknown')}",
            f"- Confidence: {data.get('confidence_percent', 'unknown')}%",
            f"- Reason: {data.get('reason', 'No reason available')}",
            "- Auth Headers (SPF/DKIM/DMARC): not evaluated in content-only mode",
        ]

        if url_count > 0:
            lines.extend(
                [
                    "- Hybrid URL Analysis: enabled",
                    f"- Embedded URLs: {url_count}",
                    f"- URL Risk Summary: phishing={phishing_urls}, suspicious={suspicious_urls}",
                ]
            )

        return "\n".join(lines)

    if tool_name == "read_only_policy":
        return (
            "This chat is read-only for list management. I can check whether a URL or file hash looks safe/phishing, "
            "but I cannot add/remove blacklist or whitelist entries here."
        )

    if tool_name == "check_url_reputation":
        return "\n".join(
            [
                "URL Safety Check",
                f"- URL: {data.get('target')}",
                f"- Verdict: {data.get('verdict', 'unknown')}",
                f"- Blacklist: {data.get('is_blacklisted')} | Whitelist: {data.get('is_whitelisted')}",
                f"- Web Model: label={data.get('web_label')}, risk={data.get('web_risk_score')}, confidence={data.get('web_confidence')}",
                f"- AI Result: classify={data.get('ai_classify')}, confidence={data.get('ai_confidence_percent')}%",
                f"- Indicators Found: {data.get('indicator_count', 0)}",
            ]
        )

    if tool_name == "check_file_hash_reputation":
        return "\n".join(
            [
                "File Hash Safety Check",
                f"- SHA-256: {data.get('target')}",
                f"- Verdict: {data.get('verdict', 'unknown')}",
                f"- Stored Status: {data.get('status', 'unknown')}",
                f"- Risk: level={data.get('latest_risk_level')}, confidence={data.get('latest_confidence')}",
                f"- Static Signals: has_macros={data.get('has_macros')}, obfuscation={data.get('obfuscation_score')}, packing={data.get('packing_detected')}",
            ]
        )

    if tool_name == "top_senders_receivers":
        sender_text = ", ".join([f"{item['sender']} ({item['count']})" for item in data.get("top_senders", [])]) or "none"
        receiver_text = ", ".join([f"{item['receiver']} ({item['count']})" for item in data.get("top_receivers", [])]) or "none"
        return (
            f"Top senders/receivers for last {data['window_days']} days: "
            f"senders={sender_text}. receivers={receiver_text}."
        )

    if tool_name == "kpi_summary":
        return (
            f"KPI summary for last {data['window_days']} days: total scans={data['total_scans']}, "
            f"pass rate={data['pass_rate_percent']}%, avg issues={data['avg_issue_count']}, "
            f"avg duration={data['avg_duration_ms']} ms."
        )

    if tool_name == "risky_senders_domains":
        sender_text = ", ".join([f"{item['sender']} ({item['count']})" for item in data.get("top_senders", [])]) or "none"
        url_text = ", ".join([f"{item['url']} ({item['count']})" for item in data.get("top_risky_urls", [])]) or "none"
        return f"Top risky senders: {sender_text}. Top risky URLs: {url_text}."

    if tool_name == "file_risk_summary":
        return (
            f"File risk summary for last {data['window_days']} days: "
            f"high={data['high_risk_count']}, medium={data['medium_risk_count']}, low={data['low_risk_count']}."
        )

    if tool_name == "url_threat_summary":
        return (
            f"URL threat summary for last {data['window_days']} days: malicious={data['malicious_count']}, "
            f"suspicious={data['suspicious_count']}, safe={data['safe_count']}."
        )

    if tool_name == "ai_confidence_summary":
        return (
            f"AI confidence summary for last {data['window_days']} days: avg confidence={data['average_confidence_percent']}%, "
            f"dangerous={data['dangerous_count']}, suspicious={data['suspicious_count']}, safe={data['safe_count']}."
        )

    return "I could not summarize the requested dataset."
