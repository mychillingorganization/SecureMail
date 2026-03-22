"""Deep-dive analysis pipeline: when DANGER detected, analyze with LLM for detailed reasoning."""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from email_agent.protocol_verifier import ProtocolVerifier
from orchestra.clients import AgentClient
from orchestra.config import Settings
from orchestra.models import AuditLog, Email, EmailFile, EmailStatus, EmailUrl, EntityStatus, File, Url, VerdictType
from orchestra.schemas import ScanResponse
from orchestra.threat_intel import ThreatIntelScanner
from utils.parse_eml import parse_eml


def _hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _hash_url(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8", errors="ignore")).hexdigest()


def _verdict_type_from_status(status: str) -> VerdictType:
    if status == "DANGER":
        return VerdictType.malicious
    if status == "WARNING":
        return VerdictType.suspicious
    return VerdictType.safe


async def _upsert_url(session: AsyncSession, raw_url: str, status: EntityStatus) -> str:
    url_hash = _hash_url(raw_url)
    db_obj = await session.get(Url, url_hash)
    if db_obj is None:
        db_obj = Url(url_hash=url_hash, raw_url=raw_url, status=status)
        session.add(db_obj)
    else:
        db_obj.status = status
    return url_hash


async def _upsert_file(session: AsyncSession, file_hash: str, file_path: str, status: EntityStatus) -> str:
    db_obj = await session.get(File, file_hash)
    if db_obj is None:
        db_obj = File(file_hash=file_hash, file_path=file_path, status=status)
        session.add(db_obj)
    else:
        db_obj.status = status
        db_obj.file_path = file_path
    return file_hash


class DeepDiveAnalyzer:
    """LLM-based deep-dive analyzer for DANGER-flagged emails."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def analyze_danger(
        self, 
        email_subject: str,
        body_snippet: str,
        auth_result: dict[str, Any],
        agent_signals: dict[str, Any],
        urls: list[str],
    ) -> dict[str, Any]:
        """Deeply analyze why email is flagged as DANGER."""
        api_key = self._settings.google_ai_studio_api_key
        if not api_key:
            return {
                "risk_factors": ["Không thể phân tích chi tiết"],
                "simple_summary": "Không cấu hình Google API key",
                "confidence_percent": 0,
                "what_to_do": "Cấu hình API key",
            }

        model = self._settings.google_ai_studio_model
        base_url = self._settings.google_ai_studio_base_url.rstrip("/")
        
        # Build full URL
        url = f"{base_url}/models/{model}:generateContent?key={api_key}"

        prompt = (
            "You are a leading cybersecurity expert. Analyze THIS EMAIL and explain why it is DANGEROUS.\n\n"
            "CRITICAL: Do NOT provide generic analysis. Analyze ONLY BASED ON:\n"
            "1. ACTUAL EMAIL CONTENT (subject, body, links)\n"
            "2. AUTHENTICATION STATUS (SPF/DKIM/DMARC)\n"
            "3. SPECIFIC SOFT INDICATORS (urgency, emotional triggers, suspicious links, etc)\n\n"
            "EMAIL TO ANALYZE:\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"Subject: {email_subject}\n"
            f"Body:\n{body_snippet}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"AUTHENTICATION STATUS:\n"
            f"- SPF: {'✓ PASS (sender authorized)' if auth_result.get('spf', {}).get('pass') else '✗ FAIL (possible spoofing)'}\n"
            f"- DKIM: {'✓ PASS (valid signature)' if auth_result.get('dkim', {}).get('pass') else '✗ FAIL (not authenticated)'}\n"
            f"- DMARC: {'✓ PASS (legitimate policy)' if auth_result.get('dmarc', {}).get('pass') else '✗ FAIL (policy violation)'}\n\n"
            f"URLs found: {urls if urls else '(None detected)'}\n\n"
            "RESPOND IN ENGLISH. Output ONLY valid JSON:\n"
            "{\n"
            '  "risk_factors": [\n'
            '    "Specific indicator 1 (derived from email content)",\n'
            '    "Specific indicator 2 (derived from email content)",\n'
            '    "..."\n'
            '  ],\n'
            '  "confidence_percent": <0-100>,\n'
            '  "simple_summary": "1-2 sentences explaining WHY dangerous based on SPECIFIC EMAIL CONTENT",\n'
            '  "what_to_do": "Recommended action"\n'
            "}\n"
        )

        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.3,
                "responseMimeType": "application/json",
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self._settings.request_timeout_seconds) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                body = response.json()

            text = str(body["candidates"][0]["content"]["parts"][0]["text"])
            parsed = json.loads(text)
            result = self._normalize_deepdive(parsed)
            return result
        except Exception as exc:
            return {
                "risk_factors": ["Không thể phân tích chi tiết"],
                "simple_summary": f"Hệ thống phát hiện email nguy hiểm nhưng không thể giải thích chi tiết",
                "confidence_percent": 50,
                "what_to_do": "Đánh dấu là thư rác hoặc xóa",
            }

    def _normalize_deepdive(self, payload: dict[str, Any]) -> dict[str, Any]:
        risk_factors = payload.get("risk_factors", [])
        if not isinstance(risk_factors, list):
            risk_factors = [str(risk_factors)]

        confidence = payload.get("confidence_percent", 0)
        try:
            confidence = max(0, min(100, int(confidence)))
        except Exception:
            confidence = 0

        return {
            "risk_factors": [str(x) for x in risk_factors],
            "confidence_percent": confidence,
            "simple_summary": str(payload.get("simple_summary", "Email không an toàn")),
            "what_to_do": str(payload.get("what_to_do", "Xóa hoặc đánh dấu là thư rác")),
        }


async def execute_pipeline_deepdive(
    email_path: str,
    session: AsyncSession,
    settings: Settings,
    user_accepts_danger: bool = False,
) -> ScanResponse:
    """Pipeline with deep-dive analysis when DANGER is detected.
    
    Steps:
    1. Parse email
    2. Run protocol verification
    3. Collect agent signals
    4. If any signal indicates DANGER → trigger LLM deep-dive analysis
    5. Return enhanced response with detailed reasoning
    """

    logs: list[str] = []
    email_path_obj = Path(email_path)

    with tempfile.TemporaryDirectory(prefix="securemail-deepdive-") as temp_dir:
        attachment_dir = Path(temp_dir) / "attachments"
        attachment_dir.mkdir(parents=True, exist_ok=True)

        parsed = parse_eml(email_path_obj, attachment_dir)
        logs.append("[INFO] Step 1: Email parsed")

        protocol_verifier = ProtocolVerifier()
        auth_result = protocol_verifier.verify_from_eml_file(email_path_obj)
        logs.append("[INFO] Step 2: Protocol verification completed")

        threat_scanner = ThreatIntelScanner(
            {item.strip() for item in settings.threat_intel_malicious_hashes.split(",") if item.strip()}
        )
        attachment_hashes: list[dict[str, Any]] = []
        for attachment in attachment_dir.iterdir():
            if not attachment.is_file():
                continue
            file_hash = _hash_file(attachment)
            triage = threat_scanner.scan_hash(file_hash)
            attachment_hashes.append(
                {
                    "path": str(attachment),
                    "sha256": file_hash,
                    "triage_verdict": triage.verdict,
                }
            )
        logs.append("[INFO] Step 3: Hash triage completed")

        email_client = AgentClient(settings.email_agent_url, settings.request_timeout_seconds)
        
        body_text = "\n\n".join(parsed.plain_parts)
        email_payload = {
            "email_id": parsed.subject,
            "subject": parsed.subject,
            "headers": parsed.auth_headers,
            "body_text": body_text,
            "timestamp": parsed.sent_at,
        }

        email_analysis: dict[str, Any] = {}
        try:
            email_analysis = await email_client.analyze(email_payload)
            logs.append(f"[INFO] Step 4: EmailAgent analyzed (risk={email_analysis.get('risk_score', 0)})")
        except Exception as exc:
            email_analysis = {"error": str(exc), "unavailable": True}
            logs.append(f"[INFO] Step 4: EmailAgent unavailable ({exc})")

        urls = sorted(parsed.urls)
        
        # Determine if DANGER detected from signals
        is_danger = False
        danger_reason = ""
        
        email_risk = float(email_analysis.get("risk_score", 0.0))
        if email_risk >= 0.5:  # More sensitive threshold for deep-dive analysis
            is_danger = True
            danger_reason = f"EmailAgent high risk score: {email_risk}"
        
        spf_ok = bool(auth_result.get("spf", {}).get("pass", False))
        dkim_ok = bool(auth_result.get("dkim", {}).get("pass", False))
        dmarc_ok = bool(auth_result.get("dmarc", {}).get("pass", False))
        if not (spf_ok and dkim_ok and dmarc_ok):
            is_danger = True
            danger_reason = f"Auth failed: SPF={spf_ok} DKIM={dkim_ok} DMARC={dmarc_ok}"

        final_status = "DANGER" if is_danger else "PASS"
        termination_reason = None
        deepdive_analysis = {}

        if is_danger:
            analyzer = DeepDiveAnalyzer(settings)
            deepdive_analysis = await analyzer.analyze_danger(
                email_subject=parsed.subject,
                body_snippet=body_text[:500],
                auth_result=auth_result,
                agent_signals={"email_agent": email_analysis},
                urls=urls,
            )
            logs.append(f"[DANGER] LLM analysis: {deepdive_analysis.get('simple_summary', '')}")
            logs.append(f"[DANGER] Reason: {', '.join(deepdive_analysis.get('risk_factors', []))}")
            logs.append(f"[DANGER] Confidence: {deepdive_analysis.get('confidence_percent', 0)}%")
            logs.append(f"[ACTION] {deepdive_analysis.get('what_to_do', '')}")
            termination_reason = deepdive_analysis.get("simple_summary", danger_reason)

        issue_count = 1 if is_danger else 0

        # Persist to DB
        email_row = Email(
            message_id=parsed.subject,
            sender=parsed.auth_headers.get("from", [None])[0] if parsed.auth_headers.get("from") else None,
            receiver=parsed.auth_headers.get("to", [None])[0] if parsed.auth_headers.get("to") else None,
            status=EmailStatus.quarantined if final_status == "DANGER" else EmailStatus.completed,
            total_risk_score=float(issue_count),
            final_verdict=_verdict_type_from_status(final_status),
        )
        session.add(email_row)
        await session.flush()

        session.add(
            AuditLog(
                email_id=email_row.id,
                agent_name="DeepDiveOrchestrator",
                reasoning_trace={
                    "is_danger": is_danger,
                    "danger_reason": danger_reason,
                    "deepdive_analysis": deepdive_analysis,
                    "logs": logs,
                },
                cryptographic_hash=None,
            )
        )

        default_status = EntityStatus.malicious if final_status == "DANGER" and user_accepts_danger else EntityStatus.unknown

        for raw_url in urls:
            url_hash = await _upsert_url(session, raw_url, default_status)
            session.add(EmailUrl(email_id=email_row.id, url_hash=url_hash))

        for attachment in attachment_hashes:
            attachment_hash = str(attachment.get("sha256", ""))
            attachment_path = str(attachment.get("path", ""))
            if not attachment_hash:
                continue
            file_hash = await _upsert_file(session, attachment_hash, attachment_path, default_status)
            session.add(EmailFile(email_id=email_row.id, file_hash=file_hash))

        await session.commit()

    return ScanResponse(
        final_status=final_status,
        issue_count=issue_count,
        termination_reason=termination_reason,
        execution_logs=logs,
    )
