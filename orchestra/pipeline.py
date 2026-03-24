from __future__ import annotations

import hashlib
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from email_agent.protocol_verifier import ProtocolVerifier
from orchestra.clients import AgentClient
from orchestra.config import Settings
from orchestra.early_termination import should_terminate
from orchestra.models import AuditLog, Email, EmailFile, EmailStatus, EmailUrl, EntityStatus, File, Url, VerdictType
from orchestra.risk_scorer import final_status_from_issue_count
from orchestra.schemas import ScanResponse
from orchestra.threat_intel import ThreatIntelScanner
from utils.parse_eml import parse_eml


@dataclass
class PipelineDependencies:
    settings: Settings
    email_client: AgentClient
    file_client: AgentClient
    web_client: AgentClient
    threat_scanner: ThreatIntelScanner
    protocol_verifier: ProtocolVerifier


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


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


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


async def execute_pipeline(email_path: str, session: AsyncSession, deps: PipelineDependencies, user_accepts_danger: bool = False) -> ScanResponse:
    issue_count = 0
    termination_reason: str | None = None
    logs: list[str] = []

    email_path_obj = Path(email_path)
    with tempfile.TemporaryDirectory(prefix="securemail-orch-") as temp_dir:
        attachment_dir = Path(temp_dir) / "attachments"
        attachment_dir.mkdir(parents=True, exist_ok=True)

        parsed = parse_eml(email_path_obj, attachment_dir)
        logs.append("[INFO] Step 1: utils.parse_eml() - SUCCESS")

        auth_result = deps.protocol_verifier.verify_from_eml_file(email_path_obj)
        spf_ok = bool(auth_result.get("spf", {}).get("pass", False))
        dkim_ok = bool(auth_result.get("dkim", {}).get("pass", False))
        dmarc_ok = bool(auth_result.get("dmarc", {}).get("pass", False))
        auth_failed = not (spf_ok and dkim_ok and dmarc_ok)
        logs.append(f"[INFO] Step 2: protocol verification - SPF={spf_ok} DKIM={dkim_ok} DMARC={dmarc_ok}")
        logs.append(
            "[INFO] Step 2 details: "
            f"SPF({auth_result.get('spf', {}).get('result', 'unknown')}): {auth_result.get('spf', {}).get('detail', '')} | "
            f"DKIM({auth_result.get('dkim', {}).get('result', 'unknown')}): {auth_result.get('dkim', {}).get('detail', '')} | "
            f"DMARC({auth_result.get('dmarc', {}).get('result', 'unknown')}): {auth_result.get('dmarc', {}).get('detail', '')}"
        )

        decision = should_terminate(issue_count=issue_count, auth_failed=auth_failed, malicious_detected=False, reason="Auth Failure: SPF/DKIM/DMARC failed")
        attachment_hashes: list[tuple[str, str]] = []
        if decision.halt:
            termination_reason = decision.reason
            logs.append(f"[HALT] Step 2: {termination_reason}")
        else:
            # Step 3
            malicious_hash_detected = False
            for attachment in attachment_dir.iterdir():
                if not attachment.is_file():
                    continue
                attachment_hash = _hash_file(attachment)
                attachment_hashes.append((attachment_hash, str(attachment)))
                scan_result = deps.threat_scanner.scan_hash(attachment_hash)
                if scan_result.verdict == "MALICIOUS":
                    malicious_hash_detected = True
                    termination_reason = f"Malicious file hash detected: {attachment_hash}"
                    logs.append(f"[HALT] Step 3: {termination_reason}")
                    break
            if not malicious_hash_detected:
                logs.append("[INFO] Step 3: attachment hash triage - SAFE")

            decision = should_terminate(issue_count=issue_count, auth_failed=False, malicious_detected=malicious_hash_detected, reason=termination_reason)

            if not decision.halt:
                # Step 4: Email Agent
                body_text = "\n\n".join(parsed.plain_parts)
                email_payload = {
                    "email_id": parsed.subject,
                    "headers": parsed.auth_headers,
                    "body_text": body_text,
                    "timestamp": parsed.sent_at,
                }
                try:
                    email_resp = await deps.email_client.analyze(email_payload)
                    email_risk = float(email_resp.get("risk_score", 0.0))
                    if email_risk >= deps.settings.email_suspicious_threshold:
                        issue_count += 1
                        logs.append(f"[WARNING] Step 4: EmailAgent suspicious - issue_count={issue_count}")
                    else:
                        logs.append("[INFO] Step 4: EmailAgent - PASS")
                except Exception as exc:  # pragma: no cover - network failure path
                    issue_count += 1
                    logs.append(f"[WARNING] Step 4: EmailAgent unavailable ({exc}) - issue_count={issue_count}")

                decision = should_terminate(issue_count=issue_count, auth_failed=False, malicious_detected=False)
                if decision.halt:
                    termination_reason = decision.reason
                    logs.append(f"[HALT] Step 4: {termination_reason}")

            if not decision.halt:
                # Step 5: File Agent
                if attachment_hashes:
                    try:
                        for file_hash, path in attachment_hashes:
                            if hasattr(deps.file_client, "analyze_file"):
                                file_resp = await deps.file_client.analyze_file(path)
                            else:
                                # Backward-compatible path for older File Agent contracts/tests.
                                file_resp = await deps.file_client.analyze(
                                    {
                                        "email_id": parsed.subject,
                                        "attachments": [{"path": path, "sha256": file_hash}],
                                    }
                                )

                            file_label = str(file_resp.get("label", "safe")).lower()
                            file_risk_level = str(file_resp.get("risk_level", "")).lower()
                            file_risk_score = float(file_resp.get("risk_score", 0.0))

                            if file_label in {"malicious", "phishing"} or file_risk_level in {"high", "critical"} or file_risk_score >= 0.7:
                                termination_reason = f"FileAgent detected malicious attachment: {Path(path).name}"
                                logs.append(f"[HALT] Step 5: {termination_reason}")
                                decision = should_terminate(
                                    issue_count=issue_count,
                                    auth_failed=False,
                                    malicious_detected=True,
                                    reason=termination_reason,
                                )
                                break

                            if file_risk_level == "medium" or file_risk_score >= 0.4:
                                issue_count += 1
                                logs.append(
                                    f"[WARNING] Step 5: FileAgent suspicious ({Path(path).name}) - issue_count={issue_count}"
                                )
                            else:
                                logs.append(f"[INFO] Step 5: FileAgent - PASS ({Path(path).name})")
                    except Exception as exc:  # pragma: no cover
                        if deps.settings.count_file_agent_unavailable_as_issue:
                            issue_count += 1
                            logs.append(f"[WARNING] Step 5: FileAgent unavailable ({exc}) - issue_count={issue_count}")
                        else:
                            logs.append(f"[INFO] Step 5: FileAgent unavailable ({exc}) - degraded mode, no issue increment")
                else:
                    logs.append("[INFO] Step 5: FileAgent skipped - no attachments")

                if not decision.halt:
                    decision = should_terminate(issue_count=issue_count, auth_failed=False, malicious_detected=False)
                if decision.halt and termination_reason is None:
                    termination_reason = decision.reason
                    logs.append(f"[HALT] Step 5: {termination_reason}")

            if not decision.halt:
                # Step 6: Web Agent
                urls = sorted(parsed.urls)
                if urls:
                    try:
                        web_resp = await deps.web_client.analyze({"email_id": parsed.subject, "urls": urls})
                        web_label = str(web_resp.get("label", "safe")).lower()
                        web_risk = _safe_float(web_resp.get("risk_score", 0.0))
                        url_analysis = web_resp.get("checks", {}).get("url_analysis", [])
                        suspicious_urls: list[str] = []
                        if isinstance(url_analysis, list):
                            for item in url_analysis:
                                if not isinstance(item, dict):
                                    continue
                                item_label = str(item.get("label", "safe")).lower()
                                item_risk = _safe_float(item.get("risk_score", 0.0))
                                if item_label in {"malicious", "phishing"} or item_risk >= 0.5:
                                    suspicious_urls.append(str(item.get("input_url") or item.get("url") or "unknown-url"))

                        if web_label in {"malicious", "phishing"} or suspicious_urls:
                            flagged = suspicious_urls[0] if suspicious_urls else "unknown-url"
                            termination_reason = f"WebAgent detected phishing URL: {flagged}"
                            logs.append(f"[HALT] Step 6: {termination_reason}")
                            decision = should_terminate(issue_count=issue_count, auth_failed=False, malicious_detected=True, reason=termination_reason)
                        elif web_risk >= 0.5:
                            issue_count += 1
                            logs.append(f"[WARNING] Step 6: WebAgent suspicious - issue_count={issue_count}")
                        else:
                            logs.append(f"[INFO] Step 6: WebAgent - PASS (risk_score={web_risk:.4f})")
                    except Exception as exc:  # pragma: no cover
                        issue_count += 1
                        logs.append(f"[WARNING] Step 6: WebAgent unavailable ({exc}) - issue_count={issue_count}")
                else:
                    logs.append("[INFO] Step 6: WebAgent skipped - no URLs")

                if not decision.halt:
                    decision = should_terminate(issue_count=issue_count, auth_failed=False, malicious_detected=False)
                if decision.halt and termination_reason is None:
                    termination_reason = decision.reason
                    logs.append(f"[HALT] Step 6: {termination_reason}")

        final_status = "DANGER" if decision.halt else final_status_from_issue_count(issue_count)
        logs.append(f"[INFO] Step 7: Final verdict = {final_status}")

        email_row = Email(
            message_id=parsed.subject,
            sender=parsed.sender,
            receiver=parsed.receiver,
            status=EmailStatus.quarantined if final_status == "DANGER" else EmailStatus.completed,
            total_risk_score=float(issue_count),
            final_verdict=_verdict_type_from_status(final_status),
        )
        session.add(email_row)
        await session.flush()

        session.add(
            AuditLog(
                email_id=email_row.id,
                agent_name="Orchestrator",
                reasoning_trace={
                    "issue_count": issue_count,
                    "termination_reason": termination_reason,
                    "logs": logs,
                },
                cryptographic_hash=None,
            )
        )

        urls = sorted(parsed.urls)
        for url in urls:
            default_status = EntityStatus.malicious if final_status == "DANGER" and user_accepts_danger else EntityStatus.unknown
            url_hash = await _upsert_url(session, url, default_status)
            session.add(EmailUrl(email_id=email_row.id, url_hash=url_hash))

        for file_hash, file_path in attachment_hashes:
            default_status = EntityStatus.malicious if final_status == "DANGER" and user_accepts_danger else EntityStatus.unknown
            row_hash = await _upsert_file(session, file_hash, file_path, default_status)
            session.add(EmailFile(email_id=email_row.id, file_hash=row_hash))

        await session.commit()

    return ScanResponse(
        final_status=final_status,
        issue_count=issue_count,
        termination_reason=termination_reason,
        execution_logs=logs,
    )
