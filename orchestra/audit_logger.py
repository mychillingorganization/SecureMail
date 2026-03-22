"""
Audit Logger — Ghi nhật ký kiểm toán bất biến cho pipeline.
Lưu trữ Email record + per-agent AuditLog vào PostgreSQL
với xác minh toàn vẹn SHA-256.
"""

import hashlib
import json
import logging
from typing import Any

from sqlalchemy import or_, select

from database import Database
from db_models import AuditLogRecord, EmailRecord
from models import EmailScanRequest, ScanResult

logger = logging.getLogger(__name__)


def _compute_hash(data: dict[str, Any]) -> str:
    """Tính SHA-256 hash của payload JSON để chống chỉnh sửa audit log."""
    serialized = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class AuditLogger:
    """Ghi và truy vấn audit trail cho mỗi email scan."""

    def __init__(self, database: Database):
        self.database = database

    async def log_scan(self, request: EmailScanRequest, result: ScanResult) -> None:
        """
        Ghi toàn bộ kết quả quét vào database.
        Bao gồm: 1 email record + 1 orchestrator log + N per-agent logs.
        """
        async with self.database.get_session() as session:
            async with session.begin():
                email_record = EmailRecord(
                    # Luôn lưu pipeline email_id để endpoint /trace/{email_id} truy vấn được.
                    message_id=request.message_id or request.email_id or request.headers.get("message-id"),
                    sender=request.headers.get("from", ""),
                    receiver=request.headers.get("to", ""),
                    status="quarantined" if result.final_status.value == "DANGER" else "completed",
                    total_risk_score=result.risk_score,
                    final_verdict=self._map_verdict_to_db(result.final_status.value),
                )
                session.add(email_record)
                await session.flush()

                orchestrator_trace = {
                    "final_status": result.final_status.value,
                    "issue_count": result.issue_count,
                    "termination_reason": result.termination_reason,
                    "execution_logs": result.execution_logs,
                    "reasoning_traces": [t.model_dump(mode="json") for t in result.reasoning_traces],
                    "processing_time_ms": result.processing_time_ms,
                    "early_terminated": result.early_terminated,
                }
                session.add(
                    AuditLogRecord(
                        email_id=email_record.id,
                        agent_name="Orchestrator",
                        reasoning_trace=orchestrator_trace,
                        cryptographic_hash=_compute_hash(orchestrator_trace),
                    )
                )

                for agent_result in result.agent_results:
                    agent_trace = agent_result.model_dump(mode="json")
                    session.add(
                        AuditLogRecord(
                            email_id=email_record.id,
                            agent_name=self._format_agent_name(agent_result.agent_name),
                            reasoning_trace=agent_trace,
                            cryptographic_hash=_compute_hash(agent_trace),
                        )
                    )

        logger.info(
            "Audit log saved: email_id=%s verdict=%s agents=%d",
            result.email_id,
            result.final_status.value,
            len(result.agent_results),
        )

    async def get_full_trace(self, email_id: str) -> dict[str, Any] | None:
        """
        Truy vấn audit trail theo email id.
        Hỗ trợ cả EmailRecord.id lẫn EmailRecord.message_id.
        """
        async with self.database.get_session() as session:
            email_result = await session.execute(
                select(EmailRecord).where(
                    or_(EmailRecord.id == email_id, EmailRecord.message_id == email_id)
                )
            )
            email_record = email_result.scalar_one_or_none()
            if not email_record:
                return None

            logs_result = await session.execute(
                select(AuditLogRecord)
                .where(AuditLogRecord.email_id == email_record.id)
                .order_by(AuditLogRecord.created_at)
            )
            logs = logs_result.scalars().all()

            return {
                "email": {
                    "id": email_record.id,
                    "message_id": email_record.message_id,
                    "sender": email_record.sender,
                    "receiver": email_record.receiver,
                    "status": email_record.status,
                    "total_risk_score": email_record.total_risk_score,
                    "final_verdict": email_record.final_verdict,
                    "processed_at": str(email_record.processed_at),
                },
                "audit_logs": [
                    {
                        "agent_name": log.agent_name,
                        "reasoning_trace": log.reasoning_trace,
                        "cryptographic_hash": log.cryptographic_hash,
                        "created_at": str(log.created_at),
                    }
                    for log in logs
                ],
            }

    def _format_agent_name(self, name: str) -> str:
        mapping = {
            "email": "Email Agent",
            "file": "File Agent",
            "web": "Web Agent",
        }
        return mapping.get(name, name)

    def _map_verdict_to_db(self, verdict: str) -> str:
        mapping = {
            "PASS": "safe",
            "WARNING": "suspicious",
            "DANGER": "malicious",
        }
        return mapping.get(verdict, "safe")
