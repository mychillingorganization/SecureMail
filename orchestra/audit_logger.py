"""
Audit Logger — Ghi nhật ký kiểm toán theo PRD improve_plan.md.

Sử dụng bảng audit_logs mới với:
- agent_name: Orchestrator | Email Agent | File Agent | Web Agent
- reasoning_trace: JSONB chứa toàn bộ trace
- cryptographic_hash: hash chống giả mạo
"""

import hashlib
import json
import logging
from typing import Any

from database import Database
from db_models import AuditLogRecord, EmailRecord
from models import EmailScanRequest, ScanResult

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Ghi nhật ký kiểm toán theo PRD schema.
    Mỗi email scan tạo 1 EmailRecord + N AuditLogRecords (1 per agent).
    """

    def __init__(self, database: Database):
        self.database = database

    async def log_scan(self, request: EmailScanRequest, result: ScanResult):
        """
        Ghi toàn bộ kết quả quét vào database.
        Bao gồm: email record + audit logs per agent.
        """
        async with self.database.get_session() as session:
            async with session.begin():
                # 1. Ghi email record
                email_record = EmailRecord(
                    message_id=request.message_id or request.headers.get("message-id"),
                    sender=request.headers.get("from", ""),
                    receiver=request.headers.get("to", ""),
                    status="quarantined" if result.final_status.value == "DANGER" else "completed",
                    total_risk_score=result.risk_score,
                    final_verdict=self._map_verdict_to_db(result.final_status.value),
                )
                session.add(email_record)
                await session.flush()  # Get the generated ID

                # 2. Ghi orchestrator audit log (full pipeline trace)
                orchestrator_trace = {
                    "final_status": result.final_status.value,
                    "issue_count": result.issue_count,
                    "termination_reason": result.termination_reason,
                    "execution_logs": result.execution_logs,
                    "reasoning_traces": [t.model_dump(mode="json") for t in result.reasoning_traces],
                    "processing_time_ms": result.processing_time_ms,
                    "early_terminated": result.early_terminated,
                }
                orchestrator_hash = self._compute_hash(orchestrator_trace)
                orchestrator_log = AuditLogRecord(
                    email_id=email_record.id,
                    agent_name="Orchestrator",
                    reasoning_trace=orchestrator_trace,
                    cryptographic_hash=orchestrator_hash,
                )
                session.add(orchestrator_log)

                # 3. Ghi per-agent audit logs
                for agent_result in result.agent_results:
                    agent_trace = agent_result.model_dump(mode="json")
                    agent_hash = self._compute_hash(agent_trace)
                    agent_log = AuditLogRecord(
                        email_id=email_record.id,
                        agent_name=self._format_agent_name(agent_result.agent_name),
                        reasoning_trace=agent_trace,
                        cryptographic_hash=agent_hash,
                    )
                    session.add(agent_log)

        logger.info(
            f"Audit log saved: email_id={result.email_id}, "
            f"verdict={result.final_status.value}, "
            f"agents={len(result.agent_results)}"
        )

    async def get_full_trace(self, email_id: str) -> dict[str, Any] | None:
        """
        Truy vấn audit trail đầy đủ cho một email.
        Returns dict chứa email info + all audit logs, hoặc None.
        """
        from sqlalchemy import select

        async with self.database.get_session() as session:
            # Query email record
            email_result = await session.execute(
                select(EmailRecord).where(EmailRecord.id == email_id)
            )
            email_record = email_result.scalar_one_or_none()
            if not email_record:
                return None

            # Query audit logs
            logs_result = await session.execute(
                select(AuditLogRecord)
                .where(AuditLogRecord.email_id == email_id)
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

    # ===== HELPERS =====

    def _compute_hash(self, data: dict) -> str:
        """Compute SHA-256 hash of trace data for tamper-proof audit."""
        serialized = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()

    def _format_agent_name(self, name: str) -> str:
        """Format agent name to match PRD spec."""
        mapping = {
            "email": "Email Agent",
            "file": "File Agent",
            "web": "Web Agent",
        }
        return mapping.get(name, name)

    def _map_verdict_to_db(self, verdict: str) -> str:
        """Map PRD verdict (PASS/WARNING/DANGER) to DB enum (safe/suspicious/malicious)."""
        mapping = {
            "PASS": "safe",
            "WARNING": "suspicious",
            "DANGER": "malicious",
        }
        return mapping.get(verdict, "safe")
