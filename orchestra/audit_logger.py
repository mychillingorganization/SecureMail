"""
Audit Logger — Ghi nhật ký kiểm toán bất biến cho mọi quyết định của agent.
Lưu trữ Email record + AuditLog (reasoning traces, agent scores) vào PostgreSQL
với xác minh tính toàn vẹn SHA-256.
"""

import hashlib
import json
import logging
from datetime import datetime
from typing import Any

from database import Database
from db_models import AuditLog, Email, EmailStatusEnum, VerdictTypeEnum
from models import EmailScanRequest, ScanResult
from sqlalchemy import select

logger = logging.getLogger(__name__)


def _compute_hash(data: dict) -> str:
    """Tính SHA-256 hash của payload JSONB để đảm bảo tính toàn vẹn kiểm toán."""
    serialized = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


class AuditLogger:
    """
    Ghi nhật ký kiểm toán đầy đủ cho mỗi email được phân tích.
    Mỗi bản ghi AuditLog được bảo vệ bởi SHA-256 hash để ngăn chặn giả mạo.
    """

    def __init__(self, database: Database):
        self.database = database

    async def log_scan(self, request: EmailScanRequest, result: ScanResult):
        """
        Ghi toàn bộ kết quả quét vào database.
        Tạo: 1 Email record + 1 AuditLog cho orchestrator + 1 AuditLog cho mỗi agent.
        """
        verdict_value = result.verdict.value.lower()
        status = (
            EmailStatusEnum.QUARANTINED
            if verdict_value == "malicious"
            else EmailStatusEnum.COMPLETED
        )

        async with self.database.get_session() as session:
            async with session.begin():
                # 1. Tạo Email record
                email_record = Email(
                    message_id=result.email_id,
                    sender=request.headers.get("from", ""),
                    receiver=request.headers.get("to", ""),
                    status=status,
                    total_risk_score=result.risk_score,
                    final_verdict=VerdictTypeEnum(verdict_value),
                    processed_at=datetime.utcnow(),
                )
                session.add(email_record)

                # 2. AuditLog cho orchestrator — toàn bộ reasoning trace
                orchestrator_trace = {
                    "reasoning_traces": [t.model_dump() for t in result.reasoning_traces],
                    "risk_score": result.risk_score,
                    "confidence": result.confidence,
                    "early_terminated": result.early_terminated,
                    "processing_time_ms": result.processing_time_ms,
                }
                session.add(
                    AuditLog(
                        email_id=email_record.id,
                        agent_name="orchestrator",
                        reasoning_trace=orchestrator_trace,
                        cryptographic_hash=_compute_hash(orchestrator_trace),
                    )
                )

                # 3. AuditLog riêng cho mỗi agent
                for agent_result in result.agent_results:
                    agent_trace = agent_result.model_dump()
                    session.add(
                        AuditLog(
                            email_id=email_record.id,
                            agent_name=agent_result.agent_name,
                            reasoning_trace=agent_trace,
                            cryptographic_hash=_compute_hash(agent_trace),
                        )
                    )

        logger.info(f"Audit log saved: email_id={result.email_id}, verdict={result.verdict.value}")

    async def log_clawback(
        self,
        email_id: str,
        original_verdict: str,
        new_verdict: str,
        reason: str,
        created_by: str = "system",
    ):
        """Ghi sự kiện thu hồi phán định vào audit log."""
        async with self.database.get_session() as session:
            async with session.begin():
                result = await session.execute(
                    select(Email).where(Email.message_id == email_id)
                )
                email = result.scalar_one_or_none()
                if not email:
                    logger.error(
                        f"Không thể ghi clawback: không tìm thấy email {email_id} trong database"
                    )
                    return

                clawback_data = {
                    "original_verdict": original_verdict,
                    "new_verdict": new_verdict,
                    "reason": reason,
                    "created_by": created_by,
                }
                session.add(
                    AuditLog(
                        email_id=email.id,
                        agent_name="system",
                        reasoning_trace=clawback_data,
                        cryptographic_hash=_compute_hash(clawback_data),
                    )
                )
        logger.info(f"Clawback logged: {email_id} {original_verdict} → {new_verdict}")

    async def get_full_trace(self, email_id: str) -> dict[str, Any] | None:
        """
        Truy vấn toàn bộ audit trail cho một email theo message_id.

        Returns:
            Dict chứa email info và tất cả audit logs. None nếu không tìm thấy.
        """
        async with self.database.get_session() as session:
            email_result = await session.execute(
                select(Email).where(Email.message_id == email_id)
            )
            email = email_result.scalar_one_or_none()
            if not email:
                return None

            logs_result = await session.execute(
                select(AuditLog)
                .where(AuditLog.email_id == email.id)
                .order_by(AuditLog.created_at)
            )
            logs = logs_result.scalars().all()

            return {
                "email": {
                    "message_id": email.message_id,
                    "sender": email.sender,
                    "receiver": email.receiver,
                    "status": email.status.value if email.status else None,
                    "total_risk_score": email.total_risk_score,
                    "final_verdict": email.final_verdict.value if email.final_verdict else None,
                    "processed_at": str(email.processed_at),
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


class AuditLogger:
    """
    Ghi nhật ký kiểm toán đầy đủ cho mỗi email được phân tích.
    Hỗ trợ truy vấn ngược reasoning trace từ email_id.
    """

    def __init__(self, database: Database):
        self.database = database

    async def log_scan(self, request: EmailScanRequest, result: ScanResult):
        """
        Ghi toàn bộ kết quả quét vào database.
        Bao gồm: email record, reasoning traces, agent scores.
        """
        async with self.database.get_session() as session:
            async with session.begin():
                # 1. Ghi email record
                email_record = EmailRecord(
                    email_id=result.email_id,
                    sender=request.headers.get("from", ""),
                    recipient=request.headers.get("to", ""),
                    subject=request.headers.get("subject", ""),
                    verdict=result.verdict.value,
                    risk_score=result.risk_score,
                    confidence=result.confidence,
                    early_terminated=result.early_terminated,
                    processing_time_ms=result.processing_time_ms,
                    raw_request=request.model_dump(mode="json"),
                )
                session.add(email_record)

                # 2. Ghi reasoning traces
                for trace in result.reasoning_traces:
                    trace_record = ReasoningTraceRecord(
                        email_id=result.email_id,
                        step=trace.step,
                        phase=trace.phase,
                        description=trace.description,
                        data=trace.data,
                    )
                    session.add(trace_record)

                # 3. Ghi agent scores
                for agent_result in result.agent_results:
                    score_record = AgentScoreRecord(
                        email_id=result.email_id,
                        agent_name=agent_result.agent_name,
                        risk_score=agent_result.risk_score,
                        confidence=agent_result.confidence,
                        details=agent_result.details,
                        processing_time_ms=agent_result.processing_time_ms,
                    )
                    session.add(score_record)

        logger.info(f"Audit log saved: email_id={result.email_id}, verdict={result.verdict.value}")

    async def log_clawback(
        self,
        email_id: str,
        original_verdict: str,
        new_verdict: str,
        reason: str,
        created_by: str = "system",
    ):
        """Ghi sự kiện thu hồi phán định."""
        async with self.database.get_session() as session:
            async with session.begin():
                event = ClawbackEventRecord(
                    email_id=email_id,
                    original_verdict=original_verdict,
                    new_verdict=new_verdict,
                    reason=reason,
                    created_by=created_by,
                )
                session.add(event)
        logger.info(f"Clawback logged: {email_id} {original_verdict} → {new_verdict}")

    async def get_full_trace(self, email_id: str) -> dict[str, Any] | None:
        """
        Truy vấn reasoning trace đầy đủ cho một email.

        Returns:
            Dict chứa email info, reasoning traces, agent scores, clawback events.
            None nếu không tìm thấy.
        """
        from sqlalchemy import select

        async with self.database.get_session() as session:
            # Truy vấn email
            email_result = await session.execute(select(EmailRecord).where(EmailRecord.email_id == email_id))
            email_record = email_result.scalar_one_or_none()
            if not email_record:
                return None

            # Truy vấn reasoning traces
            traces_result = await session.execute(select(ReasoningTraceRecord).where(ReasoningTraceRecord.email_id == email_id).order_by(ReasoningTraceRecord.step))
            traces = traces_result.scalars().all()

            # Truy vấn agent scores
            scores_result = await session.execute(select(AgentScoreRecord).where(AgentScoreRecord.email_id == email_id))
            scores = scores_result.scalars().all()

            # Truy vấn clawback events
            clawback_result = await session.execute(select(ClawbackEventRecord).where(ClawbackEventRecord.email_id == email_id).order_by(ClawbackEventRecord.created_at))
            clawbacks = clawback_result.scalars().all()

            return {
                "email": {
                    "email_id": email_record.email_id,
                    "sender": email_record.sender,
                    "recipient": email_record.recipient,
                    "subject": email_record.subject,
                    "verdict": email_record.verdict,
                    "risk_score": email_record.risk_score,
                    "confidence": email_record.confidence,
                    "early_terminated": email_record.early_terminated,
                    "processing_time_ms": email_record.processing_time_ms,
                    "created_at": str(email_record.created_at),
                },
                "reasoning_traces": [
                    {
                        "step": t.step,
                        "phase": t.phase,
                        "description": t.description,
                        "data": t.data,
                        "created_at": str(t.created_at),
                    }
                    for t in traces
                ],
                "agent_scores": [
                    {
                        "agent_name": s.agent_name,
                        "risk_score": s.risk_score,
                        "confidence": s.confidence,
                        "details": s.details,
                        "processing_time_ms": s.processing_time_ms,
                    }
                    for s in scores
                ],
                "clawback_events": [
                    {
                        "original_verdict": c.original_verdict,
                        "new_verdict": c.new_verdict,
                        "reason": c.reason,
                        "created_by": c.created_by,
                        "created_at": str(c.created_at),
                    }
                    for c in clawbacks
                ],
            }
