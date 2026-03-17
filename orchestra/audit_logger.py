"""
Audit Logger — Ghi nhật ký kiểm toán cho mọi quyết định.
Lưu trữ reasoning traces, agent scores, và scan results vào PostgreSQL.
"""

import logging
from typing import Any

from database import Database
from db_models import (
    AgentScoreRecord,
    ClawbackEventRecord,
    EmailRecord,
    ReasoningTraceRecord,
)
from models import EmailScanRequest, ScanResult

logger = logging.getLogger(__name__)


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
