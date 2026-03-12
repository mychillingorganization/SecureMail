"""
ReAct Pipeline — Pipeline suy luận 5 bước cho phân tích bảo mật email.
Bước 1: Perceive (nhận dữ liệu)
Bước 2: Reason (quyết định agent)
Bước 3: Act (gửi tới agents)
Bước 4: Observe (thu thập kết quả)
Bước 5: Reason (kết thúc sớm hoặc tính điểm)
"""
import time
import asyncio
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

import httpx

from config import Settings
from models import (
    EmailScanRequest,
    ScanResult,
    AgentResult,
    ReasoningTrace,
    Verdict,
)
from risk_scorer import RiskScorer
from early_termination import EarlyTerminator
from redis_bus import RedisBus

logger = logging.getLogger(__name__)


class ReActPipeline:
    """
    Pipeline ReAct 5 bước cho phân tích bảo mật email.
    Mỗi bước được ghi lại dưới dạng dấu vết suy luận (reasoning trace).
    """

    def __init__(
        self,
        settings: Settings,
        redis_bus: Optional[RedisBus] = None,
        audit_logger=None,
    ):
        self.settings = settings
        self.redis_bus = redis_bus
        self.audit_logger = audit_logger

        self.risk_scorer = RiskScorer(
            w_email=settings.RISK_WEIGHT_EMAIL,
            w_file=settings.RISK_WEIGHT_FILE,
            w_web=settings.RISK_WEIGHT_WEB,
            malicious_threshold=settings.MALICIOUS_THRESHOLD,
            suspicious_threshold=settings.SUSPICIOUS_THRESHOLD,
        )
        self.early_terminator = EarlyTerminator(
            confidence_threshold=settings.EARLY_TERM_CONFIDENCE_THRESHOLD,
        )

        self._http_client: Optional[httpx.AsyncClient] = None

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Lazy init HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=self.settings.AGENT_TIMEOUT)
        return self._http_client

    async def run(self, request: EmailScanRequest) -> ScanResult:
        """
        Chạy pipeline ReAct đầy đủ cho một email.

        Args:
            request: EmailScanRequest chứa thông tin email

        Returns:
            ScanResult với verdict, risk_score, reasoning_traces
        """
        start_time = time.time()
        traces: List[ReasoningTrace] = []
        agent_results: List[AgentResult] = []
        step = 0

        # ===== BƯỚC 1: PERCEIVE — Phân tích dữ liệu đầu vào =====
        step += 1
        has_attachments = len(request.attachments) > 0
        has_urls = len(request.urls) > 0
        perception = {
            "email_id": request.email_id,
            "has_attachments": has_attachments,
            "attachment_count": len(request.attachments),
            "has_urls": has_urls,
            "url_count": len(request.urls),
            "headers_present": list(request.headers.keys()),
            "body_length": len(request.body_text),
        }
        traces.append(ReasoningTrace(
            step=step,
            phase="PERCEIVE",
            description=f"Nhận email {request.email_id}: "
                        f"{len(request.attachments)} tệp đính kèm, "
                        f"{len(request.urls)} URL, "
                        f"body {len(request.body_text)} ký tự",
            data=perception,
        ))
        logger.info(f"[Step {step}] PERCEIVE: {perception}")

        # ===== BƯỚC 2: REASON — Quyết định gọi agent nào =====
        step += 1
        agents_to_call = ["email"]  # Email Agent luôn được gọi
        if has_attachments:
            agents_to_call.append("file")
        if has_urls:
            agents_to_call.append("web")

        reasoning_data = {
            "agents_selected": agents_to_call,
            "reason_file": "Có tệp đính kèm" if has_attachments else "Không có tệp đính kèm",
            "reason_web": "Có URL" if has_urls else "Không có URL",
        }
        traces.append(ReasoningTrace(
            step=step,
            phase="REASON",
            description=f"Quyết định gọi agents: {', '.join(agents_to_call)}",
            data=reasoning_data,
        ))
        logger.info(f"[Step {step}] REASON: agents={agents_to_call}")

        # ===== BƯỚC 3: ACT — Gửi yêu cầu tới Email Agent (luôn luôn) =====
        step += 1
        email_result = await self._call_agent(
            agent_name="email",
            url=f"{self.settings.EMAIL_AGENT_URL}/api/v1/analyze",
            payload=self._build_email_payload(request),
        )
        agent_results.append(email_result)
        traces.append(ReasoningTrace(
            step=step,
            phase="ACT",
            description=f"Gửi tới Email Agent → risk={email_result.risk_score:.4f}, "
                        f"confidence={email_result.confidence:.4f}",
            data={"agent": "email", "result_summary": email_result.model_dump()},
        ))
        logger.info(f"[Step {step}] ACT: Email Agent → risk={email_result.risk_score}")

        # ===== BƯỚC 4 (phần 1): Kiểm tra kết thúc sớm SAU khi có kết quả Email Agent =====
        step += 1
        should_terminate, term_reason = self.early_terminator.should_terminate(email_result)
        traces.append(ReasoningTrace(
            step=step,
            phase="REASON",
            description=f"Kiểm tra kết thúc sớm: {'CÓ' if should_terminate else 'KHÔNG'} — {term_reason}",
            data={"early_termination": should_terminate, "reason": term_reason},
        ))

        if should_terminate:
            logger.warning(f"[Step {step}] EARLY TERMINATION: {term_reason}")
            result = ScanResult(
                email_id=request.email_id,
                verdict=Verdict.MALICIOUS,
                risk_score=email_result.risk_score,
                confidence=email_result.confidence,
                agent_results=agent_results,
                reasoning_traces=traces,
                early_terminated=True,
                processing_time_ms=(time.time() - start_time) * 1000,
            )
            # Ghi audit log nếu có
            if self.audit_logger:
                await self._safe_audit_log(request, result)
            return result

        # ===== BƯỚC 4 (phần 2): ACT — Gọi File/Web agents song song =====
        step += 1
        file_result: Optional[AgentResult] = None
        web_result: Optional[AgentResult] = None

        parallel_tasks = []
        if "file" in agents_to_call:
            parallel_tasks.append(
                self._call_agent(
                    agent_name="file",
                    url=f"{self.settings.FILE_AGENT_URL}/api/v1/analyze",
                    payload=self._build_file_payload(request),
                )
            )
        if "web" in agents_to_call:
            parallel_tasks.append(
                self._call_agent(
                    agent_name="web",
                    url=f"{self.settings.WEB_AGENT_URL}/api/v1/analyze",
                    payload=self._build_web_payload(request),
                )
            )

        if parallel_tasks:
            results = await asyncio.gather(*parallel_tasks, return_exceptions=True)
            idx = 0
            if "file" in agents_to_call:
                if isinstance(results[idx], AgentResult):
                    file_result = results[idx]
                    agent_results.append(file_result)
                else:
                    logger.error(f"File Agent lỗi: {results[idx]}")
                idx += 1
            if "web" in agents_to_call:
                if isinstance(results[idx], AgentResult):
                    web_result = results[idx]
                    agent_results.append(web_result)
                else:
                    logger.error(f"Web Agent lỗi: {results[idx]}")

        act_desc_parts = []
        if file_result:
            act_desc_parts.append(f"File Agent → risk={file_result.risk_score:.4f}")
        if web_result:
            act_desc_parts.append(f"Web Agent → risk={web_result.risk_score:.4f}")
        if not act_desc_parts:
            act_desc_parts.append("Không có agent phụ nào được gọi")

        traces.append(ReasoningTrace(
            step=step,
            phase="OBSERVE",
            description=f"Thu thập kết quả: {'; '.join(act_desc_parts)}",
            data={
                "file_result": file_result.model_dump() if file_result else None,
                "web_result": web_result.model_dump() if web_result else None,
            },
        ))
        logger.info(f"[Step {step}] OBSERVE: {act_desc_parts}")

        # ===== BƯỚC 5: REASON — Tính điểm tổng hợp =====
        step += 1
        risk_result = self.risk_scorer.compute(
            email_score=email_result.risk_score,
            file_score=file_result.risk_score if file_result else None,
            web_score=web_result.risk_score if web_result else None,
        )

        traces.append(ReasoningTrace(
            step=step,
            phase="REASON",
            description=f"Điểm rủi ro tổng hợp: {risk_result.total_score:.4f} → {risk_result.verdict.value}",
            data=risk_result.model_dump(),
        ))
        logger.info(f"[Step {step}] REASON: total={risk_result.total_score} verdict={risk_result.verdict}")

        # ===== KẾT QUẢ =====
        result = ScanResult(
            email_id=request.email_id,
            verdict=risk_result.verdict,
            risk_score=risk_result.total_score,
            confidence=self._compute_aggregate_confidence(agent_results),
            agent_results=agent_results,
            reasoning_traces=traces,
            early_terminated=False,
            processing_time_ms=(time.time() - start_time) * 1000,
        )

        # Ghi audit log nếu có
        if self.audit_logger:
            await self._safe_audit_log(request, result)

        return result

    # ===== HELPER METHODS =====

    async def _call_agent(self, agent_name: str, url: str, payload: dict) -> AgentResult:
        """Gọi một agent qua HTTP và trả về AgentResult."""
        start = time.time()
        try:
            client = await self._get_http_client()
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            return AgentResult(
                agent_name=agent_name,
                risk_score=data.get("risk_score", 0.0),
                confidence=data.get("confidence", 0.0),
                details=data,
                processing_time_ms=(time.time() - start) * 1000,
            )
        except Exception as e:
            logger.error(f"Agent {agent_name} tại {url} lỗi: {e}")
            return AgentResult(
                agent_name=agent_name,
                risk_score=0.0,
                confidence=0.0,
                details={"error": str(e)},
                processing_time_ms=(time.time() - start) * 1000,
            )

    def _build_email_payload(self, request: EmailScanRequest) -> dict:
        """Xây dựng payload cho Email Agent."""
        return {
            "email_id": request.email_id,
            "headers": request.headers,
            "body_text": request.body_text,
            "body_html": request.body_html,
            "timestamp": request.timestamp.isoformat(),
        }

    def _build_file_payload(self, request: EmailScanRequest) -> dict:
        """Xây dựng payload cho File Agent."""
        return {
            "email_id": request.email_id,
            "attachments": request.attachments,
        }

    def _build_web_payload(self, request: EmailScanRequest) -> dict:
        """Xây dựng payload cho Web Agent."""
        return {
            "email_id": request.email_id,
            "urls": request.urls,
        }

    def _compute_aggregate_confidence(self, results: List[AgentResult]) -> float:
        """Tính confidence trung bình từ tất cả agents."""
        if not results:
            return 0.0
        return round(sum(r.confidence for r in results) / len(results), 4)

    async def _safe_audit_log(self, request: EmailScanRequest, result: ScanResult):
        """Ghi audit log, bắt lỗi nếu DB không khả dụng."""
        try:
            await self.audit_logger.log_scan(request, result)
        except Exception as e:
            logger.error(f"Audit log lỗi: {e}")
