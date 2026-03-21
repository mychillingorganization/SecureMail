"""
ReAct Pipeline — 8-step execution pipeline theo PRD improve_plan.md.

Step 1: Data Ingestion & Parsing        → utils.parse_eml()
Step 2: Sender Authentication           → protocol_verifier.check_auth()
Step 3: Initial Triage (Hash Scans)     → threat_intel.scan_hash()
Step 4: Deep Content & Context Analysis → MailAgent
Step 5: File & Attachment Analysis      → FileAgent
Step 6: Web & Link Analysis             → WebAgent
Step 7: Final Verdict Calculation       → issue_count evaluation
Step 8: Persistence                     → save to DB + blacklist
"""

import asyncio
import logging
import time

import httpx
from config import Settings
from early_termination import EarlyTerminator
from models import (
    AgentResult,
    EmailScanRequest,
    ReasoningTrace,
    ScanResult,
    Verdict,
)
from redis_bus import RedisBus
from risk_scorer import RiskScorer
from tool_stubs import check_auth, parse_eml, scan_hash

logger = logging.getLogger(__name__)


class ReActPipeline:
    """
    Pipeline ReAct 8 bước theo PRD improve_plan.md.

    State Management (PRD Section 3):
    - issue_count = 0 → PASS
    - issue_count == 1 → WARNING (flag, proceed)
    - issue_count >= 2 → DANGER (immediate halt)

    Kill Switches (PRD Section 4):
    - Auth Failure → DANGER
    - Known Threat (malware/phishing/blacklist) → DANGER
    - issue_count >= 2 → DANGER
    """

    def __init__(
        self,
        settings: Settings,
        redis_bus: RedisBus | None = None,
        audit_logger=None,
        blacklist_service=None,
    ):
        self.settings = settings
        self.redis_bus = redis_bus
        self.audit_logger = audit_logger
        self.blacklist_service = blacklist_service

        self.risk_scorer = RiskScorer(
            w_email=settings.RISK_WEIGHT_EMAIL,
            w_file=settings.RISK_WEIGHT_FILE,
            w_web=settings.RISK_WEIGHT_WEB,
            malicious_threshold=settings.MALICIOUS_THRESHOLD,
            suspicious_threshold=settings.SUSPICIOUS_THRESHOLD,
        )
        self.early_terminator = EarlyTerminator()
        self._http_client: httpx.AsyncClient | None = None

    async def _get_http_client(self) -> httpx.AsyncClient:
        """Lazy init HTTP client."""
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(timeout=self.settings.AGENT_TIMEOUT)
        return self._http_client

    async def run(self, request: EmailScanRequest) -> ScanResult:
        """
        Chạy pipeline 8 bước đầy đủ cho một email.

        Returns:
            ScanResult với final_status, issue_count, termination_reason, execution_logs
        """
        start_time = time.time()
        traces: list[ReasoningTrace] = []
        agent_results: list[AgentResult] = []
        execution_logs: list[str] = []
        issue_count = 0
        step = 0

        # ===== STEP 1: DATA INGESTION & PARSING =====
        step += 1
        try:
            parsed = parse_eml(request.email_id)  # Stub call
            # Merge parsed data with request (in real impl, parsed would be the source)
            perception = {
                "email_id": request.email_id,
                "has_attachments": len(request.attachments) > 0,
                "attachment_count": len(request.attachments),
                "has_urls": len(request.urls) > 0,
                "url_count": len(request.urls),
                "body_length": len(request.body_text),
            }
            traces.append(
                ReasoningTrace(
                    step=step,
                    phase="PERCEIVE",
                    description=f"Parsed email {request.email_id}: "
                    f"{len(request.attachments)} attachments, "
                    f"{len(request.urls)} URLs",
                    data=perception,
                )
            )
            execution_logs.append(f"[INFO] Step 1: utils.parse_eml() - SUCCESS")
            logger.info(f"[Step {step}] PERCEIVE: {perception}")
        except Exception as e:
            execution_logs.append(f"[ERROR] Step 1: utils.parse_eml() - FAILED: {e}")
            logger.error(f"[Step {step}] parse_eml failed: {e}")

        # ===== STEP 2: SENDER AUTHENTICATION =====
        step += 1
        auth_results = check_auth(request.headers)  # Stub call
        traces.append(
            ReasoningTrace(
                step=step,
                phase="ACT",
                description=f"Authentication: SPF={auth_results['spf']}, "
                f"DKIM={auth_results['dkim']}, DMARC={auth_results['dmarc']}",
                data=auth_results,
            )
        )
        execution_logs.append(
            f"[INFO] Step 2: protocol_verifier.check_auth() - "
            f"SPF={auth_results['spf']}, DKIM={auth_results['dkim']}, DMARC={auth_results['dmarc']}"
        )

        # Kill Switch #1: Auth Failure
        should_halt, halt_reason = self.early_terminator.check_auth_failure(auth_results)
        if should_halt:
            execution_logs.append(f"[HALT] Step 2: {halt_reason}")
            return self._build_danger_result(
                request, issue_count, halt_reason, traces, agent_results,
                execution_logs, start_time,
            )

        # ===== STEP 3: INITIAL TRIAGE (HASH SCANS) =====
        step += 1
        hash_scan_results = []
        for attachment in request.attachments:
            file_hash = attachment.get("hash", attachment.get("filename", "unknown"))
            scan_result = scan_hash(file_hash)  # Stub call
            hash_scan_results.append({"hash": file_hash, "status": scan_result})

        traces.append(
            ReasoningTrace(
                step=step,
                phase="ACT",
                description=f"Hash triage: {len(request.attachments)} attachments scanned",
                data={"results": hash_scan_results},
            )
        )

        if hash_scan_results:
            execution_logs.append(
                f"[INFO] Step 3: threat_intel.scan_hash() - "
                f"Scanned {len(hash_scan_results)} hashes"
            )
        else:
            execution_logs.append("[INFO] Step 3: threat_intel.scan_hash() - No attachments to scan")

        # Kill Switch #2: Known Threat (hash scan)
        should_halt, halt_reason = self.early_terminator.check_known_threat(
            hash_results=hash_scan_results
        )
        if should_halt:
            execution_logs.append(f"[HALT] Step 3: {halt_reason}")
            return self._build_danger_result(
                request, issue_count, halt_reason, traces, agent_results,
                execution_logs, start_time,
            )

        # ===== STEP 4: DEEP CONTENT & CONTEXT ANALYSIS (MailAgent) =====
        step += 1
        email_result = await self._call_agent(
            agent_name="email",
            url=f"{self.settings.EMAIL_AGENT_URL}/api/v1/analyze",
            payload=self._build_email_payload(request),
        )
        agent_results.append(email_result)

        # Check if Email Agent flagged suspicious content
        if email_result.details.get("suspicious", False) or email_result.risk_score >= self.settings.SUSPICIOUS_THRESHOLD:
            issue_count += 1
            execution_logs.append(
                f"[WARNING] Step 4: MailAgent reported suspicious content - "
                f"issue_count incremented to {issue_count}"
            )
        else:
            execution_logs.append(
                f"[INFO] Step 4: MailAgent analysis complete - "
                f"risk={email_result.risk_score:.4f}"
            )

        traces.append(
            ReasoningTrace(
                step=step,
                phase="ACT",
                description=f"MailAgent → risk={email_result.risk_score:.4f}, "
                f"confidence={email_result.confidence:.4f}",
                data={"agent": "email", "result": email_result.model_dump()},
            )
        )

        # Check issue threshold after Step 4
        should_halt, halt_reason = self.early_terminator.check_issue_threshold(issue_count)
        if should_halt:
            execution_logs.append(f"[HALT] Step 4: {halt_reason}")
            return self._build_danger_result(
                request, issue_count, halt_reason, traces, agent_results,
                execution_logs, start_time,
            )

        # ===== STEP 5: FILE & ATTACHMENT ANALYSIS (FileAgent) =====
        step += 1
        file_result: AgentResult | None = None
        if request.attachments:
            file_result = await self._call_agent(
                agent_name="file",
                url=f"{self.settings.FILE_AGENT_URL}/api/v1/analyze",
                payload=self._build_file_payload(request),
            )
            agent_results.append(file_result)

            # Kill Switch #2: Definitive malware from FileAgent
            should_halt, halt_reason = self.early_terminator.check_known_threat(
                agent_result=file_result
            )
            if should_halt:
                execution_logs.append(f"[HALT] Step 5: {halt_reason}")
                return self._build_danger_result(
                    request, issue_count, halt_reason, traces, agent_results,
                    execution_logs, start_time,
                )

            # Increment issue_count if suspicious
            if file_result.details.get("suspicious", False) or file_result.risk_score >= self.settings.SUSPICIOUS_THRESHOLD:
                issue_count += 1
                execution_logs.append(
                    f"[WARNING] Step 5: FileAgent reported suspicious - "
                    f"issue_count incremented to {issue_count}"
                )
            else:
                execution_logs.append(
                    f"[INFO] Step 5: FileAgent analysis complete - "
                    f"risk={file_result.risk_score:.4f}"
                )

            traces.append(
                ReasoningTrace(
                    step=step,
                    phase="ACT",
                    description=f"FileAgent → risk={file_result.risk_score:.4f}",
                    data={"agent": "file", "result": file_result.model_dump()},
                )
            )
        else:
            execution_logs.append("[INFO] Step 5: No attachments - FileAgent skipped")
            traces.append(
                ReasoningTrace(
                    step=step,
                    phase="OBSERVE",
                    description="No attachments — FileAgent skipped",
                    data={},
                )
            )

        # Check issue threshold after Step 5
        should_halt, halt_reason = self.early_terminator.check_issue_threshold(issue_count)
        if should_halt:
            execution_logs.append(f"[HALT] Step 5: {halt_reason}")
            return self._build_danger_result(
                request, issue_count, halt_reason, traces, agent_results,
                execution_logs, start_time,
            )

        # ===== STEP 6: WEB & LINK ANALYSIS (WebAgent) =====
        step += 1
        web_result: AgentResult | None = None
        if request.urls:
            web_result = await self._call_agent(
                agent_name="web",
                url=f"{self.settings.WEB_AGENT_URL}/api/v1/analyze",
                payload=self._build_web_payload(request),
            )
            agent_results.append(web_result)

            # Kill Switch #2: Blacklisted/phishing from WebAgent
            should_halt, halt_reason = self.early_terminator.check_known_threat(
                agent_result=web_result
            )
            if should_halt:
                execution_logs.append(f"[HALT] Step 6: {halt_reason}")
                return self._build_danger_result(
                    request, issue_count, halt_reason, traces, agent_results,
                    execution_logs, start_time,
                )

            # Increment issue_count if suspicious
            if web_result.details.get("suspicious", False) or web_result.risk_score >= self.settings.SUSPICIOUS_THRESHOLD:
                issue_count += 1
                execution_logs.append(
                    f"[WARNING] Step 6: WebAgent reported suspicious - "
                    f"issue_count incremented to {issue_count}"
                )
            else:
                execution_logs.append(
                    f"[INFO] Step 6: WebAgent analysis complete - "
                    f"risk={web_result.risk_score:.4f}"
                )

            traces.append(
                ReasoningTrace(
                    step=step,
                    phase="ACT",
                    description=f"WebAgent → risk={web_result.risk_score:.4f}",
                    data={"agent": "web", "result": web_result.model_dump()},
                )
            )
        else:
            execution_logs.append("[INFO] Step 6: No URLs - WebAgent skipped")
            traces.append(
                ReasoningTrace(
                    step=step,
                    phase="OBSERVE",
                    description="No URLs — WebAgent skipped",
                    data={},
                )
            )

        # Check issue threshold after Step 6
        should_halt, halt_reason = self.early_terminator.check_issue_threshold(issue_count)
        if should_halt:
            execution_logs.append(f"[HALT] Step 6: {halt_reason}")
            return self._build_danger_result(
                request, issue_count, halt_reason, traces, agent_results,
                execution_logs, start_time,
            )

        # ===== STEP 7: FINAL VERDICT CALCULATION =====
        step += 1
        risk_result = self.risk_scorer.compute(
            email_score=email_result.risk_score,
            file_score=file_result.risk_score if file_result else None,
            web_score=web_result.risk_score if web_result else None,
        )

        # Determine verdict from issue_count (PRD Section 3)
        if issue_count == 0:
            final_verdict = Verdict.PASS
        elif issue_count == 1:
            final_verdict = Verdict.WARNING
        else:
            final_verdict = Verdict.DANGER  # Should have been caught by kill switch

        traces.append(
            ReasoningTrace(
                step=step,
                phase="REASON",
                description=f"Final verdict: {final_verdict.value} "
                f"(issue_count={issue_count}, risk_score={risk_result.total_score:.4f})",
                data={
                    "issue_count": issue_count,
                    "risk_result": risk_result.model_dump(),
                    "final_verdict": final_verdict.value,
                },
            )
        )
        execution_logs.append(
            f"[INFO] Step 7: Final Verdict = {final_verdict.value} "
            f"(issue_count={issue_count}, R_total={risk_result.total_score:.4f})"
        )

        # ===== STEP 8: PERSISTENCE =====
        step += 1
        result = ScanResult(
            email_id=request.email_id,
            final_status=final_verdict,
            issue_count=issue_count,
            termination_reason=None,
            risk_score=risk_result.total_score,
            confidence=self._compute_aggregate_confidence(agent_results),
            agent_results=agent_results,
            reasoning_traces=traces,
            execution_logs=execution_logs,
            early_terminated=False,
            processing_time_ms=(time.time() - start_time) * 1000,
        )

        # Save to DB
        if self.audit_logger:
            await self._safe_audit_log(request, result)
            execution_logs.append("[INFO] Step 8: Results saved to database")
        else:
            execution_logs.append("[INFO] Step 8: Database not available - results not persisted")

        traces.append(
            ReasoningTrace(
                step=step,
                phase="ACT",
                description="Results persisted to database",
                data={"saved": self.audit_logger is not None},
            )
        )

        logger.info(
            f"Pipeline complete: email_id={request.email_id}, "
            f"verdict={final_verdict.value}, issue_count={issue_count}"
        )
        return result

    # ===== HELPER METHODS =====

    def _build_danger_result(
        self,
        request: EmailScanRequest,
        issue_count: int,
        termination_reason: str,
        traces: list[ReasoningTrace],
        agent_results: list[AgentResult],
        execution_logs: list[str],
        start_time: float,
    ) -> ScanResult:
        """Build a DANGER ScanResult for kill switch termination."""
        logger.warning(
            f"DANGER: email_id={request.email_id}, reason={termination_reason}"
        )
        return ScanResult(
            email_id=request.email_id,
            final_status=Verdict.DANGER,
            issue_count=issue_count,
            termination_reason=termination_reason,
            risk_score=1.0,  # Max risk for kill switch
            confidence=1.0,
            agent_results=agent_results,
            reasoning_traces=traces,
            execution_logs=execution_logs,
            early_terminated=True,
            processing_time_ms=(time.time() - start_time) * 1000,
        )

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
            logger.error(f"Agent {agent_name} at {url} failed: {e}")
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

    def _compute_aggregate_confidence(self, results: list[AgentResult]) -> float:
        """Tính confidence trung bình từ tất cả agents."""
        if not results:
            return 0.0
        return round(sum(r.confidence for r in results) / len(results), 4)

    async def _safe_audit_log(self, request: EmailScanRequest, result: ScanResult):
        """Ghi audit log, bắt lỗi nếu DB không khả dụng."""
        try:
            await self.audit_logger.log_scan(request, result)
        except Exception as e:
            logger.error(f"Audit log failed: {e}")
