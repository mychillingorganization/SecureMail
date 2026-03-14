"""
Early Termination — Kết thúc sớm cho email giả mạo rõ ràng.
Quy tắc: SPF fail + DKIM fail + DMARC fail + confidence > 0.95 → MALICIOUS ngay lập tức.
"""
import logging
from typing import Tuple

from models import AgentResult

logger = logging.getLogger(__name__)


class EarlyTerminator:
    """
    Phát hiện email giả mạo rõ ràng và kết thúc pipeline sớm.

    Quy tắc kết thúc sớm:
    - SPF + DKIM + DMARC đều thất bại
    - Email Agent confidence > ngưỡng (mặc định 0.95)
    → Phán định MALICIOUS ngay, không gọi File/Web agent
    → Giảm thời gian xử lý 20-40% cho email giả mạo rõ ràng
    """

    def __init__(self, confidence_threshold: float = 0.95):
        self.confidence_threshold = confidence_threshold

    def should_terminate(self, email_agent_result: AgentResult) -> Tuple[bool, str]:
        """
        Kiểm tra xem có nên kết thúc sớm không.

        Args:
            email_agent_result: Kết quả từ Email Agent

        Returns:
            (should_terminate, reason) - tuple gồm boolean và lý do
        """
        details = email_agent_result.details
        checks = details.get("checks", {})

        # Kiểm tra SPF
        spf_result = checks.get("spf", {})
        spf_failed = not spf_result.get("pass", True)

        # Kiểm tra DKIM
        dkim_result = checks.get("dkim", {})
        dkim_failed = not dkim_result.get("pass", True)

        # Kiểm tra DMARC
        dmarc_result = checks.get("dmarc", {})
        dmarc_failed = not dmarc_result.get("pass", True)

        # Kiểm tra confidence
        confidence = email_agent_result.confidence
        high_confidence = confidence > self.confidence_threshold

        # Tất cả điều kiện phải thỏa mãn
        all_protocols_failed = spf_failed and dkim_failed and dmarc_failed

        if all_protocols_failed and high_confidence:
            reason = (
                f"Kết thúc sớm: SPF={spf_result.get('result', 'fail')}, "
                f"DKIM={dkim_result.get('result', 'fail')}, "
                f"DMARC={dmarc_result.get('result', 'fail')}, "
                f"confidence={confidence:.4f} > {self.confidence_threshold}"
            )
            logger.warning(f"EARLY TERMINATION: {reason}")
            return True, reason

        # Không kết thúc sớm — ghi lý do
        reasons_not_triggered = []
        if not spf_failed:
            reasons_not_triggered.append("SPF passed")
        if not dkim_failed:
            reasons_not_triggered.append("DKIM passed")
        if not dmarc_failed:
            reasons_not_triggered.append("DMARC passed")
        if not high_confidence:
            reasons_not_triggered.append(f"confidence={confidence:.4f} <= {self.confidence_threshold}")

        reason = f"Không kết thúc sớm: {', '.join(reasons_not_triggered)}"
        logger.debug(reason)
        return False, reason
