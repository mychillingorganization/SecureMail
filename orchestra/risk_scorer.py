"""
Composite Risk Scorer — Tính điểm rủi ro tổng hợp.
R_total = w1*R_email + w2*R_file + w3*R_web
Xử lý điểm thiếu bằng cách phân phối lại trọng số.
"""
import logging
from typing import Optional, Dict

from models import RiskResult, Verdict

logger = logging.getLogger(__name__)


class RiskScorer:
    """
    Bộ tính điểm rủi ro tổng hợp.

    Công thức: R_total = w1*R_email + w2*R_file + w3*R_web
    - Nếu không có tệp đính kèm → R_file = 0, trọng số phân phối lại
    - Nếu không có URL → R_web = 0, trọng số phân phối lại
    - Verdict: >= 0.7 → MALICIOUS, >= 0.4 → SUSPICIOUS, else SAFE
    """

    def __init__(
        self,
        w_email: float = 0.4,
        w_file: float = 0.3,
        w_web: float = 0.3,
        malicious_threshold: float = 0.7,
        suspicious_threshold: float = 0.4,
    ):
        self.w_email = w_email
        self.w_file = w_file
        self.w_web = w_web
        self.malicious_threshold = malicious_threshold
        self.suspicious_threshold = suspicious_threshold

    def compute(
        self,
        email_score: float,
        file_score: Optional[float] = None,
        web_score: Optional[float] = None,
    ) -> RiskResult:
        """
        Tính điểm rủi ro tổng hợp với xử lý điểm thiếu.

        Args:
            email_score: Điểm rủi ro từ Email Agent (luôn có)
            file_score: Điểm rủi ro từ File Agent (None nếu không có đính kèm)
            web_score: Điểm rủi ro từ Web Agent (None nếu không có URL)

        Returns:
            RiskResult với total_score, verdict, weights_used, component_scores
        """
        # Xác định trọng số có hiệu lực
        active_weights: Dict[str, float] = {}
        active_scores: Dict[str, float] = {}

        # Email Agent luôn có
        active_weights["email"] = self.w_email
        active_scores["email"] = email_score

        # File Agent
        if file_score is not None:
            active_weights["file"] = self.w_file
            active_scores["file"] = file_score

        # Web Agent
        if web_score is not None:
            active_weights["web"] = self.w_web
            active_scores["web"] = web_score

        # Phân phối lại trọng số nếu có agent bị thiếu
        weights_used = self._redistribute_weights(active_weights)

        # Tính điểm tổng hợp
        total_score = sum(
            weights_used[name] * active_scores[name]
            for name in active_scores
        )

        # Clamp về [0, 1]
        total_score = max(0.0, min(1.0, total_score))

        # Xác định verdict
        verdict = self._determine_verdict(total_score)

        logger.info(
            f"Risk score: {total_score:.4f} ({verdict.value}) | "
            f"weights={weights_used} | scores={active_scores}"
        )

        return RiskResult(
            total_score=round(total_score, 4),
            verdict=verdict,
            weights_used=weights_used,
            component_scores={
                "email": email_score,
                "file": file_score,
                "web": web_score,
            },
        )

    def _redistribute_weights(self, active_weights: Dict[str, float]) -> Dict[str, float]:
        """
        Phân phối lại trọng số sao cho tổng = 1.0.
        Ví dụ: nếu chỉ có email (0.4) → email = 1.0
        Nếu có email (0.4) + web (0.3) → email = 0.4/0.7, web = 0.3/0.7
        """
        total_weight = sum(active_weights.values())
        if total_weight == 0:
            # Edge case: không có agent nào
            return {name: 0.0 for name in active_weights}

        return {
            name: round(weight / total_weight, 4)
            for name, weight in active_weights.items()
        }

    def _determine_verdict(self, score: float) -> Verdict:
        """Xác định verdict dựa trên ngưỡng."""
        if score >= self.malicious_threshold:
            return Verdict.MALICIOUS
        elif score >= self.suspicious_threshold:
            return Verdict.SUSPICIOUS
        else:
            return Verdict.SAFE
