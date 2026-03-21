"""
Composite Risk Scorer — Tính điểm rủi ro tổng hợp.
R_total = w1*R_email + w2*R_file + w3*R_web
Verdict: PASS (issue_count=0), WARNING (issue_count=1), DANGER (issue_count>=2)
"""

import logging

from models import RiskResult, Verdict

logger = logging.getLogger(__name__)


class RiskScorer:
    """
    Bộ tính điểm rủi ro tổng hợp.

    Công thức: R_total = w1*R_email + w2*R_file + w3*R_web
    - Nếu không có tệp đính kèm → R_file = 0, trọng số phân phối lại
    - Nếu không có URL → R_web = 0, trọng số phân phối lại

    Verdict mapping (PRD Section 3):
    - issue_count == 0: PASS
    - issue_count == 1: WARNING (proceed)
    - issue_count >= 2: DANGER (halt)
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
        file_score: float | None = None,
        web_score: float | None = None,
    ) -> RiskResult:
        """
        Tính điểm rủi ro tổng hợp với xử lý điểm thiếu.

        Returns:
            RiskResult với total_score, verdict, weights_used, component_scores
        """
        # Xác định trọng số có hiệu lực
        active_weights: dict[str, float] = {}
        active_scores: dict[str, float] = {}

        # Email Agent luôn có
        active_weights["email"] = self.w_email
        active_scores["email"] = email_score

        if file_score is not None:
            active_weights["file"] = self.w_file
            active_scores["file"] = file_score

        if web_score is not None:
            active_weights["web"] = self.w_web
            active_scores["web"] = web_score

        # Phân phối lại trọng số
        weights_used = self._redistribute_weights(active_weights)

        # Tính điểm tổng hợp
        total_score = sum(weights_used[name] * active_scores[name] for name in active_scores)
        total_score = max(0.0, min(1.0, total_score))

        # Xác định verdict from score thresholds
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

    def _redistribute_weights(self, active_weights: dict[str, float]) -> dict[str, float]:
        """Phân phối lại trọng số sao cho tổng = 1.0."""
        total_weight = sum(active_weights.values())
        if total_weight == 0:
            return {name: 0.0 for name in active_weights}
        return {name: round(weight / total_weight, 4) for name, weight in active_weights.items()}

    def _determine_verdict(self, score: float) -> Verdict:
        """
        Xác định verdict dựa trên ngưỡng điểm số.
        Mapping: >= 0.7 → DANGER, >= 0.4 → WARNING, else PASS
        """
        if score >= self.malicious_threshold:
            return Verdict.DANGER
        elif score >= self.suspicious_threshold:
            return Verdict.WARNING
        else:
            return Verdict.PASS
