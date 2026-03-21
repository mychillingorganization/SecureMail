"""
Tests cho RiskScorer — PASS/WARNING/DANGER verdicts.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest

from models import Verdict
from risk_scorer import RiskScorer


class TestRiskScorer(unittest.TestCase):
    def setUp(self):
        self.scorer = RiskScorer(w_email=0.4, w_file=0.3, w_web=0.3)

    # Kịch bản 1: Tất cả 3 agent đều có điểm → DANGER (>=0.7)
    def test_all_three_scores_high_danger(self):
        result = self.scorer.compute(email_score=0.8, file_score=0.6, web_score=0.7)
        # R = 0.4*0.8 + 0.3*0.6 + 0.3*0.7 = 0.32 + 0.18 + 0.21 = 0.71
        self.assertAlmostEqual(result.total_score, 0.71, places=2)
        self.assertEqual(result.verdict, Verdict.DANGER)

    # Kịch bản 2: Thiếu file_score → WARNING (0.4-0.7)
    def test_missing_file_score_redistribution(self):
        result = self.scorer.compute(email_score=0.8, file_score=None, web_score=0.5)
        # email=0.5714, web=0.4286 → R=0.6714
        self.assertAlmostEqual(result.total_score, 0.6714, places=2)
        self.assertEqual(result.verdict, Verdict.WARNING)

    # Kịch bản 3: Thiếu web_score → DANGER
    def test_missing_web_score_danger(self):
        result = self.scorer.compute(email_score=0.9, file_score=0.8, web_score=None)
        self.assertAlmostEqual(result.total_score, 0.8571, places=2)
        self.assertEqual(result.verdict, Verdict.DANGER)

    # Kịch bản 4: Chỉ có email → WARNING
    def test_only_email_score_warning(self):
        result = self.scorer.compute(email_score=0.5, file_score=None, web_score=None)
        self.assertAlmostEqual(result.total_score, 0.5, places=2)
        self.assertEqual(result.verdict, Verdict.WARNING)
        self.assertAlmostEqual(result.weights_used["email"], 1.0, places=2)

    # Kịch bản 5: Tất cả = 0 → PASS
    def test_all_scores_zero_pass(self):
        result = self.scorer.compute(email_score=0.0, file_score=0.0, web_score=0.0)
        self.assertAlmostEqual(result.total_score, 0.0, places=2)
        self.assertEqual(result.verdict, Verdict.PASS)

    # Kịch bản 6: Email an toàn → PASS
    def test_safe_email_pass(self):
        result = self.scorer.compute(email_score=0.1, file_score=0.05, web_score=0.1)
        # R = 0.04 + 0.015 + 0.03 = 0.085
        self.assertAlmostEqual(result.total_score, 0.085, places=2)
        self.assertEqual(result.verdict, Verdict.PASS)

    # Kịch bản 7: Ngưỡng chính xác → WARNING (>= 0.4)
    def test_exact_warning_threshold(self):
        result = self.scorer.compute(email_score=0.4, file_score=0.4, web_score=0.4)
        self.assertAlmostEqual(result.total_score, 0.4, places=2)
        self.assertEqual(result.verdict, Verdict.WARNING)

    # Kịch bản 8: Ngưỡng chính xác → DANGER (>= 0.7)
    def test_exact_danger_threshold(self):
        result = self.scorer.compute(email_score=0.7, file_score=0.7, web_score=0.7)
        self.assertAlmostEqual(result.total_score, 0.7, places=2)
        self.assertEqual(result.verdict, Verdict.DANGER)


if __name__ == "__main__":
    unittest.main()
