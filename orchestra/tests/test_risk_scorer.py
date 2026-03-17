"""
Tests cho RiskScorer — 5 kịch bản kiểm thử.
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

    # Kịch bản 1: Tất cả 3 agent đều có điểm
    def test_all_three_scores_present(self):
        result = self.scorer.compute(
            email_score=0.8,
            file_score=0.6,
            web_score=0.7,
        )
        # R = 0.4*0.8 + 0.3*0.6 + 0.3*0.7 = 0.32 + 0.18 + 0.21 = 0.71
        self.assertAlmostEqual(result.total_score, 0.71, places=2)
        self.assertEqual(result.verdict, Verdict.MALICIOUS)
        self.assertAlmostEqual(result.weights_used["email"], 0.4, places=2)
        self.assertAlmostEqual(result.weights_used["file"], 0.3, places=2)
        self.assertAlmostEqual(result.weights_used["web"], 0.3, places=2)

    # Kịch bản 2: Thiếu file_score (không có đính kèm)
    def test_missing_file_score_redistribution(self):
        result = self.scorer.compute(
            email_score=0.8,
            file_score=None,
            web_score=0.5,
        )
        # Trọng số phân phối lại: email = 0.4/0.7 ≈ 0.5714, web = 0.3/0.7 ≈ 0.4286
        # R = 0.5714*0.8 + 0.4286*0.5 = 0.4571 + 0.2143 = 0.6714
        self.assertAlmostEqual(result.total_score, 0.6714, places=2)
        self.assertEqual(result.verdict, Verdict.SUSPICIOUS)
        self.assertIsNone(result.component_scores["file"])

    # Kịch bản 3: Thiếu web_score (không có URL)
    def test_missing_web_score_redistribution(self):
        result = self.scorer.compute(
            email_score=0.9,
            file_score=0.8,
            web_score=None,
        )
        # Trọng số phân phối lại: email = 0.4/0.7 ≈ 0.5714, file = 0.3/0.7 ≈ 0.4286
        # R = 0.5714*0.9 + 0.4286*0.8 = 0.5143 + 0.3429 = 0.8571
        self.assertAlmostEqual(result.total_score, 0.8571, places=2)
        self.assertEqual(result.verdict, Verdict.MALICIOUS)

    # Kịch bản 4: Chỉ có email (cả file và web đều thiếu)
    def test_only_email_score(self):
        result = self.scorer.compute(
            email_score=0.5,
            file_score=None,
            web_score=None,
        )
        # Trọng số: email = 1.0
        # R = 1.0 * 0.5 = 0.5
        self.assertAlmostEqual(result.total_score, 0.5, places=2)
        self.assertEqual(result.verdict, Verdict.SUSPICIOUS)
        self.assertAlmostEqual(result.weights_used["email"], 1.0, places=2)

    # Kịch bản 5: Edge case — tất cả điểm = 0
    def test_all_scores_zero(self):
        result = self.scorer.compute(
            email_score=0.0,
            file_score=0.0,
            web_score=0.0,
        )
        self.assertAlmostEqual(result.total_score, 0.0, places=2)
        self.assertEqual(result.verdict, Verdict.SAFE)

    # Kịch bản bổ sung: Email an toàn
    def test_safe_email(self):
        result = self.scorer.compute(
            email_score=0.1,
            file_score=0.05,
            web_score=0.1,
        )
        # R = 0.4*0.1 + 0.3*0.05 + 0.3*0.1 = 0.04 + 0.015 + 0.03 = 0.085
        self.assertAlmostEqual(result.total_score, 0.085, places=2)
        self.assertEqual(result.verdict, Verdict.SAFE)


if __name__ == "__main__":
    unittest.main()
