"""
Tests cho EarlyTerminator — Kiểm tra kết thúc sớm.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import unittest

from early_termination import EarlyTerminator
from models import AgentResult


class TestEarlyTerminator(unittest.TestCase):
    def setUp(self):
        self.terminator = EarlyTerminator(confidence_threshold=0.95)

    def _make_result(self, spf_pass, dkim_pass, dmarc_pass, confidence):
        """Helper tạo AgentResult với thông tin SPF/DKIM/DMARC."""
        return AgentResult(
            agent_name="email",
            risk_score=0.9,
            confidence=confidence,
            details={
                "checks": {
                    "spf": {"pass": spf_pass, "result": "pass" if spf_pass else "fail"},
                    "dkim": {"pass": dkim_pass, "result": "pass" if dkim_pass else "fail"},
                    "dmarc": {"pass": dmarc_pass, "result": "pass" if dmarc_pass else "fail"},
                }
            },
        )

    # Test 1: Tất cả fail + confidence cao → KẾT THÚC SỚM
    def test_all_protocols_fail_high_confidence_terminates(self):
        result = self._make_result(
            spf_pass=False, dkim_pass=False, dmarc_pass=False, confidence=0.98
        )
        should_term, reason = self.terminator.should_terminate(result)
        self.assertTrue(should_term)
        self.assertIn("Kết thúc sớm", reason)

    # Test 2: SPF pass → KHÔNG kết thúc sớm
    def test_spf_passes_no_termination(self):
        result = self._make_result(
            spf_pass=True, dkim_pass=False, dmarc_pass=False, confidence=0.98
        )
        should_term, reason = self.terminator.should_terminate(result)
        self.assertFalse(should_term)
        self.assertIn("SPF passed", reason)

    # Test 3: DKIM pass → KHÔNG kết thúc sớm
    def test_dkim_passes_no_termination(self):
        result = self._make_result(
            spf_pass=False, dkim_pass=True, dmarc_pass=False, confidence=0.98
        )
        should_term, reason = self.terminator.should_terminate(result)
        self.assertFalse(should_term)

    # Test 4: DMARC pass → KHÔNG kết thúc sớm
    def test_dmarc_passes_no_termination(self):
        result = self._make_result(
            spf_pass=False, dkim_pass=False, dmarc_pass=True, confidence=0.98
        )
        should_term, reason = self.terminator.should_terminate(result)
        self.assertFalse(should_term)

    # Test 5: Tất cả fail nhưng confidence thấp → KHÔNG kết thúc sớm
    def test_all_fail_low_confidence_no_termination(self):
        result = self._make_result(
            spf_pass=False, dkim_pass=False, dmarc_pass=False, confidence=0.80
        )
        should_term, reason = self.terminator.should_terminate(result)
        self.assertFalse(should_term)
        self.assertIn("confidence=0.8000 <= 0.95", reason)

    # Test 6: Confidence ngay tại ngưỡng → KHÔNG kết thúc (> chứ không >=)
    def test_confidence_at_threshold_no_termination(self):
        result = self._make_result(
            spf_pass=False, dkim_pass=False, dmarc_pass=False, confidence=0.95
        )
        should_term, reason = self.terminator.should_terminate(result)
        self.assertFalse(should_term)  # 0.95 > 0.95 is False

    # Test 7: Tất cả pass + confidence cao → KHÔNG kết thúc sớm
    def test_all_pass_high_confidence_no_termination(self):
        result = self._make_result(
            spf_pass=True, dkim_pass=True, dmarc_pass=True, confidence=0.99
        )
        should_term, reason = self.terminator.should_terminate(result)
        self.assertFalse(should_term)

    # Test 8: Không có checks trong details → KHÔNG terminate (graceful)
    def test_missing_checks_no_termination(self):
        result = AgentResult(
            agent_name="email",
            risk_score=0.5,
            confidence=0.99,
            details={},  # Không có checks
        )
        should_term, reason = self.terminator.should_terminate(result)
        # Khi không có checks, các giá trị mặc định là pass=True → không fail
        # Thực tế: get("pass", True) = True → not True = False → không fail
        self.assertFalse(should_term)


if __name__ == '__main__':
    unittest.main()
