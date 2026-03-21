"""
Tests cho EarlyTerminator — Kill Switch logic theo PRD Section 4.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest

from early_termination import EarlyTerminator
from models import AgentResult


class TestEarlyTerminator(unittest.TestCase):
    def setUp(self):
        self.terminator = EarlyTerminator()

    # ===== Kill Switch #1: Auth Failure =====

    def test_spf_fail_triggers_danger(self):
        """Any single auth protocol FAIL → DANGER."""
        should_halt, reason = self.terminator.check_auth_failure(
            {"spf": "FAIL", "dkim": "PASS", "dmarc": "PASS"}
        )
        self.assertTrue(should_halt)
        self.assertIn("SPF", reason)

    def test_dkim_fail_triggers_danger(self):
        should_halt, reason = self.terminator.check_auth_failure(
            {"spf": "PASS", "dkim": "FAIL", "dmarc": "PASS"}
        )
        self.assertTrue(should_halt)
        self.assertIn("DKIM", reason)

    def test_dmarc_fail_triggers_danger(self):
        should_halt, reason = self.terminator.check_auth_failure(
            {"spf": "PASS", "dkim": "PASS", "dmarc": "FAIL"}
        )
        self.assertTrue(should_halt)
        self.assertIn("DMARC", reason)

    def test_all_pass_no_termination(self):
        """All protocols PASS → no termination."""
        should_halt, reason = self.terminator.check_auth_failure(
            {"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"}
        )
        self.assertFalse(should_halt)

    def test_all_fail_triggers_danger(self):
        should_halt, reason = self.terminator.check_auth_failure(
            {"spf": "FAIL", "dkim": "FAIL", "dmarc": "FAIL"}
        )
        self.assertTrue(should_halt)
        self.assertIn("SPF", reason)
        self.assertIn("DKIM", reason)
        self.assertIn("DMARC", reason)

    # ===== Kill Switch #2: Known Threat =====

    def test_malicious_hash_triggers_danger(self):
        """File hash flagged MALICIOUS → DANGER."""
        should_halt, reason = self.terminator.check_known_threat(
            hash_results=[{"hash": "abc123", "status": "MALICIOUS"}]
        )
        self.assertTrue(should_halt)
        self.assertIn("MALICIOUS", reason)

    def test_safe_hash_no_termination(self):
        should_halt, reason = self.terminator.check_known_threat(
            hash_results=[{"hash": "abc123", "status": "SAFE"}]
        )
        self.assertFalse(should_halt)

    def test_malware_agent_triggers_danger(self):
        """FileAgent detects definitive malware → DANGER."""
        result = AgentResult(
            agent_name="file",
            risk_score=0.95,
            confidence=0.99,
            details={"malware_detected": True},
        )
        should_halt, reason = self.terminator.check_known_threat(agent_result=result)
        self.assertTrue(should_halt)
        self.assertIn("malware", reason)

    def test_blacklisted_url_triggers_danger(self):
        """WebAgent detects blacklisted URL → DANGER."""
        result = AgentResult(
            agent_name="web",
            risk_score=0.9,
            confidence=0.95,
            details={"blacklisted": True},
        )
        should_halt, reason = self.terminator.check_known_threat(agent_result=result)
        self.assertTrue(should_halt)
        self.assertIn("blacklisted", reason)

    def test_phishing_triggers_danger(self):
        """WebAgent detects phishing → DANGER."""
        result = AgentResult(
            agent_name="web",
            risk_score=0.9,
            confidence=0.95,
            details={"phishing_detected": True},
        )
        should_halt, reason = self.terminator.check_known_threat(agent_result=result)
        self.assertTrue(should_halt)
        self.assertIn("phishing", reason)

    def test_clean_agent_no_termination(self):
        result = AgentResult(
            agent_name="file",
            risk_score=0.2,
            confidence=0.7,
            details={"malware_detected": False},
        )
        should_halt, reason = self.terminator.check_known_threat(agent_result=result)
        self.assertFalse(should_halt)

    # ===== Kill Switch #3: Threshold =====

    def test_issue_count_0_no_termination(self):
        should_halt, reason = self.terminator.check_issue_threshold(0)
        self.assertFalse(should_halt)

    def test_issue_count_1_no_termination(self):
        should_halt, reason = self.terminator.check_issue_threshold(1)
        self.assertFalse(should_halt)

    def test_issue_count_2_triggers_danger(self):
        """issue_count >= 2 → DANGER."""
        should_halt, reason = self.terminator.check_issue_threshold(2)
        self.assertTrue(should_halt)
        self.assertIn("issue_count=2", reason)

    def test_issue_count_5_triggers_danger(self):
        should_halt, reason = self.terminator.check_issue_threshold(5)
        self.assertTrue(should_halt)


if __name__ == "__main__":
    unittest.main()
