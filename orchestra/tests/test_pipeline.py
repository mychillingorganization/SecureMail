"""
Tests cho ReActPipeline — 8-step pipeline theo PRD.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from config import Settings
from models import EmailScanRequest, Verdict
from pipeline import ReActPipeline


class TestReActPipeline(unittest.TestCase):
    def setUp(self):
        self.settings = Settings(
            EMAIL_AGENT_URL="http://localhost:8000",
            FILE_AGENT_URL="http://localhost:8001",
            WEB_AGENT_URL="http://localhost:8002",
            RISK_WEIGHT_EMAIL=0.4,
            RISK_WEIGHT_FILE=0.3,
            RISK_WEIGHT_WEB=0.3,
            EARLY_TERM_CONFIDENCE_THRESHOLD=0.95,
        )
        self.pipeline = ReActPipeline(settings=self.settings)

    def _make_request(self, attachments=None, urls=None, headers=None):
        """Helper tạo EmailScanRequest."""
        return EmailScanRequest(
            email_id="test-001",
            headers=headers or {
                "from": "attacker@evil.com",
                "to": "victim@bank.com",
                "subject": "Test Email",
                "authentication_results": {
                    "spf": "PASS",
                    "dkim": "PASS",
                    "dmarc": "PASS",
                },
            },
            body_text="This is a test email body",
            attachments=attachments or [],
            urls=urls or [],
        )

    def _mock_agent_response(self, risk_score=0.3, confidence=0.7, suspicious=False, **extra):
        """Tạo mock response cho agent."""
        data = {
            "risk_score": risk_score,
            "confidence": confidence,
            "suspicious": suspicious,
            **extra,
        }
        mock_resp = AsyncMock()
        mock_resp.json.return_value = data
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    # Test 1: Auth failure → DANGER (Kill Switch #1)
    @patch("pipeline.check_auth", return_value={"spf": "FAIL", "dkim": "PASS", "dmarc": "PASS"})
    @patch("pipeline.parse_eml", return_value={"urls": [], "content": {}, "attachments": []})
    def test_auth_failure_danger(self, mock_parse, mock_auth):
        request = self._make_request()
        result = asyncio.run(self.pipeline.run(request))

        self.assertEqual(result.final_status, Verdict.DANGER)
        self.assertTrue(result.early_terminated)
        self.assertIn("Auth Failure", result.termination_reason)

    # Test 2: Hash scan MALICIOUS → DANGER (Kill Switch #2)
    @patch("pipeline.check_auth", return_value={"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"})
    @patch("pipeline.parse_eml", return_value={"urls": [], "content": {}, "attachments": []})
    @patch("pipeline.scan_hash", return_value="MALICIOUS")
    def test_malicious_hash_danger(self, mock_scan, mock_parse, mock_auth):
        request = self._make_request(
            attachments=[{"filename": "malware.exe", "hash": "evil123"}],
        )
        result = asyncio.run(self.pipeline.run(request))

        self.assertEqual(result.final_status, Verdict.DANGER)
        self.assertTrue(result.early_terminated)
        self.assertIn("MALICIOUS", result.termination_reason)

    # Test 3: Email only (low risk) → PASS
    @patch("pipeline.check_auth", return_value={"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"})
    @patch("pipeline.parse_eml", return_value={"urls": [], "content": {}, "attachments": []})
    @patch("pipeline.scan_hash", return_value="SAFE")
    def test_email_only_pass(self, mock_scan, mock_parse, mock_auth):
        request = self._make_request()
        # Mock the _call_agent method directly
        async def mock_call_agent(agent_name, url, payload):
            from models import AgentResult
            return AgentResult(
                agent_name=agent_name, risk_score=0.2, confidence=0.6,
                details={"suspicious": False}
            )
        self.pipeline._call_agent = mock_call_agent

        result = asyncio.run(self.pipeline.run(request))

        self.assertEqual(result.final_status, Verdict.PASS)
        self.assertEqual(result.issue_count, 0)
        self.assertEqual(len(result.agent_results), 1)

    # Test 4: One suspicious agent → WARNING (issue_count=1)
    @patch("pipeline.check_auth", return_value={"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"})
    @patch("pipeline.parse_eml", return_value={"urls": [], "content": {}, "attachments": []})
    @patch("pipeline.scan_hash", return_value="SAFE")
    def test_one_suspicious_warning(self, mock_scan, mock_parse, mock_auth):
        request = self._make_request()
        async def mock_call_agent(agent_name, url, payload):
            from models import AgentResult
            return AgentResult(
                agent_name=agent_name, risk_score=0.5, confidence=0.7,
                details={"suspicious": True}
            )
        self.pipeline._call_agent = mock_call_agent

        result = asyncio.run(self.pipeline.run(request))

        self.assertEqual(result.final_status, Verdict.WARNING)
        self.assertEqual(result.issue_count, 1)

    # Test 5: Full pipeline all pass → PASS
    @patch("pipeline.check_auth", return_value={"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"})
    @patch("pipeline.parse_eml", return_value={"urls": [], "content": {}, "attachments": []})
    @patch("pipeline.scan_hash", return_value="SAFE")
    def test_full_pipeline_all_pass(self, mock_scan, mock_parse, mock_auth):
        request = self._make_request(
            attachments=[{"filename": "report.pdf", "hash": "abc123"}],
            urls=["http://example.com"],
        )
        async def mock_call_agent(agent_name, url, payload):
            from models import AgentResult
            return AgentResult(
                agent_name=agent_name, risk_score=0.1, confidence=0.8,
                details={"suspicious": False, "malware_detected": False, "blacklisted": False}
            )
        self.pipeline._call_agent = mock_call_agent

        result = asyncio.run(self.pipeline.run(request))

        self.assertEqual(result.final_status, Verdict.PASS)
        self.assertEqual(result.issue_count, 0)
        self.assertFalse(result.early_terminated)
        self.assertGreater(len(result.execution_logs), 0)

    # Test 6: Execution logs recorded
    @patch("pipeline.check_auth", return_value={"spf": "PASS", "dkim": "PASS", "dmarc": "PASS"})
    @patch("pipeline.parse_eml", return_value={"urls": [], "content": {}, "attachments": []})
    @patch("pipeline.scan_hash", return_value="SAFE")
    def test_execution_logs_recorded(self, mock_scan, mock_parse, mock_auth):
        request = self._make_request()
        async def mock_call_agent(agent_name, url, payload):
            from models import AgentResult
            return AgentResult(
                agent_name=agent_name, risk_score=0.1, confidence=0.8,
                details={"suspicious": False}
            )
        self.pipeline._call_agent = mock_call_agent

        result = asyncio.run(self.pipeline.run(request))

        self.assertGreater(len(result.execution_logs), 0)
        log_text = " ".join(result.execution_logs)
        self.assertIn("Step 1", log_text)
        self.assertIn("Step 2", log_text)
        self.assertIn("Step 7", log_text)


if __name__ == "__main__":
    unittest.main()
