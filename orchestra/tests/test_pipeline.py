"""
Tests cho ReActPipeline — Kiểm thử pipeline đầy đủ.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import unittest
from unittest.mock import AsyncMock, patch, MagicMock
import asyncio
from datetime import datetime

from pipeline import ReActPipeline
from config import Settings
from models import EmailScanRequest, Verdict, AgentResult


def run_async(coro):
    """Helper để chạy async test."""
    return asyncio.get_event_loop().run_until_complete(coro)


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

    def _make_request(self, attachments=None, urls=None):
        """Helper tạo EmailScanRequest."""
        return EmailScanRequest(
            email_id="test-001",
            headers={
                "from": "attacker@evil.com",
                "to": "victim@bank.com",
                "subject": "Test Email",
            },
            body_text="This is a test email body",
            attachments=attachments or [],
            urls=urls or [],
        )

    def _mock_email_response(self, risk_score=0.8, confidence=0.92,
                              spf_pass=False, dkim_pass=False, dmarc_pass=False):
        """Tạo mock response cho Email Agent."""
        return {
            "email_id": "test-001",
            "risk_score": risk_score,
            "confidence": confidence,
            "checks": {
                "spf": {"pass": spf_pass, "result": "pass" if spf_pass else "fail"},
                "dkim": {"pass": dkim_pass, "result": "pass" if dkim_pass else "fail"},
                "dmarc": {"pass": dmarc_pass, "result": "pass" if dmarc_pass else "fail"},
            },
            "processing_time_ms": 100,
        }

    def _mock_file_response(self, risk_score=0.3):
        return {"email_id": "test-001", "risk_score": risk_score, "confidence": 0.75, "processing_time_ms": 50}

    def _mock_web_response(self, risk_score=0.4):
        return {"email_id": "test-001", "risk_score": risk_score, "confidence": 0.70, "processing_time_ms": 30}

    # Test 1: Pipeline đầy đủ với tất cả agents
    @patch('httpx.AsyncClient.post')
    def test_full_pipeline_all_agents(self, mock_post):
        request = self._make_request(
            attachments=[{"filename": "report.pdf"}],
            urls=["http://example.com"],
        )

        # Mock responses cho 3 agents
        mock_responses = [
            self._mock_email_response(risk_score=0.6, confidence=0.85, spf_pass=True),
            self._mock_file_response(risk_score=0.3),
            self._mock_web_response(risk_score=0.4),
        ]

        response_mocks = []
        for resp_data in mock_responses:
            mock_resp = MagicMock()
            mock_resp.json.return_value = resp_data
            mock_resp.raise_for_status = MagicMock()
            response_mocks.append(mock_resp)

        mock_post.side_effect = response_mocks

        result = run_async(self.pipeline.run(request))

        self.assertEqual(result.email_id, "test-001")
        self.assertFalse(result.early_terminated)
        self.assertEqual(len(result.agent_results), 3)
        self.assertGreater(len(result.reasoning_traces), 0)
        self.assertIn(result.verdict, [Verdict.SAFE, Verdict.SUSPICIOUS, Verdict.MALICIOUS])

    # Test 2: Early termination — email giả mạo rõ ràng
    @patch('httpx.AsyncClient.post')
    def test_early_termination_spoofed_email(self, mock_post):
        request = self._make_request(
            attachments=[{"filename": "malware.exe"}],
            urls=["http://phishing-site.com"],
        )

        # Email Agent trả về: tất cả protocol fail + confidence > 0.95
        mock_resp = MagicMock()
        mock_resp.json.return_value = self._mock_email_response(
            risk_score=0.95, confidence=0.98,
            spf_pass=False, dkim_pass=False, dmarc_pass=False,
        )
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = run_async(self.pipeline.run(request))

        self.assertTrue(result.early_terminated)
        self.assertEqual(result.verdict, Verdict.MALICIOUS)
        # Chỉ có 1 agent (email) — File/Web bị bỏ qua
        self.assertEqual(len(result.agent_results), 1)
        self.assertEqual(result.agent_results[0].agent_name, "email")

    # Test 3: Email không có đính kèm, không có URL → chỉ gọi Email Agent
    @patch('httpx.AsyncClient.post')
    def test_email_only_no_attachments_no_urls(self, mock_post):
        request = self._make_request()  # Không có attachments/urls

        mock_resp = MagicMock()
        mock_resp.json.return_value = self._mock_email_response(
            risk_score=0.3, confidence=0.6, spf_pass=True, dkim_pass=True, dmarc_pass=True,
        )
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = run_async(self.pipeline.run(request))

        self.assertFalse(result.early_terminated)
        self.assertEqual(len(result.agent_results), 1)
        self.assertEqual(result.agent_results[0].agent_name, "email")
        self.assertEqual(result.verdict, Verdict.SAFE)  # risk_score 0.3 < 0.4

    # Test 4: Reasoning traces ghi đầy đủ các bước
    @patch('httpx.AsyncClient.post')
    def test_reasoning_traces_recorded(self, mock_post):
        request = self._make_request()

        mock_resp = MagicMock()
        mock_resp.json.return_value = self._mock_email_response(
            risk_score=0.5, confidence=0.7, spf_pass=True, dkim_pass=True, dmarc_pass=True,
        )
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        result = run_async(self.pipeline.run(request))

        phases = [t.phase for t in result.reasoning_traces]
        # Phải có: PERCEIVE, REASON, ACT, REASON (early check), OBSERVE, REASON (scoring)
        self.assertIn("PERCEIVE", phases)
        self.assertIn("REASON", phases)
        self.assertIn("ACT", phases)

    # Test 5: Có đính kèm nhưng không có URL → chỉ Email + File
    @patch('httpx.AsyncClient.post')
    def test_attachments_only_no_urls(self, mock_post):
        request = self._make_request(
            attachments=[{"filename": "doc.pdf"}],
        )

        mock_responses = [
            self._mock_email_response(risk_score=0.4, confidence=0.7, spf_pass=True),
            self._mock_file_response(risk_score=0.2),
        ]
        response_mocks = []
        for resp_data in mock_responses:
            mock_resp = MagicMock()
            mock_resp.json.return_value = resp_data
            mock_resp.raise_for_status = MagicMock()
            response_mocks.append(mock_resp)
        mock_post.side_effect = response_mocks

        result = run_async(self.pipeline.run(request))

        agent_names = [r.agent_name for r in result.agent_results]
        self.assertIn("email", agent_names)
        self.assertIn("file", agent_names)
        self.assertNotIn("web", agent_names)


if __name__ == '__main__':
    unittest.main()
