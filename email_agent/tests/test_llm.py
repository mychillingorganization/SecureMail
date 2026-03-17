import json
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from email_agent.llm_analyzer import LLMContentAnalyzer


class TestLLMContentAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = LLMContentAnalyzer()

    def _create_mock_response(self, classification, confidence, reasoning):
        mock_response = MagicMock()
        llm_response = {"classification": classification, "confidence": confidence, "reasoning": reasoning}
        mock_response.read.return_value = json.dumps({"response": json.dumps(llm_response)}).encode("utf-8")
        return mock_response

    @patch("urllib.request.urlopen")
    def test_analyze_safe_email_1(self, mock_urlopen):
        mock_response = self._create_mock_response("safe", 0.95, "Standard newsletter.")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = self.analyzer.analyze("Newsletter Weekly", "Here is your weekly news.")
        self.assertEqual(result["classification"], "safe")

    @patch("urllib.request.urlopen")
    def test_analyze_safe_email_2(self, mock_urlopen):
        mock_response = self._create_mock_response("safe", 0.90, "Team lunch update.")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = self.analyzer.analyze("Team Lunch Tomorrow", "Hi team, lunch is at 12.")
        self.assertEqual(result["classification"], "safe")

    @patch("urllib.request.urlopen")
    def test_analyze_phishing_email_1(self, mock_urlopen):
        # 1. Tạo dữ liệu giả
        mock_response = self._create_mock_response("phishing", 0.99, "Suspicious password reset link.")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # 2. Chạy hàm analyze
        result = self.analyzer.analyze("URGENT: Password Reset", "Click here to reset your account immediately!")

        # 3. YÊU CẦU IN RA ĐỂ XEM KẾT QUẢ TRẢ VỀ:
        import json

        print("\n=== KẾT QUẢ ĐÃ MOCK ===")
        print(json.dumps(result, indent=4))

        # 4. Kiểm chứng xem giá trị trả về có đúng không
        self.assertEqual(result["classification"], "phishing")

    @patch("urllib.request.urlopen")
    def test_analyze_phishing_email_2(self, mock_urlopen):
        mock_response = self._create_mock_response("phishing", 0.92, "Fake invoice attachment.")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = self.analyzer.analyze("Invoice INC-2023", "Please find attached your overdue invoice. Pay now.")
        self.assertEqual(result["classification"], "phishing")

    @patch("urllib.request.urlopen")
    def test_analyze_bec_email(self, mock_urlopen):
        mock_response = self._create_mock_response("bec", 0.88, "CEO requesting urgent wire transfer.")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = self.analyzer.analyze("Wire Transfer Request", "Please wire $50,000 to this new vendor account ASAP. - CEO")
        self.assertEqual(result["classification"], "bec")

    @patch("urllib.request.urlopen")
    def test_retry_on_timeout(self, mock_urlopen):
        mock_response = self._create_mock_response("safe", 0.9, "Normal text")

        # side_effect list: first two calls raise exception, third returns mock_response
        mock_urlopen.side_effect = [TimeoutError("Timeout"), urllib.error.URLError("Connection reset by peer"), MagicMock(__enter__=MagicMock(return_value=mock_response))]

        result = self.analyzer.analyze("Hello", "Hi there")

        # Since max_retries is 2, the total attempts is 3. It should succeed on the 3rd.
        self.assertEqual(result["classification"], "safe")
        self.assertEqual(mock_urlopen.call_count, 3)

    @patch("urllib.request.urlopen")
    def test_failure_after_retries(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("Connection Refused")

        result = self.analyzer.analyze("Hello", "Hi there")

        self.assertEqual(result["classification"], "unknown")
        self.assertEqual(mock_urlopen.call_count, 3)


if __name__ == "__main__":
    unittest.main()
