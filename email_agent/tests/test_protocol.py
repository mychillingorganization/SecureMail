import sys
import unittest
from unittest.mock import MagicMock, patch

# == MOCK CÁC THƯ VIỆN ĐỂ TRÁNH LỖI KHI CHƯA CÀI ĐẶT TRÊN WINDOWS ==
mock_spf = MagicMock()
mock_dkim = MagicMock()
class DKIMException(Exception):
    pass
mock_dkim.DKIMException = DKIMException

mock_checkdmarc = MagicMock()
class DMARCRecordNotFound(Exception):
    pass
class DMARCRecordIncomplete(Exception):
    pass
class DMARCError(Exception):
    pass
mock_checkdmarc.DMARCRecordNotFound = DMARCRecordNotFound
mock_checkdmarc.DMARCRecordIncomplete = DMARCRecordIncomplete
mock_checkdmarc.checkdmarcError = DMARCError

sys.modules['spf'] = mock_spf
sys.modules['dkim'] = mock_dkim
sys.modules['checkdmarc'] = mock_checkdmarc

# =================================================================

from email_agent.protocol_verifier import ProtocolVerifier  # noqa: E402


class TestProtocolVerifier(unittest.TestCase):
    def setUp(self):
        self.verifier = ProtocolVerifier()

    # ====== TEST SPF ======
    @patch('spf.check2')
    def test_spf_pass(self, mock_spf_check2):
        mock_spf_check2.return_value = ('pass', 250, 'sender SPF authorized')
        res = self.verifier.verify_spf('1.2.3.4', 'example.com', 'test@example.com')
        self.assertTrue(res['pass'])
        self.assertEqual(res['result'], 'pass')

    @patch('spf.check2')
    def test_spf_softfail(self, mock_spf_check2):
        mock_spf_check2.return_value = ('softfail', 250, 'transitioning domains')
        res = self.verifier.verify_spf('1.2.3.4', 'example.com', 'test@example.com')
        self.assertFalse(res['pass'])
        self.assertEqual(res['result'], 'softfail')

    @patch('spf.check2')
    def test_spf_fail(self, mock_spf_check2):
        mock_spf_check2.return_value = ('fail', 550, 'SPF fail - not authorized')
        res = self.verifier.verify_spf('1.2.3.4', 'example.com', 'test@example.com')
        self.assertFalse(res['pass'])
        self.assertEqual(res['result'], 'fail')

    @patch('spf.check2')
    def test_spf_temperror_dns_timeout(self, mock_spf_check2):
        mock_spf_check2.return_value = ('temperror', 451, 'DNS timeout')
        res = self.verifier.verify_spf('1.2.3.4', 'example.com', 'test@example.com')
        self.assertFalse(res['pass'])
        self.assertEqual(res['result'], 'temperror')

    @patch('spf.check2')
    def test_spf_exception(self, mock_spf_check2):
        mock_spf_check2.side_effect = Exception("Internal SPF crash")
        res = self.verifier.verify_spf('1.2.3.4', 'example.com', 'test@example.com')
        self.assertFalse(res['pass'])
        self.assertEqual(res['result'], 'error')
        self.assertTrue("Internal SPF crash" in res['error'])

    # ====== TEST DKIM ======
    @patch('dkim.verify')
    def test_dkim_pass(self, mock_dkim_verify):
        mock_dkim_verify.return_value = True
        res = self.verifier.verify_dkim(b"raw email content")
        self.assertTrue(res['pass'])
        self.assertEqual(res['result'], 'pass')

    @patch('dkim.verify')
    def test_dkim_fail(self, mock_dkim_verify):
        mock_dkim_verify.return_value = False
        res = self.verifier.verify_dkim(b"raw email content with bad signature")
        self.assertFalse(res['pass'])
        self.assertEqual(res['result'], 'fail')

    @patch('dkim.verify')
    def test_dkim_dkimexception(self, mock_dkim_verify):
        mock_dkim_verify.side_effect = sys.modules['dkim'].DKIMException("Invalid DKIM format")
        res = self.verifier.verify_dkim(b"malformed raw email")
        self.assertFalse(res['pass'])
        self.assertEqual(res['result'], 'error')
        self.assertEqual(res['error'], "Invalid DKIM format")

    @patch('dkim.verify')
    def test_dkim_general_exception(self, mock_dkim_verify):
        mock_dkim_verify.side_effect = Exception("General Error")
        res = self.verifier.verify_dkim(b"raw email")
        self.assertFalse(res['pass'])
        self.assertEqual(res['result'], 'error')
        self.assertTrue("General Error" in res['error'])

    @patch('dkim.verify')
    def test_dkim_empty_email(self, mock_dkim_verify):
        mock_dkim_verify.return_value = False
        res = self.verifier.verify_dkim(b"")
        self.assertFalse(res['pass'])
        self.assertEqual(res['result'], 'fail')

    # ====== TEST DMARC ======
    @patch('checkdmarc.check_dmarc_record')
    def test_dmarc_pass(self, mock_dmarc_check):
        mock_dmarc_check.return_value = {
            "record": "v=DMARC1; p=reject;",
            "tags": {"p": {"value": "reject"}}
        }
        res = self.verifier.verify_dmarc("example.com")
        self.assertTrue(res['pass'])
        self.assertEqual(res['result'], 'pass')
        self.assertEqual(res['policy'], 'reject')

    @patch('checkdmarc.check_dmarc_record')
    def test_dmarc_none_policy(self, mock_dmarc_check):
        mock_dmarc_check.return_value = {
            "record": "v=DMARC1; p=none;",
            "tags": {"p": {"value": "none"}}
        }
        res = self.verifier.verify_dmarc("example.com")
        self.assertTrue(res['pass'])
        self.assertEqual(res['result'], 'pass')
        self.assertEqual(res['policy'], 'none')

    @patch('checkdmarc.check_dmarc_record')
    def test_dmarc_record_not_found(self, mock_dmarc_check):
        mock_dmarc_check.side_effect = sys.modules['checkdmarc'].DMARCRecordNotFound("No DMARC record")
        res = self.verifier.verify_dmarc("example.com")
        self.assertFalse(res['pass'])
        self.assertEqual(res['result'], 'none')
        self.assertEqual(res['policy'], 'none')

    @patch('checkdmarc.check_dmarc_record')
    def test_dmarc_record_incomplete(self, mock_dmarc_check):
        mock_dmarc_check.side_effect = sys.modules['checkdmarc'].DMARCRecordIncomplete("Incomplete record")
        res = self.verifier.verify_dmarc("example.com")
        self.assertFalse(res['pass'])
        self.assertEqual(res['result'], 'error')

    @patch('checkdmarc.check_dmarc_record')
    def test_dmarc_dns_timeout(self, mock_dmarc_check):
        mock_dmarc_check.side_effect = Exception("DNS Timeout error")
        res = self.verifier.verify_dmarc("example.com")
        self.assertFalse(res['pass'])
        self.assertEqual(res['result'], 'error')
        self.assertTrue("DNS Timeout" in res['error'])

    # ====== TEST VERIFY_ALL ======
    @patch.object(ProtocolVerifier, 'verify_spf')
    @patch.object(ProtocolVerifier, 'verify_dkim')
    @patch.object(ProtocolVerifier, 'verify_dmarc')
    def test_verify_all(self, mock_dmarc, mock_dkim, mock_spf):
        mock_spf.return_value = {"pass": True}
        mock_dkim.return_value = {"pass": True}
        mock_dmarc.return_value = {"pass": True}

        res = self.verifier.verify_all("1.2.3.4", "example.com", "test@example.com", "example.com", b"raw")
        
        self.assertTrue(res["spf"]["pass"])
        self.assertTrue(res["dkim"]["pass"])
        self.assertTrue(res["dmarc"]["pass"])
        mock_spf.assert_called_once_with("1.2.3.4", "example.com", "test@example.com")
        mock_dkim.assert_called_once_with(b"raw")
        mock_dmarc.assert_called_once_with("example.com")

if __name__ == '__main__':
    unittest.main()
