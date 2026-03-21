"""
Early Termination — Kill Switch logic theo PRD Section 4.

Bypass issue_count nếu:
1. Authentication Failure: protocol_verifier returns FAIL
2. Known Threat: file hash/URL/domain definitively malicious or on Blacklist
3. Threshold Exceeded: issue_count >= 2
"""

import logging

from models import AgentResult

logger = logging.getLogger(__name__)


class EarlyTerminator:
    """
    Kill Switch engine — kiểm tra các điều kiện kết thúc sớm.

    PRD Section 4 — Critical Termination Protocols:
    1. Auth Failure: check_auth() returns FAIL → DANGER
    2. Known Threat: malware/phishing flagged → DANGER
    3. issue_count >= 2 → DANGER
    """

    def check_auth_failure(self, auth_results: dict[str, str]) -> tuple[bool, str]:
        """
        Kill Switch #1: Authentication Failure.
        Nếu bất kỳ protocol (SPF, DKIM, DMARC) nào trả về FAIL → DANGER.

        Args:
            auth_results: {"spf": "PASS"|"FAIL", "dkim": "PASS"|"FAIL", "dmarc": "PASS"|"FAIL"}

        Returns:
            (should_terminate, reason)
        """
        failed_protocols = []
        for protocol in ["spf", "dkim", "dmarc"]:
            if auth_results.get(protocol, "PASS").upper() == "FAIL":
                failed_protocols.append(protocol.upper())

        if failed_protocols:
            reason = f"Auth Failure: {', '.join(failed_protocols)} failed"
            logger.warning(f"KILL SWITCH: {reason}")
            return True, reason

        return False, "All authentication protocols passed"

    def check_known_threat(
        self,
        hash_results: list[dict] | None = None,
        agent_result: AgentResult | None = None,
    ) -> tuple[bool, str]:
        """
        Kill Switch #2: Known Threat (Malware/Phishing).
        Nếu bất kỳ file hash, URL, hoặc domain nào bị flag là definitively malicious.

        Args:
            hash_results: kết quả từ scan_hash, list of {"hash": "...", "status": "SAFE"|"MALICIOUS"}
            agent_result: kết quả từ agent (File/Web) chứa malware/phishing flag

        Returns:
            (should_terminate, reason)
        """
        # Check hash scan results
        if hash_results:
            for result in hash_results:
                if result.get("status", "").upper() == "MALICIOUS":
                    reason = f"Known Threat: File hash {result.get('hash', 'unknown')[:16]}... is MALICIOUS"
                    logger.warning(f"KILL SWITCH: {reason}")
                    return True, reason

        # Check agent results for definitive malware/phishing flags
        if agent_result and agent_result.details:
            details = agent_result.details

            # File Agent: definitive malware detection
            if details.get("malware_detected") is True:
                reason = f"Known Threat: {agent_result.agent_name} detected definitive malware"
                logger.warning(f"KILL SWITCH: {reason}")
                return True, reason

            # Web Agent: blacklisted URL/domain or phishing
            if details.get("blacklisted") is True:
                reason = f"Known Threat: {agent_result.agent_name} detected blacklisted URL/domain"
                logger.warning(f"KILL SWITCH: {reason}")
                return True, reason

            if details.get("phishing_detected") is True:
                reason = f"Known Threat: {agent_result.agent_name} detected phishing"
                logger.warning(f"KILL SWITCH: {reason}")
                return True, reason

        return False, "No known threats detected"

    def check_issue_threshold(self, issue_count: int) -> tuple[bool, str]:
        """
        Kill Switch #3: Threshold Exceeded.
        Nếu issue_count >= 2 → DANGER.

        Args:
            issue_count: current issue counter

        Returns:
            (should_terminate, reason)
        """
        if issue_count >= 2:
            reason = f"Threshold Exceeded: issue_count={issue_count} >= 2"
            logger.warning(f"KILL SWITCH: {reason}")
            return True, reason

        return False, f"issue_count={issue_count} < 2, within threshold"
