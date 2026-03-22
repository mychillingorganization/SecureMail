from dataclasses import dataclass


@dataclass
class TerminationDecision:
    halt: bool
    reason: str | None = None


def should_terminate(issue_count: int, auth_failed: bool, malicious_detected: bool, reason: str | None = None) -> TerminationDecision:
    """Evaluate kill-switch conditions from the orchestration plan."""
    if auth_failed:
        return TerminationDecision(halt=True, reason=reason or "Auth failure")
    if malicious_detected:
        return TerminationDecision(halt=True, reason=reason or "Known malicious indicator")
    if issue_count >= 2:
        return TerminationDecision(halt=True, reason=reason or "Issue threshold reached")
    return TerminationDecision(halt=False, reason=None)
