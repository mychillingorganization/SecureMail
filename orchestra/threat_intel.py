from dataclasses import dataclass


@dataclass
class HashScanResult:
    hash_value: str
    verdict: str
    source: str


class ThreatIntelScanner:
    """Simple hash scanner interface for step-3 triage.

    This is a local stub that can be replaced by a real VT/internal CTI provider.
    """

    def __init__(self, malicious_hashes: set[str] | None = None) -> None:
        self._malicious_hashes = malicious_hashes or set()

    def scan_hash(self, hash_value: str) -> HashScanResult:
        verdict = "MALICIOUS" if hash_value in self._malicious_hashes else "SAFE"
        return HashScanResult(hash_value=hash_value, verdict=verdict, source="local-stub")
