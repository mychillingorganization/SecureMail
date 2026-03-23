from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from orchestra.config import Settings
from orchestra.models import AuditLog, Email
from orchestra.pipeline import PipelineDependencies, execute_pipeline
from orchestra.threat_intel import ThreatIntelScanner


class DummyProtocolVerifier:
    def __init__(self, *, auth_ok: bool = True) -> None:
        self._auth_ok = auth_ok

    def verify_from_eml_file(self, _path: str):
        if self._auth_ok:
            return {
                "spf": {"pass": True},
                "dkim": {"pass": True},
                "dmarc": {"pass": True},
            }
        return {
            "spf": {"pass": False},
            "dkim": {"pass": False},
            "dmarc": {"pass": False},
        }


class DummyAgentClient:
    def __init__(self, payload: dict):
        self._payload = payload

    async def analyze(self, _payload: dict):
        return self._payload


class FailIfCalledAgentClient:
    async def analyze(self, _payload: dict):
        raise AssertionError("Agent should not be called for empty inputs")


class WebChecksAgentClient:
    async def analyze(self, _payload: dict):
        return {
            "risk_score": 0.1,
            "label": "safe",
            "checks": {
                "url_analysis": [
                    {
                        "input_url": "https://bad.example",
                        "risk_score": 0.91,
                        "label": "phishing",
                    }
                ]
            },
        }


@pytest.mark.asyncio
async def test_pipeline_pass(db_session, monkeypatch):
    def fake_parse_eml(_eml_path, attachments_dir):
        (attachments_dir / "a.txt").write_text("benign")
        return SimpleNamespace(
            subject="msg-1",
            sent_at="2026-01-01T00:00:00",
            auth_headers={"from": ["sender@example.com"], "to": ["receiver@example.com"]},
            plain_parts=["hello"],
            urls={"https://example.com"},
        )

    monkeypatch.setattr("orchestra.pipeline.parse_eml", fake_parse_eml)

    deps = PipelineDependencies(
        settings=Settings(),
        email_client=DummyAgentClient({"risk_score": 0.1, "label": "safe"}),
        file_client=DummyAgentClient({"risk_score": 0.1, "label": "safe"}),
        web_client=DummyAgentClient({"risk_score": 0.1, "label": "safe"}),
        threat_scanner=ThreatIntelScanner(set()),
        protocol_verifier=DummyProtocolVerifier(auth_ok=True),
    )

    result = await execute_pipeline("/tmp/fake.eml", db_session, deps)

    assert result.final_status == "PASS"
    assert result.issue_count == 0
    assert result.termination_reason is None

    emails = (await db_session.execute(select(Email))).scalars().all()
    logs = (await db_session.execute(select(AuditLog))).scalars().all()
    assert len(emails) == 1
    assert len(logs) == 1


@pytest.mark.asyncio
async def test_pipeline_warning(db_session, monkeypatch):
    def fake_parse_eml(_eml_path, attachments_dir):
        (attachments_dir / "a.txt").write_text("benign")
        return SimpleNamespace(
            subject="msg-2",
            sent_at="2026-01-01T00:00:00",
            auth_headers={"from": ["sender@example.com"], "to": ["receiver@example.com"]},
            plain_parts=["hello"],
            urls={"https://example.com"},
        )

    monkeypatch.setattr("orchestra.pipeline.parse_eml", fake_parse_eml)

    deps = PipelineDependencies(
        settings=Settings(),
        email_client=DummyAgentClient({"risk_score": 0.8, "label": "phishing"}),
        file_client=DummyAgentClient({"risk_score": 0.1, "label": "safe"}),
        web_client=DummyAgentClient({"risk_score": 0.1, "label": "safe"}),
        threat_scanner=ThreatIntelScanner(set()),
        protocol_verifier=DummyProtocolVerifier(auth_ok=True),
    )

    result = await execute_pipeline("/tmp/fake.eml", db_session, deps)

    assert result.final_status == "WARNING"
    assert result.issue_count == 1


@pytest.mark.asyncio
async def test_pipeline_danger_auth_failure(db_session, monkeypatch):
    def fake_parse_eml(_eml_path, attachments_dir):
        (attachments_dir / "a.txt").write_text("benign")
        return SimpleNamespace(
            subject="msg-3",
            sent_at="2026-01-01T00:00:00",
            auth_headers={"from": ["sender@example.com"], "to": ["receiver@example.com"]},
            plain_parts=["hello"],
            urls={"https://example.com"},
        )

    monkeypatch.setattr("orchestra.pipeline.parse_eml", fake_parse_eml)

    deps = PipelineDependencies(
        settings=Settings(),
        email_client=DummyAgentClient({"risk_score": 0.1, "label": "safe"}),
        file_client=DummyAgentClient({"risk_score": 0.1, "label": "safe"}),
        web_client=DummyAgentClient({"risk_score": 0.1, "label": "safe"}),
        threat_scanner=ThreatIntelScanner(set()),
        protocol_verifier=DummyProtocolVerifier(auth_ok=False),
    )

    result = await execute_pipeline("/tmp/fake.eml", db_session, deps)

    assert result.final_status == "DANGER"
    assert "Auth Failure" in (result.termination_reason or "")


@pytest.mark.asyncio
async def test_pipeline_danger_malicious_hash(db_session, monkeypatch):
    content = b"known-malware"
    malicious_hash = hashlib.sha256(content).hexdigest()

    def fake_parse_eml(_eml_path, attachments_dir):
        (attachments_dir / "bad.bin").write_bytes(content)
        return SimpleNamespace(
            subject="msg-4",
            sent_at="2026-01-01T00:00:00",
            auth_headers={"from": ["sender@example.com"], "to": ["receiver@example.com"]},
            plain_parts=["hello"],
            urls={"https://example.com"},
        )

    monkeypatch.setattr("orchestra.pipeline.parse_eml", fake_parse_eml)

    deps = PipelineDependencies(
        settings=Settings(),
        email_client=DummyAgentClient({"risk_score": 0.1, "label": "safe"}),
        file_client=DummyAgentClient({"risk_score": 0.1, "label": "safe"}),
        web_client=DummyAgentClient({"risk_score": 0.1, "label": "safe"}),
        threat_scanner=ThreatIntelScanner({malicious_hash}),
        protocol_verifier=DummyProtocolVerifier(auth_ok=True),
    )

    result = await execute_pipeline("/tmp/fake.eml", db_session, deps)

    assert result.final_status == "DANGER"
    assert "Malicious file hash" in (result.termination_reason or "")


@pytest.mark.asyncio
async def test_pipeline_skips_file_and_web_without_inputs(db_session, monkeypatch):
    def fake_parse_eml(_eml_path, _attachments_dir):
        return SimpleNamespace(
            subject="msg-5",
            sent_at="2026-01-01T00:00:00",
            auth_headers={"from": ["sender@example.com"], "to": ["receiver@example.com"]},
            plain_parts=["hello"],
            urls=set(),
        )

    monkeypatch.setattr("orchestra.pipeline.parse_eml", fake_parse_eml)

    deps = PipelineDependencies(
        settings=Settings(),
        email_client=DummyAgentClient({"risk_score": 0.1, "label": "safe"}),
        file_client=FailIfCalledAgentClient(),
        web_client=FailIfCalledAgentClient(),
        threat_scanner=ThreatIntelScanner(set()),
        protocol_verifier=DummyProtocolVerifier(auth_ok=True),
    )

    result = await execute_pipeline("/tmp/fake.eml", db_session, deps)

    assert result.final_status == "PASS"
    assert any("FileAgent skipped - no attachments" in line for line in result.execution_logs)
    assert any("WebAgent skipped - no URLs" in line for line in result.execution_logs)


@pytest.mark.asyncio
async def test_pipeline_halts_on_web_agent_url_checks(db_session, monkeypatch):
    def fake_parse_eml(_eml_path, _attachments_dir):
        return SimpleNamespace(
            subject="msg-6",
            sent_at="2026-01-01T00:00:00",
            auth_headers={"from": ["sender@example.com"], "to": ["receiver@example.com"]},
            plain_parts=["hello"],
            urls={"https://bad.example"},
        )

    monkeypatch.setattr("orchestra.pipeline.parse_eml", fake_parse_eml)

    deps = PipelineDependencies(
        settings=Settings(),
        email_client=DummyAgentClient({"risk_score": 0.1, "label": "safe"}),
        file_client=FailIfCalledAgentClient(),
        web_client=WebChecksAgentClient(),
        threat_scanner=ThreatIntelScanner(set()),
        protocol_verifier=DummyProtocolVerifier(auth_ok=True),
    )

    result = await execute_pipeline("/tmp/fake.eml", db_session, deps)

    assert result.final_status == "DANGER"
    assert any("WebAgent detected phishing URL" in line for line in result.execution_logs)
