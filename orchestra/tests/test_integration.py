from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy import select

from orchestra.config import Settings
from orchestra.models import EntityStatus, File, Url
from orchestra.pipeline import PipelineDependencies, execute_pipeline
from orchestra.threat_intel import ThreatIntelScanner


class ProtocolOK:
    def verify_from_eml_file(self, _path: str):
        return {
            "spf": {"pass": True},
            "dkim": {"pass": True},
            "dmarc": {"pass": True},
        }


class AgentResult:
    def __init__(self, risk_score: float, label: str):
        self._risk_score = risk_score
        self._label = label

    async def analyze(self, _payload: dict):
        return {"risk_score": self._risk_score, "label": self._label}


@pytest.mark.asyncio
async def test_danger_acceptance_marks_ioc_as_malicious(db_session, monkeypatch):
    def fake_parse_eml(_eml_path, attachments_dir):
        (attachments_dir / "sample.txt").write_text("hello")
        return SimpleNamespace(
            subject="msg-5",
            sent_at="2026-01-01T00:00:00",
            auth_headers={"from": ["sender@example.com"], "to": ["receiver@example.com"]},
            plain_parts=["hello"],
            urls={"https://malicious.example"},
        )

    monkeypatch.setattr("orchestra.pipeline.parse_eml", fake_parse_eml)

    deps = PipelineDependencies(
        settings=Settings(),
        email_client=AgentResult(0.1, "safe"),
        file_client=AgentResult(0.1, "safe"),
        web_client=AgentResult(0.99, "phishing"),
        threat_scanner=ThreatIntelScanner(set()),
        protocol_verifier=ProtocolOK(),
    )

    result = await execute_pipeline(
        email_path="/tmp/fake.eml",
        session=db_session,
        deps=deps,
        user_accepts_danger=True,
    )

    assert result.final_status == "DANGER"

    urls = (await db_session.execute(select(Url))).scalars().all()
    files = (await db_session.execute(select(File))).scalars().all()

    assert len(urls) == 1
    assert len(files) == 1
    assert urls[0].status == EntityStatus.malicious
    assert files[0].status == EntityStatus.malicious
