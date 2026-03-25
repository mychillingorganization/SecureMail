from __future__ import annotations

from typing import Protocol

from ai_module.schemas import AnalyzeRequest, AnalyzeResponse


class AIProvider(Protocol):
    provider_name: str

    async def analyze(self, payload: AnalyzeRequest) -> AnalyzeResponse:
        ...
