from typing import Any

import httpx


class AgentClient:
    def __init__(self, base_url: str, timeout_seconds: float = 20.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds

    async def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response = await client.post(f"{self._base_url}/api/v1/analyze", json=payload)
            response.raise_for_status()
            return response.json()
