from typing import Any
from pathlib import Path

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

    async def analyze_file(self, file_path: str, full_analysis: bool = False) -> dict[str, Any]:
        """Analyze a local attachment by uploading it to File Agent multipart endpoint."""
        endpoint = "/analyze/full" if full_analysis else "/analyze"
        path_obj = Path(file_path)
        if not path_obj.exists():
            raise FileNotFoundError(f"Attachment not found: {file_path}")

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            with path_obj.open("rb") as handle:
                files = {"file": (path_obj.name, handle, "application/octet-stream")}
                response = await client.post(f"{self._base_url}{endpoint}", files=files)
            response.raise_for_status()
            return response.json()
