from fastapi import FastAPI

from ai_module.config import get_ai_agent_settings
from ai_module.providers.factory import get_provider
from ai_module.schemas import AnalyzeRequest, AnalyzeResponse

app = FastAPI(title="SecureMail AI Agent", version="0.1.0")


@app.get("/health")
async def health() -> dict[str, str]:
    settings = get_ai_agent_settings()
    return {"status": "ok", "service": settings.service_name, "provider": settings.provider}


@app.post("/api/v1/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    settings = get_ai_agent_settings()
    provider = get_provider(settings)
    return await provider.analyze(request)
