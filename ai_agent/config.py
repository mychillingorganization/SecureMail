from functools import lru_cache

from ai_agent import thresholds
from pydantic_settings import BaseSettings, SettingsConfigDict


class AIAgentSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SECUREMAIL_AI_AGENT_", extra="ignore")

    service_name: str = "ai-agent"
    provider: str = "gemini"
    request_timeout_seconds: float = thresholds.LLM_REQUEST_TIMEOUT_SECONDS
    autonomous_max_attempts: int = thresholds.MAX_AUTONOMOUS_ATTEMPTS
    autonomous_retry_backoff_seconds: float = thresholds.RETRY_BACKOFF_SECONDS
    autonomous_temperature: float = thresholds.LLM_TEMPERATURE
    autonomous_max_tool_steps: int = thresholds.MAX_TOOL_STEPS_PER_ATTEMPT

    google_ai_studio_api_key: str | None = None
    google_ai_studio_model: str = "gemini-3.1-flash-lite-preview"
    google_ai_studio_reviewer_model: str = "gemma-3-27b-it"
    google_ai_studio_base_url: str = "https://generativelanguage.googleapis.com/v1beta"
    json_reviewer_enabled: bool = True
    json_reviewer_on_error_only: bool = True
    json_reviewer_max_attempts: int = 1
    gemini_primary_rpm_limit: int = 15
    gemma_reviewer_rpm_limit: int = 30


@lru_cache(maxsize=1)
def get_ai_agent_settings() -> AIAgentSettings:
    return AIAgentSettings()
