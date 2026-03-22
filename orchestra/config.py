from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for the orchestrator service."""

    model_config = SettingsConfigDict(env_file=".env", env_prefix="SECUREMAIL_", extra="ignore")

    service_name: str = "orchestrator"
    email_agent_url: str = "http://localhost:8000"
    file_agent_url: str = "http://localhost:8001"
    web_agent_url: str = "http://localhost:8002"

    database_url: str = "postgresql+asyncpg://securemail:securemail@localhost:5432/securemail"
    request_timeout_seconds: float = 20.0
    email_suspicious_threshold: float = 0.8
    count_file_agent_unavailable_as_issue: bool = False
    google_ai_studio_api_key: str | None = None
    google_ai_studio_model: str = "gemini-3.1-flash-lite-preview"
    google_ai_studio_base_url: str = "https://generativelanguage.googleapis.com/v1beta"

    # If any scanned file hash is in this comma-separated list, mark as MALICIOUS.
    threat_intel_malicious_hashes: str = ""


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
