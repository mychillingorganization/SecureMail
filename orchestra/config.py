"""
Cấu hình trung tâm cho Orchestrator.
Sử dụng Pydantic BaseSettings để load từ biến môi trường.
"""
from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Cấu hình Orchestrator - tất cả giá trị có thể ghi đè qua biến môi trường."""

    # --- Service URLs ---
    REDIS_URL: str = "redis://redis:6379/0"
    POSTGRES_URL: str = "postgresql+asyncpg://securemail:securemail@postgres:5432/securemail"
    EMAIL_AGENT_URL: str = "http://email-agent:8000"
    FILE_AGENT_URL: str = "http://file-agent:8001"
    WEB_AGENT_URL: str = "http://web-agent:8002"

    # --- Risk Scoring Weights ---
    RISK_WEIGHT_EMAIL: float = 0.4
    RISK_WEIGHT_FILE: float = 0.3
    RISK_WEIGHT_WEB: float = 0.3

    # --- Early Termination ---
    EARLY_TERM_CONFIDENCE_THRESHOLD: float = 0.95

    # --- Redis ---
    REDIS_MAX_CONNECTIONS: int = 20

    # --- Verdict Thresholds ---
    MALICIOUS_THRESHOLD: float = 0.7
    SUSPICIOUS_THRESHOLD: float = 0.4

    # --- Timeouts (seconds) ---
    AGENT_TIMEOUT: float = 30.0

    model_config = {"env_prefix": "", "case_sensitive": True}


@lru_cache
def get_settings() -> Settings:
    return Settings()
