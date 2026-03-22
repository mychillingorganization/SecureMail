"""
config.py — Centralized settings via pydantic-settings
Đọc từ .env hoặc biến môi trường hệ thống
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from pathlib import Path


class Settings(BaseSettings):
    # Redis
    redis_url:         str = "redis://localhost:6379/0"
    redis_ttl_seconds: int = 604800   # 7 ngày

    # PostgreSQL
    database_url: str = "postgresql+asyncpg://fileagent:fileagent@localhost:5432/fileagent"

    # ClamAV (disabled by default — unreliable)
    clamd_host: str = Field(default="localhost", description="ClamAV daemon host (use 'clamav' in Docker)")
    clamd_port: int = 3310
    clamd_timeout: int = 5  # Timeout nhanh vì không tin tưởng

    # Sandbox
    sandbox_timeout_seconds:    int = 90
    wine_exec_timeout_seconds:  int = 60

    # YARA
    yara_rules_dir: Path = Path("../yara_rules")

    # ✅ XGBoost: Primary Risk Scorer
    xgboost_model_path:             Path  = Path("../dataset/model.pkl")
    xgboost_confidence_threshold:   float = 0.70   # XGBoost output is final risk level
    xgboost_is_primary_scorer: bool = True  # XGBoost as primary scorer
    
    # ✅ ClamAV: Low priority (unreliable)
    clamd_enabled: bool = False  # Tắt ClamAV (không đáng tin)
    clamd_risk_weight: float = 0.0  # ClamAV không tác động lên risk score

    # FastAPI
    max_upload_size_mb: int = 50
    api_secret_key:     str = "change_me_in_production"

    # Logging
    log_level: str = "INFO"

    class Config:
        env_file          = ".env"
        env_file_encoding = "utf-8"
        case_sensitive    = False
        extra             = "ignore"  # ✅ Ignore unknown env variables


settings = Settings()