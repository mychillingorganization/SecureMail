"""Database-specific settings separated from orchestrator app settings."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SECUREMAIL_", extra="ignore")

    database_url: str = "postgresql+asyncpg://securemail:securemail@localhost:5432/securemail"


@lru_cache(maxsize=1)
def get_db_settings() -> DatabaseSettings:
    return DatabaseSettings()
