"""Application settings and database configuration using pydantic-settings."""

from functools import lru_cache
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database Configuration (FalkorDB)
    FALKORDB_HOST: str = "localhost"
    FALKORDB_PORT: int = 6379
    FALKORDB_PASSWORD: str | None = None
    FALKORDB_GRAPH: str = "vulnify"

    # Security & Session Configuration
    SESSION_SECRET: str
    SESSION_TTL_MINUTES: int = 480
    COOKIE_SECURE: bool = False
    ALLOWED_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    @field_validator("SESSION_SECRET")
    @classmethod
    def validate_session_secret(cls, v: str) -> str:
        if not v or len(v.strip()) < 32:
            raise ValueError(
                "SESSION_SECRET is weak or missing: must be at least 32 characters long."
            )
        return v.strip()

    @property
    def allowed_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
