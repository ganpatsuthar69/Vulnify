"""Application settings and database configuration using pydantic-settings."""

from functools import lru_cache
from pydantic import field_validator, model_validator
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

    # Ingestion Configuration
    DEPENDENCY_IMPORT_MAX_FILE_SIZE_MB: int = 10
    DEPENDENCY_IMPORT_MAX_PACKAGES: int = 5000
    DEPENDENCY_IMPORT_BATCH_SIZE: int = 500
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # Derived from DEPENDENCY_IMPORT_MAX_FILE_SIZE_MB

    # OSV Advisory Integration Configuration
    OSV_ENABLED: bool = True
    OSV_API_BASE_URL: str = "https://api.osv.dev"
    OSV_API_TIMEOUT_SECONDS: int = 15
    OSV_REQUEST_TIMEOUT_SECONDS: int | None = None  # Alias for OSV_API_TIMEOUT_SECONDS
    OSV_API_MAX_RETRIES: int = 3
    OSV_MAX_RETRIES: int | None = None  # Alias for OSV_API_MAX_RETRIES
    OSV_API_BACKOFF_BASE_SECONDS: float = 1.0
    OSV_CACHE_TTL_SECONDS: int = 86400
    OSV_MAX_CONCURRENT_REQUESTS: int = 5
    OSV_BATCH_SIZE: int = 100

    @field_validator("DEPENDENCY_IMPORT_MAX_FILE_SIZE_MB")
    @classmethod
    def validate_max_file_size_mb(cls, v: int) -> int:
        if v <= 0 or v > 100:
            raise ValueError("DEPENDENCY_IMPORT_MAX_FILE_SIZE_MB must be between 1 and 100 MB.")
        return v

    @field_validator("DEPENDENCY_IMPORT_MAX_PACKAGES")
    @classmethod
    def validate_max_packages(cls, v: int) -> int:
        if v <= 0 or v > 100000:
            raise ValueError("DEPENDENCY_IMPORT_MAX_PACKAGES must be between 1 and 100,000.")
        return v

    @field_validator("DEPENDENCY_IMPORT_BATCH_SIZE")
    @classmethod
    def validate_import_batch_size(cls, v: int) -> int:
        if v <= 0 or v > 5000:
            raise ValueError("DEPENDENCY_IMPORT_BATCH_SIZE must be between 1 and 5,000.")
        return v

    @field_validator("SESSION_SECRET")
    @classmethod
    def validate_session_secret(cls, v: str) -> str:
        if not v or len(v.strip()) < 32:
            raise ValueError(
                "SESSION_SECRET is weak or missing: must be at least 32 characters long."
            )
        return v.strip()

    @field_validator("OSV_API_TIMEOUT_SECONDS")
    @classmethod
    def validate_osv_timeout(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("OSV_API_TIMEOUT_SECONDS must be positive.")
        return v

    @field_validator("OSV_API_MAX_RETRIES")
    @classmethod
    def validate_osv_retries(cls, v: int) -> int:
        if v < 0:
            raise ValueError("OSV_API_MAX_RETRIES cannot be negative.")
        return v

    @field_validator("OSV_API_BACKOFF_BASE_SECONDS")
    @classmethod
    def validate_osv_backoff(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("OSV_API_BACKOFF_BASE_SECONDS must be positive.")
        return v

    @field_validator("OSV_CACHE_TTL_SECONDS")
    @classmethod
    def validate_osv_cache_ttl(cls, v: int) -> int:
        if v < 0:
            raise ValueError("OSV_CACHE_TTL_SECONDS cannot be negative.")
        return v

    @field_validator("OSV_MAX_CONCURRENT_REQUESTS")
    @classmethod
    def validate_osv_concurrency(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("OSV_MAX_CONCURRENT_REQUESTS must be positive.")
        return v

    @field_validator("OSV_BATCH_SIZE")
    @classmethod
    def validate_osv_batch_size(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("OSV_BATCH_SIZE must be positive.")
        return v

    @model_validator(mode="after")
    def sync_derived_settings(self) -> "Settings":
        self.MAX_UPLOAD_SIZE_BYTES = self.DEPENDENCY_IMPORT_MAX_FILE_SIZE_MB * 1024 * 1024
        if self.OSV_REQUEST_TIMEOUT_SECONDS is not None:
            self.OSV_API_TIMEOUT_SECONDS = self.OSV_REQUEST_TIMEOUT_SECONDS
        if self.OSV_MAX_RETRIES is not None:
            self.OSV_API_MAX_RETRIES = self.OSV_MAX_RETRIES
        return self

    @property
    def allowed_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
