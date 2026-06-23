"""
rexdr - Entity Store Service
config.py - Engine configuration and settings

Author  : Rayyan Umair
Date    : 2026-06-23
Purpose : Defines configuration for the standalone Entity Store service.
          This service owns the single writable DuckDB connection to
          entity_store.duckdb. Every other engine talks to this service
          over HTTP rather than opening the file directly - DuckDB
          enforces a single writer per file, so a shared file mounted
          into eight separate engine containers cannot be opened
          directly by all of them simultaneously. This service is the
          fix for that constraint.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"One identity. One risk score. Every engine."

--- Part of the REXDR platform. ---
"""

# -- Third Party -------------------------------------------------------------
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class EntityStoreSettings(BaseSettings):
    """Configuration for the standalone Entity Store service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8008)
    data_dir: str = Field(default="/data")
    log_level: str = Field(default="INFO")
    log_format: str = Field(
        default="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )


settings = EntityStoreSettings()