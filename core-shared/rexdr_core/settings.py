"""
rexdr_core
settings.py - Base settings class for all REXDR engines

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Provides the canonical base settings class that every engine
          extends using pydantic-settings. Defines all shared configuration
          fields common to every engine. Each engine extends this with its
          own specific fields only. All config is read from environment
          variables or the .env file - never hardcoded.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"The foundation everything else is built on."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
from pathlib import Path

# -- Third Party -------------------------------------------------------------
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# -- Internal ----------------------------------------------------------------
from rexdr_core.identity import EngineID

# ============================================================================


class BaseEngineSettings(BaseSettings):
    """
    Base configuration class for all REXDR engines.
    Every engine extends this and adds its own specific fields.

    All values are read from environment variables or the .env file.
    The .env file is loaded from the project root by Docker Compose.
    No engine hardcodes any configuration value.

    Usage:
        class MyEngineSettings(BaseEngineSettings):
            my_engine_id: EngineID = EngineID.WINDOWS_EVENT
            winrm_host: str = Field(..., description="Target Windows host")
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Platform identity
    # -------------------------------------------------------------------------

    engine_id: EngineID = Field(
        ...,
        description="Which engine this instance is. Set per-engine in docker-compose.yml.",
    )

    # -------------------------------------------------------------------------
    # Data storage
    # -------------------------------------------------------------------------

    data_dir: Path = Field(
        default=Path("/data"),
        description="Directory where DuckDB files and Parquet archives are stored.",
    )

    archive_dir: Path = Field(
        default=Path("/data/archive"),
        description="Directory where Parquet archive files are written.",
    )

    db_retention_days: int = Field(
        default=30,
        description="How many days of data to keep in DuckDB before archiving to Parquet.",
    )

    # -------------------------------------------------------------------------
    # API server
    # -------------------------------------------------------------------------

    api_host: str = Field(
        default="0.0.0.0",
        description="Host the engine API binds to.",
    )

    api_port: int = Field(
        ...,
        description="Port the engine API listens on. Set per-engine in docker-compose.yml.",
    )

    api_workers: int = Field(
        default=1,
        description="Number of Uvicorn workers. Keep at 1 - DuckDB is single-writer.",
    )

    # -------------------------------------------------------------------------
    # ZeroMQ
    # -------------------------------------------------------------------------

    zmq_host: str = Field(
        default="0.0.0.0",
        description="ZeroMQ bind host for PUB sockets.",
    )

    zmq_publisher_port: int | None = Field(
        default=None,
        description="ZeroMQ PUB port for this engine. None if engine does not publish.",
    )

    zmq_subscriber_ports: list[int] = Field(
        default_factory=list,
        description="ZeroMQ ports this engine subscribes to.",
    )

    # -------------------------------------------------------------------------
    # AI integration
    # -------------------------------------------------------------------------

    ai_provider: str | None = Field(
        default=None,
        description="AI provider - groq, openai, anthropic, gemini, ollama. None disables AI features.",
    )

    ai_api_key: str | None = Field(
        default=None,
        description="API key for the configured AI provider.",
    )

    ai_model: str | None = Field(
        default=None,
        description="Model name override. If None, REXDR uses the recommended default per provider.",
    )

    ai_base_url: str | None = Field(
        default=None,
        description="Base URL override - used for Ollama or self-hosted providers.",
    )

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------

    log_level: str = Field(
        default="INFO",
        description="Logging level - DEBUG, INFO, WARNING, ERROR.",
    )

    log_format: str = Field(
        default="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        description="Python logging format string.",
    )

    # -------------------------------------------------------------------------
    # Network zones
    # -------------------------------------------------------------------------

    zones_config_path: Path = Field(
        default=Path("/config/zones.yaml"),
        description="Path to the network zone definitions file.",
    )

    # -------------------------------------------------------------------------
    # Platform
    # -------------------------------------------------------------------------

    environment: str = Field(
        default="production",
        description="Deployment environment - production, development, testing.",
    )

    rexdr_version: str = Field(
        default="1.0.0",
        description="REXDR platform version. Set by docker-compose.yml.",
    )