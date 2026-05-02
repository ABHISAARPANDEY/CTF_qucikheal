"""Application configuration loaded from environment variables."""

from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Strongly-typed application settings sourced from the environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = Field(default="SentinelAI")
    app_version: str = Field(default="0.1.0")
    environment: str = Field(default="development")
    debug: bool = Field(default=False)

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)

    api_prefix: str = Field(default="/api/v1")
    enable_docs: bool = Field(default=True)

    log_level: str = Field(default="INFO")

    cors_origins: List[str] = Field(default_factory=lambda: ["*"])

                                                                          
                                                                      
                                                                  
    orchestrator_enabled: bool = Field(default=False)
    orchestrator_interval_seconds: float = Field(default=1.0, gt=0)

                                                                            
                                                                           
                                      
    banking_simulator_enabled: bool = Field(default=True)
    banking_simulator_interval_seconds: float = Field(default=1.5, gt=0)
    banking_attack_duration_seconds: float = Field(default=14.0, gt=0)
    kafka_enabled: bool = Field(default=False)
    kafka_bootstrap_servers: str = Field(default="localhost:9092")
    kafka_topic_raw_events: str = Field(default="raw.events")
    kafka_group_id: str = Field(default="sentinelai-pipeline")
    copilot_provider: str = Field(default="mock")
    a4f_api_key: str = Field(default="")
    a4f_base_url: str = Field(default="https://api.a4f.co/v1")
    a4f_model: str = Field(default="provider-6/gpt-4.1-mini")

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_cors_origins(cls, value):
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("log_level")
    @classmethod
    def _normalize_log_level(cls, value: str) -> str:
        return value.upper()


@lru_cache
def get_settings() -> Settings:
    """Cached accessor so settings are parsed only once per process."""
    return Settings()
