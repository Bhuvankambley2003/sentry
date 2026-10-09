"""Shared configuration via pydantic-settings (reads .env)."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # API gateway
    api_host: str = Field("127.0.0.1", alias="HOMEGUARD_API_HOST")
    api_port: int = Field(8000, alias="HOMEGUARD_API_PORT")
    token_file: Path = Field(Path("~/.homeguard/token"), alias="HOMEGUARD_TOKEN_FILE")

    # Internal service ports
    scanner_port: int = Field(8001, alias="HOMEGUARD_SCANNER_PORT")
    discovery_port: int = Field(8002, alias="HOMEGUARD_DISCOVERY_PORT")
    identity_port: int = Field(8003, alias="HOMEGUARD_IDENTITY_PORT")
    trust_port: int = Field(8004, alias="HOMEGUARD_TRUST_PORT")
    notifier_port: int = Field(8005, alias="HOMEGUARD_NOTIFIER_PORT")
    inventory_port: int = Field(8006, alias="HOMEGUARD_INVENTORY_PORT")

    # Redis
    redis_url: str = Field("redis://127.0.0.1:6379/0", alias="REDIS_URL")

    # Database — expand ~ at runtime
    database_url: str = Field(
        f"sqlite+aiosqlite://{Path('~/.homeguard/homeguard.db').expanduser()}",
        alias="DATABASE_URL",
    )

    # Scanner
    scan_interval_seconds: int = Field(120, alias="SCAN_INTERVAL_SECONDS")
    port_probe_enabled: bool = Field(True, alias="PORT_PROBE_ENABLED")
    port_probe_timeout_ms: int = Field(500, alias="PORT_PROBE_TIMEOUT_MS")
    port_probe_concurrency: int = Field(10, alias="PORT_PROBE_CONCURRENCY")

    # Logging
    log_level: str = Field("INFO", alias="LOG_LEVEL")
    log_format: str = Field("json", alias="LOG_FORMAT")

    def service_url(self, name: str) -> str:
        """Return the base URL for a named internal service."""
        port_map = {
            "scanner": self.scanner_port,
            "discovery": self.discovery_port,
            "identity": self.identity_port,
            "trust": self.trust_port,
            "notifier": self.notifier_port,
            "inventory": self.inventory_port,
            "api": self.api_port,
        }
        port = port_map[name]
        return f"http://127.0.0.1:{port}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
