from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .security_tools.secrets_policy import validate_server_secrets


class Settings(BaseSettings):
    app_name: str = "License Server"
    environment: Literal["development", "production"] = "production"
    database_url: str = Field(default="sqlite:///./license.db")

    # Core server controls.
    secure_startup_enforced: bool = True
    admin_token: str = Field(default="change-this-admin-token")

    # License and token signing secrets.
    license_key_secret: str = Field(default="change-this-license-key-secret")
    activation_token_secret: str = Field(default="change-this-activation-token-secret")

    # Additional hardening secrets required at startup.
    jwt_secret: str = Field(default="change-this-jwt-secret")
    server_secret: str = Field(default="change-this-server-secret")
    api_secret: str = Field(default="change-this-api-secret")
    hmac_key: str = Field(default="change-this-hmac-key")
    license_signing_key: str = Field(default="change-this-license-signing-key")

    # Session/token lifetimes.
    activation_token_ttl_minutes: int = Field(default=30, ge=15, le=60)
    launch_token_ttl_seconds: int = Field(default=300, ge=60, le=900)
    activation_token_issuer: str = "license-server"

    # Challenge/response anti-replay.
    challenge_ttl_seconds: int = Field(default=120, ge=30, le=600)
    challenge_timestamp_ttl_seconds: int = Field(default=90, ge=30, le=300)

    # Runtime heartbeat guidance for clients (15-30 seconds).
    heartbeat_interval_seconds: int = Field(default=15, ge=15, le=30)

    # TLS enforcement.
    require_https: bool = True
    allow_http_localhost: bool = False
    proxy_proto_header: str = "x-forwarded-proto"

    # Client request-signing security.
    require_client_signatures: bool = True
    client_shared_secret: str = Field(default="change-this-client-shared-secret")
    client_signature_ttl_seconds: int = Field(default=120, ge=30, le=300)

    # Per-IP in-memory rate limiting.
    rate_limit_window_seconds: int = Field(default=60, ge=10, le=600)
    rate_limit_activate_per_window: int = Field(default=20, ge=1, le=10000)
    rate_limit_validate_per_window: int = Field(default=120, ge=1, le=10000)
    rate_limit_heartbeat_per_window: int = Field(default=120, ge=1, le=10000)
    rate_limit_challenge_per_window: int = Field(default=40, ge=1, le=10000)
    rate_limit_security_event_per_window: int = Field(default=30, ge=1, le=10000)

    # Per-license controls.
    per_license_rate_limit_window_seconds: int = Field(default=60, ge=10, le=600)
    per_license_activate_per_window: int = Field(default=8, ge=1, le=1000)
    per_license_validate_per_window: int = Field(default=40, ge=1, le=1000)

    # Abuse detection and automatic response.
    auto_revoke_on_abuse: bool = True
    max_activation_failures_per_hour: int = Field(default=10, ge=3, le=1000)
    max_heartbeat_failures_per_activation: int = Field(default=6, ge=2, le=1000)
    max_ip_changes_per_activation_per_day: int = Field(default=4, ge=1, le=1000)
    max_tamper_events_per_day: int = Field(default=1, ge=1, le=100)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


def _validate_security_policies(settings: Settings) -> None:
    if not settings.secure_startup_enforced:
        return

    validate_server_secrets(
        {
            "ADMIN_TOKEN": settings.admin_token,
            "LICENSE_KEY_SECRET": settings.license_key_secret,
            "ACTIVATION_TOKEN_SECRET": settings.activation_token_secret,
            "CLIENT_SHARED_SECRET": settings.client_shared_secret,
            "JWT_SECRET": settings.jwt_secret,
            "SERVER_SECRET": settings.server_secret,
            "API_SECRET": settings.api_secret,
            "HMAC_KEY": settings.hmac_key,
            "LICENSE_SIGNING_KEY": settings.license_signing_key,
        }
    )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    _validate_security_policies(settings)
    return settings
