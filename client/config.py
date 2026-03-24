from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


LOCAL_APPDATA = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
LOCALHOST_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _env_str(name: str, default: str = "") -> str:
    return str(os.environ.get(name, default) or "").strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(os.environ.get(name, default)).strip())
    except Exception:
        return int(default)


def _is_localhost_url(url: str) -> bool:
    try:
        parsed = urlparse(str(url or "").strip())
    except Exception:
        return False
    host = str(parsed.hostname or "").strip().lower()
    return host in LOCALHOST_HOSTS


@dataclass(frozen=True)
class ClientConfig:
    server_url: str = field(default_factory=lambda: _env_str("LICENSE_SERVER_URL", "https://YOUR_REAL_LICENSE_API_URL"))
    pinned_public_key_sha256: str = field(default_factory=lambda: _env_str("PINNED_PUBLIC_KEY_SHA256").lower())
    client_shared_secret: str = field(default_factory=lambda: _env_str("CLIENT_SHARED_SECRET"))
    device_hmac_key: str = field(default_factory=lambda: _env_str("DEVICE_HMAC_KEY", _env_str("HMAC_KEY")))

    app_version: str = field(default_factory=lambda: _env_str("APP_VERSION", "1.0.0"))
    request_timeout_seconds: int = field(default_factory=lambda: _env_int("REQUEST_TIMEOUT_SECONDS", 15))
    heartbeat_interval_seconds: int = field(default_factory=lambda: _env_int("HEARTBEAT_INTERVAL_SECONDS", 240))

    state_dir: Path = field(default_factory=lambda: Path(_env_str("STATE_DIR", str(LOCAL_APPDATA / "Macro Suite Secure"))))
    state_file: str = field(default_factory=lambda: _env_str("STATE_FILE", "license_state.dpapi"))

    require_code_signature: bool = field(default_factory=lambda: _as_bool(os.environ.get("REQUIRE_CODE_SIGNATURE"), True))
    expected_self_sha256: str = field(default_factory=lambda: _env_str("EXPECTED_SELF_SHA256").lower())
    allow_insecure_localhost: bool = field(default_factory=lambda: _as_bool(os.environ.get("ALLOW_INSECURE_LOCALHOST"), False))

    def __post_init__(self) -> None:
        server_url = str(self.server_url or "").strip().rstrip("/")
        if not server_url:
            raise RuntimeError("LICENSE_SERVER_URL is required.")
        object.__setattr__(self, "server_url", server_url)

        is_localhost = _is_localhost_url(server_url)
        if not server_url.lower().startswith("https://"):
            if not (self.allow_insecure_localhost and is_localhost and server_url.lower().startswith("http://")):
                raise RuntimeError("LICENSE_SERVER_URL must use HTTPS unless it targets localhost.")

        if len(self.client_shared_secret.strip()) < 32:
            raise RuntimeError("CLIENT_SHARED_SECRET must be at least 32 chars.")

        if len(self.device_hmac_key.strip()) < 32:
            raise RuntimeError("DEVICE_HMAC_KEY must be at least 32 chars.")

        pin = str(self.pinned_public_key_sha256 or "").strip().lower()
        if server_url.lower().startswith("https://") and not self.should_skip_certificate_pinning():
            if len(pin) != 64:
                raise RuntimeError("PINNED_PUBLIC_KEY_SHA256 must be a 64-char SHA256 hex fingerprint.")
        elif pin and len(pin) != 64:
            raise RuntimeError("PINNED_PUBLIC_KEY_SHA256 must be a 64-char SHA256 hex fingerprint when provided.")

        if not (180 <= int(self.heartbeat_interval_seconds) <= 300):
            raise RuntimeError("HEARTBEAT_INTERVAL_SECONDS must be between 180 and 300.")

    def is_localhost_server(self) -> bool:
        return _is_localhost_url(self.server_url)

    def should_skip_certificate_pinning(self) -> bool:
        pin = str(self.pinned_public_key_sha256 or "").strip().lower()
        missing_or_placeholder_pin = (not pin) or set(pin) == {"0"}
        return bool(self.allow_insecure_localhost and self.is_localhost_server() and missing_or_placeholder_pin)

