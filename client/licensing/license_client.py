from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
import uuid
from dataclasses import dataclass

import requests

from ..config import ClientConfig
from ..security.cert_pinning import assert_pinned_public_key


@dataclass
class LicenseClientError(RuntimeError):
    message: str
    status_code: int | None = None
    body: str | None = None


class LicenseClient:
    def __init__(self, config: ClientConfig) -> None:
        self.config = config
        self.session = requests.Session()
        self._pin_verified = False

    def _verify_pin(self) -> None:
        if self._pin_verified:
            return
        if self.config.should_skip_certificate_pinning():
            self._pin_verified = True
            return
        assert_pinned_public_key(self.config.server_url, self.config.pinned_public_key_sha256)
        self._pin_verified = True

    def _signed_headers(self, *, url: str, method: str, body: bytes) -> dict[str, str]:
        timestamp = str(int(time.time()))
        nonce = uuid.uuid4().hex
        path = urllib.parse.urlparse(url).path or "/"
        body_hash = hashlib.sha256(body).hexdigest()
        canonical = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_hash}".encode("utf-8")
        signature = hmac.new(self.config.client_shared_secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        return {
            "Content-Type": "application/json",
            "X-Client-Timestamp": timestamp,
            "X-Client-Nonce": nonce,
            "X-Client-Signature": signature,
        }

    def _post(self, path: str, payload: dict, timeout: int | None = None) -> dict:
        self._verify_pin()
        url = f"{self.config.server_url.rstrip('/')}{path}"
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = self._signed_headers(url=url, method="POST", body=body)
        response = self.session.post(url, data=body, headers=headers, timeout=timeout or self.config.request_timeout_seconds)

        if response.status_code >= 400:
            raise LicenseClientError(
                message=f"HTTP {response.status_code} for {path}",
                status_code=response.status_code,
                body=response.text,
            )

        try:
            return response.json()
        except Exception as exc:
            raise LicenseClientError(message=f"Invalid JSON response for {path}: {exc}") from exc

    def request_challenge(self, *, license_key: str, device_id: str, device_name: str, device_fingerprint: str) -> dict:
        return self._post(
            "/challenge/request",
            {
                "license_key": license_key.strip().upper(),
                "device_id": device_id,
                "device_name": device_name,
                "device_fingerprint": device_fingerprint,
            },
        )

    def verify_challenge(
        self,
        *,
        challenge_id: str,
        license_key: str,
        device_id: str,
        device_fingerprint: str,
        timestamp: int,
        signature: str,
    ) -> dict:
        return self._post(
            "/challenge/verify",
            {
                "challenge_id": challenge_id,
                "license_key": license_key.strip().upper(),
                "device_id": device_id,
                "device_fingerprint": device_fingerprint,
                "timestamp": int(timestamp),
                "signature": signature,
            },
        )

    def activate(
        self,
        *,
        license_key: str,
        device_id: str,
        device_name: str,
        device_fingerprint: str,
        launch_token: str,
    ) -> dict:
        return self._post(
            "/activate",
            {
                "license_key": license_key.strip().upper(),
                "device_id": device_id,
                "device_name": device_name,
                "device_fingerprint": device_fingerprint,
                "launch_token": launch_token,
            },
        )

    def validate(
        self,
        *,
        activation_token: str,
        device_id: str,
        device_fingerprint: str,
    ) -> dict:
        return self._post(
            "/validate",
            {
                "activation_token": activation_token,
                "device_id": device_id,
                "device_fingerprint": device_fingerprint,
            },
        )

    def heartbeat(
        self,
        *,
        activation_token: str,
        device_id: str,
        device_fingerprint: str,
        app_version: str,
        uptime_seconds: int,
    ) -> dict:
        return self._post(
            "/heartbeat",
            {
                "activation_token": activation_token,
                "device_id": device_id,
                "device_fingerprint": device_fingerprint,
                "app_version": app_version,
                "uptime_seconds": int(uptime_seconds),
            },
        )

    def report_security_event(
        self,
        *,
        event_type: str,
        severity: str,
        detail: str,
        activation_token: str | None = None,
        license_key: str | None = None,
        device_id: str | None = None,
        device_fingerprint: str | None = None,
    ) -> None:
        payload = {
            "event_type": event_type,
            "severity": severity,
            "detail": detail,
            "activation_token": activation_token,
            "license_key": license_key,
            "device_id": device_id,
            "device_fingerprint": device_fingerprint,
        }
        clean_payload = {k: v for k, v in payload.items() if v is not None}
        self._post("/security/event", clean_payload)
