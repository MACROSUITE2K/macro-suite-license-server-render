from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
import urllib.parse
import uuid
from pathlib import Path

import requests

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from client.security.device_fingerprint import build_challenge_signature

ADMIN_HEADER = "X-Admin-Token"


def _require_env(name: str) -> str:
    value = str(os.getenv(name, "")).strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _json_or_raise(response: requests.Response) -> dict:
    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError(
            f"{response.request.method} {response.request.path_url} returned invalid JSON"
        ) from exc

    if not str(response.headers.get("content-type", "")).lower().startswith("application/json"):
        raise RuntimeError(
            f"{response.request.method} {response.request.path_url} returned non-JSON content-type"
        )
    return payload


def _signed_headers(url: str, payload: dict, client_shared_secret: str) -> tuple[bytes, dict[str, str]]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = uuid.uuid4().hex
    path = urllib.parse.urlparse(url).path or "/"
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"POST\n{path}\n{timestamp}\n{nonce}\n{body_hash}".encode("utf-8")
    signature = hmac.new(
        client_shared_secret.encode("utf-8"),
        canonical,
        hashlib.sha256,
    ).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-Client-Timestamp": timestamp,
        "X-Client-Nonce": nonce,
        "X-Client-Signature": signature,
    }
    return body, headers


def _post_signed(base_url: str, path: str, payload: dict, client_shared_secret: str) -> dict:
    url = f"{base_url.rstrip('/')}{path}"
    body, headers = _signed_headers(url, payload, client_shared_secret)
    response = requests.post(url, data=body, headers=headers, timeout=20)
    payload_json = _json_or_raise(response)
    if response.status_code >= 400:
        raise RuntimeError(f"POST {path} failed: {response.status_code} {json.dumps(payload_json)}")
    return payload_json


def main() -> int:
    base_url = _require_env("LICENSE_SERVER_URL").rstrip("/")
    if urllib.parse.urlparse(base_url).scheme.lower() != "https":
        raise RuntimeError("LICENSE_SERVER_URL must use HTTPS")
    admin_token = _require_env("LICENSE_ADMIN_TOKEN")
    client_shared_secret = _require_env("CLIENT_SHARED_SECRET")
    device_hmac_key = str(
        os.getenv("DEVICE_HMAC_KEY", os.getenv("HMAC_KEY", ""))
    ).strip()
    if not device_hmac_key:
        raise RuntimeError("DEVICE_HMAC_KEY or HMAC_KEY is required")

    health_response = requests.get(f"{base_url}/health", timeout=20)
    health_payload = _json_or_raise(health_response)
    if health_response.status_code >= 400:
        raise RuntimeError(f"GET /health failed: {health_response.status_code} {json.dumps(health_payload)}")
    if health_payload.get("status") != "ok":
        raise RuntimeError(f"GET /health returned unexpected payload: {json.dumps(health_payload)}")

    product_name = f"Render Prod Verification {int(time.time())}"
    generate_response = requests.post(
        f"{base_url}/generate",
        json={
            "product": product_name,
            "max_devices": 2,
            "expiration_date": None,
        },
        headers={ADMIN_HEADER: admin_token},
        timeout=20,
    )
    generate_payload = _json_or_raise(generate_response)
    if generate_response.status_code >= 400:
        raise RuntimeError(
            f"POST /generate failed: {generate_response.status_code} {json.dumps(generate_payload)}"
        )

    license_key = str(generate_payload.get("license_key") or "").strip().upper()
    if not license_key:
        raise RuntimeError("POST /generate did not return a license key")

    device_id = f"render-prod-verifier-{int(time.time())}"
    device_name = "Render Verification Device"
    device_fingerprint = hashlib.sha256(device_id.encode("utf-8")).hexdigest()

    challenge_payload = _post_signed(
        base_url,
        "/challenge",
        {
            "license_key": license_key,
            "device_id": device_id,
            "device_name": device_name,
            "device_fingerprint": device_fingerprint,
        },
        client_shared_secret,
    )

    challenge_id = str(challenge_payload.get("challenge_id") or "").strip()
    nonce = str(challenge_payload.get("nonce") or "").strip()
    if not challenge_id or not nonce:
        raise RuntimeError("POST /challenge did not return a usable challenge")

    timestamp = int(time.time())
    challenge_signature = build_challenge_signature(
        challenge_id=challenge_id,
        nonce=nonce,
        timestamp=timestamp,
        device_id=device_id,
        device_fingerprint=device_fingerprint,
        device_hmac_key=device_hmac_key,
    )

    verify_payload = _post_signed(
        base_url,
        "/challenge/verify",
        {
            "challenge_id": challenge_id,
            "license_key": license_key,
            "device_id": device_id,
            "device_fingerprint": device_fingerprint,
            "timestamp": timestamp,
            "signature": challenge_signature,
        },
        client_shared_secret,
    )

    launch_token = str(verify_payload.get("launch_token") or "").strip()
    if not launch_token:
        raise RuntimeError("POST /challenge/verify did not return a launch token")

    activate_payload = _post_signed(
        base_url,
        "/activate",
        {
            "license_key": license_key,
            "device_id": device_id,
            "device_name": device_name,
            "device_fingerprint": device_fingerprint,
            "launch_token": launch_token,
        },
        client_shared_secret,
    )

    activation_token = str(activate_payload.get("activation_token") or "").strip()
    if not activation_token:
        raise RuntimeError("POST /activate did not return an activation token")
    if str(activate_payload.get("status") or "").strip() not in {"activated", "already_activated"}:
        raise RuntimeError(f"POST /activate returned unexpected payload: {json.dumps(activate_payload)}")

    validate_payload = _post_signed(
        base_url,
        "/validate",
        {
            "activation_token": activation_token,
            "device_id": device_id,
            "device_fingerprint": device_fingerprint,
        },
        client_shared_secret,
    )
    if not bool(validate_payload.get("valid")):
        raise RuntimeError(f"POST /validate returned invalid result: {json.dumps(validate_payload)}")

    summary = {
        "url": base_url,
        "health": health_payload,
        "challenge": {
            "challenge_id": challenge_id,
            "has_nonce": bool(nonce),
        },
        "activate": {
            "status": activate_payload.get("status"),
            "device_id": activate_payload.get("device_id"),
        },
        "validate": {
            "valid": validate_payload.get("valid"),
            "device_id": validate_payload.get("device_id"),
        },
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
