from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from datetime import date, datetime, time, timedelta, timezone

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..config import get_settings


LICENSE_KEY_PATTERN = re.compile(r"^[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$")
LICENSE_KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class TokenError(ValueError):
    pass


def normalize_license_key(raw: str) -> str:
    return (raw or "").strip().upper()


def is_license_key_format_valid(raw: str) -> bool:
    return bool(LICENSE_KEY_PATTERN.match(normalize_license_key(raw)))


def generate_license_key() -> str:
    groups = []
    for _ in range(4):
        groups.append("".join(secrets.choice(LICENSE_KEY_ALPHABET) for _ in range(4)))
    return "-".join(groups)


def hash_license_key(raw_key: str) -> str:
    settings = get_settings()
    normalized = normalize_license_key(raw_key)
    if not is_license_key_format_valid(normalized):
        raise ValueError("License key format must be XXXX-XXXX-XXXX-XXXX")
    return hmac.new(
        settings.license_key_secret.encode("utf-8"),
        normalized.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _activation_token_expiration(expiration_date: date | None) -> datetime:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    default_exp = now + timedelta(minutes=settings.activation_token_ttl_minutes)

    if expiration_date is None:
        return default_exp

    license_exp = datetime.combine(expiration_date, time.max).replace(tzinfo=timezone.utc)
    return min(default_exp, license_exp)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    text = str(raw or "").strip()
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _license_signing_key() -> Ed25519PrivateKey:
    settings = get_settings()
    seed = hashlib.sha256(settings.license_signing_key.encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def get_activation_token_public_key() -> str:
    raw = _license_signing_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64url_encode(raw)


def build_activation_token(
    *,
    license_id: int,
    activation_id: int,
    license_key: str,
    device_id: str,
    device_fingerprint: str,
    product: str,
    license_status: str,
    expiration_date: date | None,
) -> tuple[str, datetime]:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    exp = _activation_token_expiration(expiration_date)

    payload = {
        "token_type": "offline_license",
        "iss": settings.activation_token_issuer,
        "sub": f"license:{license_id}",
        "license_key": normalize_license_key(license_key),
        "license_id": license_id,
        "activation_id": activation_id,
        "device_id": device_id,
        "device_fingerprint": device_fingerprint,
        "product": product,
        "plan": product,
        "license_status": license_status,
        "jti": secrets.token_hex(12),
        "issued_at": int(now.timestamp()),
        "expires_at": int(exp.timestamp()),
        "last_server_time": int(now.timestamp()),
    }

    header = {"alg": "Ed25519", "typ": "MSLT1"}
    encoded_header = _b64url_encode(_canonical_json(header))
    encoded_payload = _b64url_encode(_canonical_json(payload))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = _license_signing_key().sign(signing_input)
    token = f"{encoded_header}.{encoded_payload}.{_b64url_encode(signature)}"
    return token, exp


def decode_activation_token(token: str) -> dict:
    settings = get_settings()
    try:
        encoded_header, encoded_payload, encoded_signature = str(token or "").strip().split(".")
        header = json.loads(_b64url_decode(encoded_header).decode("utf-8"))
        claims = json.loads(_b64url_decode(encoded_payload).decode("utf-8"))
        signature = _b64url_decode(encoded_signature)
    except Exception as exc:
        raise TokenError("invalid activation token") from exc

    if header != {"alg": "Ed25519", "typ": "MSLT1"}:
        raise TokenError("invalid activation token")

    try:
        _license_signing_key().public_key().verify(signature, f"{encoded_header}.{encoded_payload}".encode("ascii"))
    except Exception as exc:
        raise TokenError("invalid activation token") from exc

    required = {
        "license_key",
        "license_id",
        "activation_id",
        "device_id",
        "device_fingerprint",
        "issued_at",
        "expires_at",
        "last_server_time",
        "iss",
        "token_type",
    }
    if claims.get("token_type") != "offline_license" or not required.issubset(claims):
        raise TokenError("activation token missing required claims")
    if str(claims.get("iss", "")).strip() != settings.activation_token_issuer:
        raise TokenError("invalid activation token")

    try:
        expires_at_epoch = int(claims["expires_at"])
    except Exception as exc:
        raise TokenError("activation token missing required claims") from exc
    if expires_at_epoch <= int(datetime.now(timezone.utc).timestamp()):
        raise TokenError("activation token expired")

    return claims


def build_launch_token(
    *,
    license_id: int,
    challenge_id: str,
    device_id: str,
    device_fingerprint: str,
) -> tuple[str, datetime]:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    exp = now + timedelta(seconds=int(settings.launch_token_ttl_seconds))

    payload = {
        "token_type": "launch",
        "iss": settings.activation_token_issuer,
        "sub": f"license:{license_id}",
        "license_id": license_id,
        "challenge_id": challenge_id,
        "device_id": device_id,
        "device_fingerprint": device_fingerprint,
        "jti": secrets.token_hex(12),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    token = jwt.encode(payload, settings.jwt_secret, algorithm="HS256")
    return token, exp


def decode_launch_token(token: str) -> dict:
    settings = get_settings()
    try:
        claims = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=["HS256"],
            issuer=settings.activation_token_issuer,
            options={"require": ["exp", "iat", "iss", "token_type"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("launch token expired") from exc
    except jwt.PyJWTError as exc:
        raise TokenError("invalid launch token") from exc

    required = {"license_id", "challenge_id", "device_id", "device_fingerprint", "exp"}
    if claims.get("token_type") != "launch" or not required.issubset(claims):
        raise TokenError("launch token missing required claims")

    return claims
