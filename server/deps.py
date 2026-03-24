import hashlib
import hmac
import secrets
import threading
import time
from typing import Annotated

from fastapi import Header, HTTPException, Request, status

from .config import get_settings
from .security_tools.rate_limiter import RATE_LIMITER


ADMIN_HEADER_NAME = "X-Admin-Token"
CLIENT_TS_HEADER = "X-Client-Timestamp"
CLIENT_NONCE_HEADER = "X-Client-Nonce"
CLIENT_SIG_HEADER = "X-Client-Signature"

_NONCE_CACHE: dict[str, int] = {}
_NONCE_LOCK = threading.Lock()


def has_admin_access(token: str | None) -> bool:
    settings = get_settings()
    return bool(token) and secrets.compare_digest(token, settings.admin_token)


def require_admin(
    x_admin_token: Annotated[str | None, Header(alias=ADMIN_HEADER_NAME)] = None,
) -> None:
    if not has_admin_access(x_admin_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication failed",
        )


def get_client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client is None:
        return None
    return request.client.host


def _canonical_signature_payload(
    *,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    payload = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_hash}"
    return payload.encode("utf-8")


def _compute_client_signature(
    *,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> str:
    settings = get_settings()
    payload = _canonical_signature_payload(
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
    )
    return hmac.new(settings.client_shared_secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _validate_and_store_nonce(nonce: str, now_ts: int, ttl_seconds: int) -> None:
    if not nonce or len(nonce) < 16 or len(nonce) > 256:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client nonce")

    cutoff = now_ts - ttl_seconds
    with _NONCE_LOCK:
        # Purge expired nonce entries first.
        for key in list(_NONCE_CACHE.keys()):
            if _NONCE_CACHE.get(key, 0) < cutoff:
                _NONCE_CACHE.pop(key, None)

        if nonce in _NONCE_CACHE:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Replay detected")

        _NONCE_CACHE[nonce] = now_ts


async def require_signed_client_request(
    request: Request,
    x_client_timestamp: Annotated[str | None, Header(alias=CLIENT_TS_HEADER)] = None,
    x_client_nonce: Annotated[str | None, Header(alias=CLIENT_NONCE_HEADER)] = None,
    x_client_signature: Annotated[str | None, Header(alias=CLIENT_SIG_HEADER)] = None,
) -> None:
    settings = get_settings()
    if not settings.require_client_signatures:
        return

    if not x_client_timestamp or not x_client_nonce or not x_client_signature:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing client signature headers")

    try:
        ts_int = int(x_client_timestamp)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client timestamp") from exc

    now_ts = int(time.time())
    if abs(now_ts - ts_int) > int(settings.client_signature_ttl_seconds):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Client timestamp outside allowed window")

    body = await request.body()
    expected_sig = _compute_client_signature(
        method=request.method,
        path=request.url.path,
        timestamp=x_client_timestamp,
        nonce=x_client_nonce,
        body=body,
    )

    if not secrets.compare_digest(expected_sig, x_client_signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid client signature")

    _validate_and_store_nonce(
        nonce=x_client_nonce,
        now_ts=now_ts,
        ttl_seconds=int(settings.client_signature_ttl_seconds),
    )


def _enforce_rate_limit(*, key: str, max_requests: int, window_seconds: int, detail: str) -> None:
    count_after = RATE_LIMITER.check_and_increment(
        bucket_key=key,
        max_requests=int(max_requests),
        window_seconds=int(window_seconds),
    )
    if count_after < 0:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail)


async def _rate_limit_ip_bucket(request: Request, *, bucket_name: str, max_requests: int) -> None:
    settings = get_settings()
    window = int(settings.rate_limit_window_seconds)
    ip = get_client_ip(request) or "unknown"
    key = f"ip:{bucket_name}:{ip}"
    _enforce_rate_limit(key=key, max_requests=max_requests, window_seconds=window, detail="Rate limit exceeded")


def enforce_per_license_rate_limit(bucket_name: str, license_hash: str, max_requests: int | None = None) -> None:
    settings = get_settings()
    window = int(settings.per_license_rate_limit_window_seconds)

    if max_requests is None:
        if bucket_name == "activate":
            max_requests = int(settings.per_license_activate_per_window)
        else:
            max_requests = int(settings.per_license_validate_per_window)

    key = f"license:{bucket_name}:{license_hash}"
    _enforce_rate_limit(
        key=key,
        max_requests=int(max_requests),
        window_seconds=window,
        detail="Per-license rate limit exceeded",
    )


async def rate_limit_activate(request: Request) -> None:
    settings = get_settings()
    await _rate_limit_ip_bucket(
        request,
        bucket_name="activate",
        max_requests=int(settings.rate_limit_activate_per_window),
    )


async def rate_limit_validate(request: Request) -> None:
    settings = get_settings()
    await _rate_limit_ip_bucket(
        request,
        bucket_name="validate",
        max_requests=int(settings.rate_limit_validate_per_window),
    )


async def rate_limit_heartbeat(request: Request) -> None:
    settings = get_settings()
    await _rate_limit_ip_bucket(
        request,
        bucket_name="heartbeat",
        max_requests=int(settings.rate_limit_heartbeat_per_window),
    )


async def rate_limit_challenge(request: Request) -> None:
    settings = get_settings()
    await _rate_limit_ip_bucket(
        request,
        bucket_name="challenge",
        max_requests=int(settings.rate_limit_challenge_per_window),
    )


async def rate_limit_security_event(request: Request) -> None:
    settings = get_settings()
    await _rate_limit_ip_bucket(
        request,
        bucket_name="security_event",
        max_requests=int(settings.rate_limit_security_event_per_window),
    )

