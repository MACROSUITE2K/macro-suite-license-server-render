from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import ChallengeSession, License


class ChallengeError(ValueError):
    pass


def _as_utc(dt: datetime) -> datetime:
    """Normalize DB datetimes for safe comparisons across SQLite/postgres."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def issue_challenge(
    db: Session,
    *,
    license_obj: License,
    device_id: str,
    device_fingerprint: str,
    ip_address: str | None,
) -> ChallengeSession:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=int(settings.challenge_ttl_seconds))

    challenge = ChallengeSession(
        challenge_id=secrets.token_hex(16),
        nonce=secrets.token_hex(24),
        license_id=license_obj.id,
        device_id=device_id,
        device_fingerprint=device_fingerprint,
        ip_address=ip_address,
        expires_at=expires_at,
    )
    db.add(challenge)
    db.commit()
    db.refresh(challenge)
    return challenge


def get_challenge_for_update(db: Session, challenge_id: str) -> ChallengeSession | None:
    return db.execute(
        select(ChallengeSession)
        .where(ChallengeSession.challenge_id == challenge_id)
        .with_for_update()
    ).scalar_one_or_none()


def derive_device_key(device_fingerprint: str) -> bytes:
    settings = get_settings()
    return hmac.new(
        settings.hmac_key.encode("utf-8"),
        device_fingerprint.encode("utf-8"),
        hashlib.sha256,
    ).digest()


def canonical_challenge_payload(
    *,
    challenge_id: str,
    nonce: str,
    timestamp: int,
    device_id: str,
    device_fingerprint: str,
) -> bytes:
    return (
        f"{challenge_id}\n{nonce}\n{int(timestamp)}\n{device_id}\n{device_fingerprint}".encode("utf-8")
    )


def build_challenge_signature(
    *,
    challenge_id: str,
    nonce: str,
    timestamp: int,
    device_id: str,
    device_fingerprint: str,
) -> str:
    key = derive_device_key(device_fingerprint)
    payload = canonical_challenge_payload(
        challenge_id=challenge_id,
        nonce=nonce,
        timestamp=timestamp,
        device_id=device_id,
        device_fingerprint=device_fingerprint,
    )
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_challenge_signature(
    *,
    challenge: ChallengeSession,
    signature: str,
    timestamp: int,
    device_id: str,
    device_fingerprint: str,
) -> None:
    settings = get_settings()
    now = int(time.time())

    if challenge.used_at is not None:
        raise ChallengeError("challenge already used")

    if _as_utc(challenge.expires_at) < datetime.now(timezone.utc):
        raise ChallengeError("challenge expired")

    if abs(now - int(timestamp)) > int(settings.challenge_timestamp_ttl_seconds):
        raise ChallengeError("challenge timestamp outside allowed window")

    if challenge.device_id != device_id or challenge.device_fingerprint != device_fingerprint:
        raise ChallengeError("challenge device mismatch")

    expected = build_challenge_signature(
        challenge_id=challenge.challenge_id,
        nonce=challenge.nonce,
        timestamp=timestamp,
        device_id=device_id,
        device_fingerprint=device_fingerprint,
    )
    if not secrets.compare_digest(expected, str(signature or "")):
        raise ChallengeError("invalid challenge signature")


def consume_challenge(challenge: ChallengeSession) -> None:
    challenge.used_at = datetime.now(timezone.utc)


