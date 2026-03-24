from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Activation, License, LicenseStatus, SecurityEvent


_BUCKETS: dict[str, deque[int]] = defaultdict(deque)
_LOCK = threading.Lock()


def _record_window_event(bucket: str, key: str, window_seconds: int) -> int:
    now_ts = int(time.time())
    cutoff = now_ts - int(window_seconds)
    bucket_key = f"{bucket}:{key}"

    with _LOCK:
        queue = _BUCKETS[bucket_key]
        while queue and queue[0] <= cutoff:
            queue.popleft()
        queue.append(now_ts)
        return len(queue)


def log_security_event(
    db: Session,
    *,
    event_type: str,
    severity: str,
    detail: str,
    ip_address: str | None = None,
    license_id: int | None = None,
    activation_id: int | None = None,
) -> None:
    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        detail=detail[:2000],
        ip_address=ip_address,
        license_id=license_id,
        activation_id=activation_id,
    )
    db.add(event)


def _auto_revoke_license(db: Session, license_obj: License, reason: str, ip_address: str | None = None) -> None:
    if license_obj.status == LicenseStatus.revoked.value:
        return

    license_obj.status = LicenseStatus.revoked.value
    license_obj.flagged_reason = reason[:255]
    license_obj.flagged_at = datetime.now(timezone.utc)
    db.add(license_obj)

    log_security_event(
        db,
        event_type="license.auto_revoke",
        severity="critical",
        detail=reason,
        ip_address=ip_address,
        license_id=license_obj.id,
    )


def record_activation_failure(db: Session, *, license_obj: License | None, ip_address: str | None, detail: str) -> None:
    settings = get_settings()

    log_security_event(
        db,
        event_type="activation.failure",
        severity="warning",
        detail=detail,
        ip_address=ip_address,
        license_id=license_obj.id if license_obj else None,
    )

    if license_obj is not None:
        count = _record_window_event("activation_failure", str(license_obj.id), 3600)
        if count >= int(settings.max_activation_failures_per_hour):
            if settings.auto_revoke_on_abuse:
                _auto_revoke_license(
                    db,
                    license_obj,
                    reason=f"Auto-revoked after {count} activation failures within 1 hour",
                    ip_address=ip_address,
                )

    db.commit()


def record_heartbeat_failure(
    db: Session,
    *,
    license_obj: License | None,
    activation: Activation | None,
    ip_address: str | None,
    detail: str,
) -> None:
    settings = get_settings()

    if activation is not None:
        activation.heartbeat_failures = int(activation.heartbeat_failures or 0) + 1
        db.add(activation)

    log_security_event(
        db,
        event_type="heartbeat.failure",
        severity="warning",
        detail=detail,
        ip_address=ip_address,
        license_id=license_obj.id if license_obj else None,
        activation_id=activation.id if activation else None,
    )

    if (
        activation is not None
        and license_obj is not None
        and int(activation.heartbeat_failures or 0) >= int(settings.max_heartbeat_failures_per_activation)
        and settings.auto_revoke_on_abuse
    ):
        _auto_revoke_license(
            db,
            license_obj,
            reason=(
                "Auto-revoked after repeated heartbeat failures "
                f"(activation {activation.id}, failures={activation.heartbeat_failures})"
            ),
            ip_address=ip_address,
        )

    db.commit()


def track_ip_change(db: Session, *, license_obj: License, activation: Activation, new_ip: str | None) -> None:
    if not new_ip:
        return

    settings = get_settings()
    old_ip = (activation.ip_address or "").strip()
    if old_ip and old_ip != new_ip:
        activation.ip_change_count = int(activation.ip_change_count or 0) + 1
        db.add(activation)

        log_security_event(
            db,
            event_type="activation.ip_change",
            severity="warning",
            detail=f"IP changed from {old_ip} to {new_ip}",
            ip_address=new_ip,
            license_id=license_obj.id,
            activation_id=activation.id,
        )

        if int(activation.ip_change_count or 0) >= int(settings.max_ip_changes_per_activation_per_day):
            count = _record_window_event("ip_change", str(activation.id), 86400)
            if count >= int(settings.max_ip_changes_per_activation_per_day) and settings.auto_revoke_on_abuse:
                _auto_revoke_license(
                    db,
                    license_obj,
                    reason=(
                        "Auto-revoked due to excessive IP movement "
                        f"for activation {activation.id}"
                    ),
                    ip_address=new_ip,
                )

    activation.ip_address = new_ip
    db.add(activation)
    db.commit()


def record_tamper_event(
    db: Session,
    *,
    license_obj: License | None,
    activation: Activation | None,
    ip_address: str | None,
    detail: str,
) -> None:
    settings = get_settings()

    log_security_event(
        db,
        event_type="client.tamper",
        severity="critical",
        detail=detail,
        ip_address=ip_address,
        license_id=license_obj.id if license_obj else None,
        activation_id=activation.id if activation else None,
    )

    if license_obj is not None:
        count = _record_window_event("tamper", str(license_obj.id), 86400)
        if count >= int(settings.max_tamper_events_per_day) and settings.auto_revoke_on_abuse:
            _auto_revoke_license(
                db,
                license_obj,
                reason=f"Auto-revoked after {count} tamper events in 24h",
                ip_address=ip_address,
            )

    db.commit()
