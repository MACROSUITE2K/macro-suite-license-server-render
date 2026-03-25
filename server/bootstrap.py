from __future__ import annotations

import base64
import json
import logging
import zlib
from datetime import date, datetime, timezone

import requests
from sqlalchemy import func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .auth.token_manager import hash_license_key
from .models import Activation, License, SecurityEvent

logger = logging.getLogger("license_server.bootstrap")


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    return date.fromisoformat(value)


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _reset_postgres_sequence(conn, table_name: str) -> None:
    conn.execute(
        text(
            f"""
            SELECT setval(
                pg_get_serial_sequence('"{table_name}"', 'id'),
                COALESCE((SELECT MAX(id) FROM "{table_name}"), 1),
                true
            )
            """
        )
    )


def _load_snapshot_payload(snapshot_b64: str | None) -> tuple[list[tuple[dict, dict]], list[dict]]:
    encoded = str(snapshot_b64 or "").strip()
    if not encoded:
        return [], []

    raw = zlib.decompress(base64.b64decode(encoded)).decode("utf-8")
    payload = json.loads(raw)

    details = []
    for item in payload.get("licenses", []):
        plain_key = str(item.get("license_key", "")).strip().upper()
        detail = dict(item.get("detail") or {})
        if plain_key and detail:
            details.append(({"license_key": plain_key}, detail))
    security_events = list(payload.get("security_events", []))
    return details, security_events


def bootstrap_legacy_admin_data_if_needed(
    *,
    engine: Engine,
    admin_token: str,
    source_url: str | None,
    snapshot_b64: str | None = None,
    timeout_seconds: int = 30,
) -> None:
    if engine.dialect.name != "postgresql":
        return

    normalized_source = str(source_url or "").strip().rstrip("/")
    if not normalized_source:
        return

    with Session(engine) as db:
        existing_licenses = int(db.scalar(select(func.count(License.id))) or 0)
    if existing_licenses > 0:
        logger.info("legacy_bootstrap_skip reason=target_not_empty license_count=%s", existing_licenses)
        return

    details, security_events = _load_snapshot_payload(snapshot_b64)
    source_label = "snapshot"

    if not details and normalized_source:
        headers = {"X-Admin-Token": admin_token}
        try:
            list_response = requests.get(
                f"{normalized_source}/licenses",
                headers=headers,
                params={"status": "all", "include_expired": "true"},
                timeout=timeout_seconds,
            )
            list_response.raise_for_status()
            items = list_response.json().get("items", [])
        except Exception as exc:
            raise RuntimeError(f"legacy bootstrap failed to fetch licenses from {normalized_source}") from exc

        if items:
            source_label = normalized_source
            for item in items:
                key = str(item.get("license_key", "")).strip().upper()
                if not key:
                    continue
                try:
                    detail_response = requests.get(
                        f"{normalized_source}/license/{key}",
                        headers=headers,
                        timeout=timeout_seconds,
                    )
                    detail_response.raise_for_status()
                    details.append((item, detail_response.json()))
                except Exception as exc:
                    raise RuntimeError(f"legacy bootstrap failed to fetch details for {key}") from exc

            try:
                security_response = requests.get(
                    f"{normalized_source}/security/events",
                    headers=headers,
                    params={"limit": 200},
                    timeout=timeout_seconds,
                )
                security_response.raise_for_status()
                security_events = list(security_response.json().get("items", []))
            except Exception:
                logger.warning("legacy_bootstrap_security_events_unavailable source=%s", normalized_source)

    if not details:
        logger.info("legacy_bootstrap_skip reason=source_empty source=%s", normalized_source or "snapshot")
        return

    with engine.begin() as conn:
        conn.execute(text("TRUNCATE TABLE challenge_sessions, security_events, activations, licenses RESTART IDENTITY CASCADE"))

    activation_count = 0
    with Session(engine) as db:
        for item, detail in details:
            plain_key = str(item.get("license_key", "")).strip().upper()
            db.add(
                License(
                    id=int(detail["id"]),
                    license_key=hash_license_key(plain_key),
                    license_key_plain=plain_key,
                    license_key_suffix=plain_key[-4:],
                    product=detail["product"],
                    status=detail["status"],
                    max_devices=int(detail["max_devices"]),
                    expiration_date=_parse_date(detail.get("expiration_date")),
                    created_at=_parse_datetime(detail["created_at"]),
                    flagged_reason=detail.get("flagged_reason"),
                    flagged_at=_parse_datetime(detail.get("flagged_at")),
                )
            )
        db.flush()

        for _, detail in details:
            for activation in detail.get("activations", []):
                db.add(
                    Activation(
                        id=int(activation["id"]),
                        license_id=int(detail["id"]),
                        device_id=activation["device_id"],
                        device_name=activation["device_name"],
                        device_fingerprint=activation.get("device_fingerprint"),
                        ip_address=activation.get("ip_address"),
                        activated_at=_parse_datetime(activation["activated_at"]),
                        last_heartbeat_at=_parse_datetime(activation.get("last_heartbeat_at")),
                        heartbeat_failures=int(activation.get("heartbeat_failures") or 0),
                        ip_change_count=int(activation.get("ip_change_count") or 0),
                    )
                )
                activation_count += 1

        for event in security_events:
            db.add(
                SecurityEvent(
                    id=int(event["id"]),
                    event_type=event["event_type"],
                    severity=event["severity"],
                    detail=event["detail"],
                    ip_address=event.get("ip_address"),
                    license_id=event.get("license_id"),
                    activation_id=event.get("activation_id"),
                    created_at=_parse_datetime(event["created_at"]),
                )
            )

        db.commit()

    with engine.begin() as conn:
        for table_name in ("licenses", "activations", "challenge_sessions", "security_events"):
            _reset_postgres_sequence(conn, table_name)

    logger.info(
        "legacy_bootstrap_complete source=%s licenses=%s activations=%s security_events=%s",
        source_label,
        len(details),
        activation_count,
        len(security_events),
    )
