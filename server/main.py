from datetime import date, datetime, timezone
import json
import logging
from pathlib import Path
import time
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, inspect, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.schema import CreateColumn

from .auth.challenge_system import ChallengeError, consume_challenge, get_challenge_for_update, issue_challenge, verify_challenge_signature
from .auth.token_manager import TokenError, build_activation_token, build_launch_token, decode_activation_token, decode_launch_token, generate_license_key, hash_license_key
from .bootstrap import bootstrap_legacy_admin_data_if_needed
from .config import get_settings
from .database import Base, database_backend, database_target, engine, get_db
from .deps import ADMIN_HEADER_NAME, enforce_per_license_rate_limit, get_client_ip, has_admin_access, rate_limit_activate, rate_limit_challenge, rate_limit_heartbeat, rate_limit_security_event, rate_limit_validate, require_admin, require_signed_client_request
from .models import Activation, ChallengeSession, License, LicenseStatus, SecurityEvent
from .schemas import ActivateRequest, ActivationResponse, ChallengeRequest, ChallengeResponse, ChallengeVerifyRequest, ChallengeVerifyResponse, DeactivateRequest, DeactivateResponse, GenerateLicenseRequest, GenerateLicenseResponse, HeartbeatRequest, HeartbeatResponse, LicenseDetailsResponse, LicenseListResponse, LicenseSummaryOut, RevokeByIdRequest, RevokeRequest, RevokeResponse, SecurityEventRequest, SecurityEventResponse, ValidateRequest, ValidateResponse
from .security_tools.abuse_detection import log_security_event, record_activation_failure, record_heartbeat_failure, record_tamper_event, track_ip_change
from .security_tools.transport_guard import require_https_or_localhost

settings = get_settings()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("license_server")
app = FastAPI(
    title="License Server",
    version="2.0.0",
    docs_url=None if settings.environment == "production" else "/docs",
    redoc_url=None if settings.environment == "production" else "/redoc",
    openapi_url=None if settings.environment == "production" else "/openapi.json",
)

ADMIN_STATIC_DIR = Path(__file__).resolve().parent / "static" / "admin"
ADMIN_FAVICON_PATH = ADMIN_STATIC_DIR / "favicon.svg"
DOWNLOADS_DIR = Path(__file__).resolve().parent / "downloads"
LATEST_DOWNLOAD_METADATA_PATH = DOWNLOADS_DIR / "latest.json"
app.mount("/admin/static", StaticFiles(directory=ADMIN_STATIC_DIR), name="admin_static")


@app.middleware("http")
async def enforce_https_transport(request: Request, call_next):
    try:
        require_https_or_localhost(request, settings)
    except PermissionError as exc:
        return JSONResponse(status_code=status.HTTP_426_UPGRADE_REQUIRED, content={"detail": str(exc)})
    return await call_next(request)


@app.middleware("http")
async def log_request_lifecycle(request: Request, call_next):
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
        logger.exception(
            "request_failed method=%s path=%s client_ip=%s duration_ms=%s",
            request.method,
            request.url.path,
            get_client_ip(request),
            duration_ms,
        )
        raise

    duration_ms = round((time.perf_counter() - started) * 1000.0, 2)
    logger.info(
        "request_completed method=%s path=%s status=%s client_ip=%s duration_ms=%s",
        request.method,
        request.url.path,
        response.status_code,
        get_client_ip(request),
        duration_ms,
    )
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(RequestValidationError)
async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    logger.warning(
        "request_validation_failed path=%s client_ip=%s error_count=%s",
        request.url.path,
        get_client_ip(request),
        len(exc.errors()),
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Invalid request payload",
            "errors": exc.errors(),
        },
    )


@app.exception_handler(Exception)
async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    logger.exception(
        "unhandled_exception path=%s client_ip=%s",
        request.url.path,
        get_client_ip(request),
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


def _apply_schema_compatibility() -> None:
    compatibility_columns = {
        Activation.__table__: (
            "last_heartbeat_at",
            "device_fingerprint",
            "heartbeat_failures",
            "ip_change_count",
        ),
        License.__table__: (
            "license_key_suffix",
            "license_key_plain",
            "flagged_reason",
            "flagged_at",
        ),
    }
    managed_tables = (
        License.__table__,
        Activation.__table__,
        ChallengeSession.__table__,
        SecurityEvent.__table__,
    )

    with engine.begin() as conn:
        inspector = inspect(conn)
        known_tables = set(inspector.get_table_names())
        identifier_preparer = conn.dialect.identifier_preparer

        for table in managed_tables:
            if table.name not in known_tables:
                table.create(bind=conn, checkfirst=True)
                inspector = inspect(conn)
                known_tables = set(inspector.get_table_names())

        for table, column_names in compatibility_columns.items():
            existing_columns = {column["name"] for column in inspector.get_columns(table.name)}
            for column_name in column_names:
                if column_name in existing_columns:
                    continue
                column = table.c[column_name]
                compiled_column = str(CreateColumn(column).compile(dialect=conn.dialect))
                quoted_table = identifier_preparer.quote(table.name)
                conn.execute(text(f"ALTER TABLE {quoted_table} ADD COLUMN {compiled_column}"))
                existing_columns.add(column_name)

        for table in managed_tables:
            for index in table.indexes:
                index.create(bind=conn, checkfirst=True)

        conn.execute(text("SELECT 1"))


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)
    _apply_schema_compatibility()
    bootstrap_legacy_admin_data_if_needed(
        engine=engine,
        admin_token=settings.admin_token,
        source_url=settings.legacy_bootstrap_url,
        snapshot_b64=settings.legacy_bootstrap_snapshot_b64,
        force_replace=settings.legacy_bootstrap_force_replace,
        timeout_seconds=settings.legacy_bootstrap_timeout_seconds,
    )
    DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(
        "startup_complete database_backend=%s database_target=%s",
        database_backend,
        database_target,
    )


def _get_license_by_plain_key(db: Session, plain_key: str) -> License | None:
    try:
        hashed = hash_license_key(plain_key)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return db.execute(select(License).where(License.license_key == hashed)).scalar_one_or_none()


def _license_invalid_reason(license_obj: License) -> str | None:
    if license_obj.status != LicenseStatus.active.value:
        return f"license is {license_obj.status}"
    if license_obj.expiration_date and license_obj.expiration_date < date.today():
        return "license expired"
    return None


def _activation_count(db: Session, license_id: int) -> int:
    return int(db.scalar(select(func.count(Activation.id)).where(Activation.license_id == license_id)) or 0)


def _touch_heartbeat(activation: Activation) -> None:
    activation.last_heartbeat_at = datetime.now(timezone.utc)


def _mask_license_key(license_obj: License) -> str:
    suffix = (license_obj.license_key_suffix or "").strip()
    return f"****-****-****-{suffix}" if len(suffix) == 4 else "****-****-****-????"


def _display_license_key(license_obj: License) -> tuple[str, bool]:
    plain = str(license_obj.license_key_plain or "").strip().upper()
    if plain:
        return plain, True
    return f"{_mask_license_key(license_obj)} (legacy hidden)", False


def _validate_launch_token_or_raise(launch_token: str, license_id: int, device_id: str, device_fingerprint: str) -> None:
    try:
        claims = decode_launch_token(launch_token)
    except TokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    if int(claims["license_id"]) != int(license_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="launch token license mismatch")
    if str(claims["device_id"]) != device_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="launch token device mismatch")
    if str(claims["device_fingerprint"]) != device_fingerprint:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="launch token fingerprint mismatch")


@app.get("/health")
def health() -> dict:
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database unavailable",
        ) from exc
    return {"status": "ok"}


@app.get("/admin", include_in_schema=False)
def admin_dashboard() -> FileResponse:
    return FileResponse(ADMIN_STATIC_DIR / "index.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> FileResponse:
    return FileResponse(ADMIN_FAVICON_PATH, media_type="image/svg+xml")


def _load_latest_download_metadata() -> dict:
    if not LATEST_DOWNLOAD_METADATA_PATH.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No download package has been published yet")

    try:
        payload = json.loads(LATEST_DOWNLOAD_METADATA_PATH.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Download metadata is invalid") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Download metadata has invalid format")

    return payload


def _resolve_download_file_from_keys_or_raise(metadata: dict, keys: tuple[str, ...], missing_detail: str) -> Path:
    downloads_root = DOWNLOADS_DIR.resolve()

    for key in keys:
        file_name = str(metadata.get(key, "")).strip()
        if not file_name:
            continue

        candidate = (DOWNLOADS_DIR / file_name).resolve()
        try:
            candidate.relative_to(downloads_root)
        except ValueError:
            continue

        if candidate.exists() and candidate.is_file():
            return candidate

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=missing_detail)


def _resolve_download_file_or_raise(metadata: dict) -> Path:
    return _resolve_download_file_from_keys_or_raise(
        metadata,
        ("primary_latest_file_name", "primary_file_name", "latest_file_name", "file_name"),
        "Published download file is missing",
    )


def _absolute_url(request: Request, path: str) -> str:
    base_url = str(request.base_url).rstrip("/")
    suffix = path if path.startswith("/") else f"/{path}"
    return f"{base_url}{suffix}"


@app.get("/download/latest.json", include_in_schema=False)
def download_latest_metadata(request: Request) -> dict:
    metadata = _load_latest_download_metadata()
    payload = dict(metadata)
    payload["download_url"] = _absolute_url(request, "/download/latest")
    payload["zip_url"] = payload["download_url"]
    return payload


@app.get("/download/latest", include_in_schema=False)
def download_latest_payload() -> FileResponse:
    metadata = _load_latest_download_metadata()
    download_path = _resolve_download_file_or_raise(metadata)
    return FileResponse(path=download_path, filename=download_path.name, media_type="application/zip")


@app.post("/challenge", response_model=ChallengeResponse, dependencies=[Depends(require_signed_client_request), Depends(rate_limit_challenge)])
@app.post("/challenge/request", response_model=ChallengeResponse, dependencies=[Depends(require_signed_client_request), Depends(rate_limit_challenge)])
def challenge_request(payload: ChallengeRequest, request: Request, db: Session = Depends(get_db)) -> ChallengeResponse:
    license_obj = _get_license_by_plain_key(db, payload.license_key)
    if not license_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="License not found")
    reason = _license_invalid_reason(license_obj)
    if reason:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)
    enforce_per_license_rate_limit("activate", license_obj.license_key)
    challenge = issue_challenge(db, license_obj=license_obj, device_id=payload.device_id, device_fingerprint=payload.device_fingerprint, ip_address=get_client_ip(request))
    return ChallengeResponse(challenge_id=challenge.challenge_id, nonce=challenge.nonce, expires_at=challenge.expires_at)


@app.post("/challenge/verify", response_model=ChallengeVerifyResponse, dependencies=[Depends(require_signed_client_request), Depends(rate_limit_challenge)])
def challenge_verify(payload: ChallengeVerifyRequest, request: Request, db: Session = Depends(get_db)) -> ChallengeVerifyResponse:
    license_obj = _get_license_by_plain_key(db, payload.license_key)
    if not license_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="License not found")
    challenge = get_challenge_for_update(db, payload.challenge_id)
    if not challenge:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Challenge not found")
    if int(challenge.license_id) != int(license_obj.id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Challenge license mismatch")
    try:
        verify_challenge_signature(challenge=challenge, signature=payload.signature, timestamp=payload.timestamp, device_id=payload.device_id, device_fingerprint=payload.device_fingerprint)
    except ChallengeError as exc:
        log_security_event(db, event_type="challenge.verify_failure", severity="warning", detail=str(exc), ip_address=get_client_ip(request), license_id=license_obj.id)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    consume_challenge(challenge)
    db.add(challenge)
    db.commit()
    launch_token, launch_exp = build_launch_token(license_id=license_obj.id, challenge_id=challenge.challenge_id, device_id=payload.device_id, device_fingerprint=payload.device_fingerprint)
    return ChallengeVerifyResponse(verified=True, launch_token=launch_token, launch_token_expires_at=launch_exp)


@app.post("/generate", response_model=GenerateLicenseResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_admin)])
def generate_license(payload: GenerateLicenseRequest, db: Session = Depends(get_db)) -> GenerateLicenseResponse:
    if payload.expiration_date and payload.expiration_date < date.today():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="expiration_date cannot be in the past")
    for _ in range(20):
        plain_key = generate_license_key()
        hashed_key = hash_license_key(plain_key)
        exists = db.scalar(select(License.id).where(License.license_key == hashed_key))
        if exists:
            continue
        license_obj = License(license_key=hashed_key, license_key_plain=plain_key, license_key_suffix=plain_key[-4:], product=payload.product, status=LicenseStatus.active.value, max_devices=payload.max_devices, expiration_date=payload.expiration_date)
        db.add(license_obj)
        db.commit()
        db.refresh(license_obj)
        return GenerateLicenseResponse(license_key=plain_key, product=license_obj.product, status=license_obj.status, max_devices=license_obj.max_devices, expiration_date=license_obj.expiration_date, created_at=license_obj.created_at)
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Unable to generate a unique license key")


@app.post("/activate", response_model=ActivationResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(require_signed_client_request), Depends(rate_limit_activate)])
def activate_license(payload: ActivateRequest, request: Request, db: Session = Depends(get_db)) -> ActivationResponse:
    ip_address = get_client_ip(request)
    hashed = hash_license_key(payload.license_key)
    enforce_per_license_rate_limit("activate", hashed)
    license_obj = db.execute(select(License).where(License.license_key == hashed).with_for_update()).scalar_one_or_none()
    if not license_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="License not found")
    reason = _license_invalid_reason(license_obj)
    if reason:
        record_activation_failure(db, license_obj=license_obj, ip_address=ip_address, detail=reason)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)
    _validate_launch_token_or_raise(payload.launch_token, license_obj.id, payload.device_id, payload.device_fingerprint)

    existing = db.execute(select(Activation).where(Activation.license_id == license_obj.id, Activation.device_id == payload.device_id)).scalar_one_or_none()
    if existing:
        if (existing.device_fingerprint or payload.device_fingerprint) != payload.device_fingerprint:
            record_activation_failure(db, license_obj=license_obj, ip_address=ip_address, detail="device fingerprint mismatch on existing activation")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="device fingerprint mismatch")
        track_ip_change(db, license_obj=license_obj, activation=existing, new_ip=ip_address)
        _touch_heartbeat(existing)
        db.add(existing)
        db.commit()
        server_now = datetime.now(timezone.utc)
        token, token_exp = build_activation_token(
            license_id=license_obj.id,
            activation_id=existing.id,
            license_key=payload.license_key,
            device_id=existing.device_id,
            device_fingerprint=payload.device_fingerprint,
            product=license_obj.product,
            license_status=license_obj.status,
            expiration_date=license_obj.expiration_date,
        )
        return ActivationResponse(
            status="already_activated",
            activation_token=token,
            token_expires_at=token_exp,
            device_id=existing.device_id,
            server_time=server_now,
            license_status=license_obj.status,
            activations_used=_activation_count(db, license_obj.id),
            max_devices=license_obj.max_devices,
        )

    if _activation_count(db, license_obj.id) >= license_obj.max_devices:
        record_activation_failure(db, license_obj=license_obj, ip_address=ip_address, detail="device activation limit reached")
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Device activation limit reached")

    activation = Activation(license_id=license_obj.id, device_id=payload.device_id, device_name=payload.device_name, device_fingerprint=payload.device_fingerprint, ip_address=ip_address, last_heartbeat_at=datetime.now(timezone.utc))
    db.add(activation)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing_after_race = db.execute(select(Activation).where(Activation.license_id == license_obj.id, Activation.device_id == payload.device_id)).scalar_one_or_none()
        if existing_after_race is None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Activation conflict, retry")
        track_ip_change(db, license_obj=license_obj, activation=existing_after_race, new_ip=ip_address)
        _touch_heartbeat(existing_after_race)
        db.add(existing_after_race)
        db.commit()
        activation = existing_after_race
    else:
        db.refresh(activation)

    server_now = datetime.now(timezone.utc)
    token, token_exp = build_activation_token(
        license_id=license_obj.id,
        activation_id=activation.id,
        license_key=payload.license_key,
        device_id=activation.device_id,
        device_fingerprint=payload.device_fingerprint,
        product=license_obj.product,
        license_status=license_obj.status,
        expiration_date=license_obj.expiration_date,
    )
    return ActivationResponse(
        status="activated",
        activation_token=token,
        token_expires_at=token_exp,
        device_id=activation.device_id,
        server_time=server_now,
        license_status=license_obj.status,
        activations_used=_activation_count(db, license_obj.id),
        max_devices=license_obj.max_devices,
    )


@app.post("/validate", response_model=ValidateResponse, dependencies=[Depends(require_signed_client_request), Depends(rate_limit_validate)])
def validate_license(payload: ValidateRequest, request: Request, db: Session = Depends(get_db)) -> ValidateResponse:
    ip_address = get_client_ip(request)
    if payload.activation_token:
        try:
            claims = decode_activation_token(payload.activation_token)
        except TokenError as exc:
            return ValidateResponse(valid=False, reason=str(exc))
        license_obj = db.get(License, int(claims["license_id"]))
        if not license_obj:
            return ValidateResponse(valid=False, reason="license not found")
        reason = _license_invalid_reason(license_obj)
        if reason:
            return ValidateResponse(valid=False, reason=reason, license_status=license_obj.status, product=license_obj.product)
        activation = db.execute(select(Activation).where(Activation.id == int(claims["activation_id"]), Activation.license_id == license_obj.id, Activation.device_id == str(claims["device_id"]))).scalar_one_or_none()
        if not activation:
            return ValidateResponse(valid=False, reason="activation no longer exists", license_status=license_obj.status, product=license_obj.product)
        if payload.device_id != activation.device_id:
            record_heartbeat_failure(db, license_obj=license_obj, activation=activation, ip_address=ip_address, detail="validate device mismatch")
            return ValidateResponse(valid=False, reason="device mismatch", license_status=license_obj.status, product=license_obj.product, device_id=activation.device_id)
        if payload.device_fingerprint != (activation.device_fingerprint or payload.device_fingerprint):
            record_heartbeat_failure(db, license_obj=license_obj, activation=activation, ip_address=ip_address, detail="validate fingerprint mismatch")
            return ValidateResponse(valid=False, reason="device fingerprint mismatch", license_status=license_obj.status, product=license_obj.product, device_id=activation.device_id)
        track_ip_change(db, license_obj=license_obj, activation=activation, new_ip=ip_address)
        _touch_heartbeat(activation)
        db.add(activation)
        db.commit()
        server_now = datetime.now(timezone.utc)
        refreshed_token, token_exp = build_activation_token(
            license_id=license_obj.id,
            activation_id=activation.id,
            license_key=str(claims.get("license_key", payload.activation_token or "")).strip(),
            device_id=activation.device_id,
            device_fingerprint=str(activation.device_fingerprint or payload.device_fingerprint),
            product=license_obj.product,
            license_status=license_obj.status,
            expiration_date=license_obj.expiration_date,
        )
        return ValidateResponse(
            valid=True,
            license_status=license_obj.status,
            product=license_obj.product,
            token_expires_at=token_exp,
            activation_token=refreshed_token,
            device_id=activation.device_id,
            server_time=server_now,
        )

    hashed = hash_license_key(payload.license_key or "")
    enforce_per_license_rate_limit("validate", hashed)
    license_obj = _get_license_by_plain_key(db, payload.license_key or "")
    if not license_obj:
        return ValidateResponse(valid=False, reason="license not found")
    reason = _license_invalid_reason(license_obj)
    if reason:
        return ValidateResponse(valid=False, reason=reason, license_status=license_obj.status, product=license_obj.product)
    _validate_launch_token_or_raise(payload.launch_token or "", license_obj.id, payload.device_id or "", payload.device_fingerprint or "")
    activation = db.execute(select(Activation).where(Activation.license_id == license_obj.id, Activation.device_id == payload.device_id)).scalar_one_or_none()
    if not activation:
        return ValidateResponse(valid=False, reason="device is not activated for this license", license_status=license_obj.status, product=license_obj.product, device_id=payload.device_id)
    if payload.device_fingerprint != (activation.device_fingerprint or payload.device_fingerprint):
        return ValidateResponse(valid=False, reason="device fingerprint mismatch", license_status=license_obj.status, product=license_obj.product, device_id=activation.device_id)
    track_ip_change(db, license_obj=license_obj, activation=activation, new_ip=ip_address)
    _touch_heartbeat(activation)
    db.add(activation)
    db.commit()
    server_now = datetime.now(timezone.utc)
    token, token_exp = build_activation_token(
        license_id=license_obj.id,
        activation_id=activation.id,
        license_key=payload.license_key or "",
        device_id=activation.device_id,
        device_fingerprint=str(activation.device_fingerprint or payload.device_fingerprint),
        product=license_obj.product,
        license_status=license_obj.status,
        expiration_date=license_obj.expiration_date,
    )
    return ValidateResponse(
        valid=True,
        license_status=license_obj.status,
        product=license_obj.product,
        token_expires_at=token_exp,
        activation_token=token,
        device_id=activation.device_id,
        server_time=server_now,
    )


@app.post("/heartbeat", response_model=HeartbeatResponse, dependencies=[Depends(require_signed_client_request), Depends(rate_limit_heartbeat)])
def heartbeat_license(payload: HeartbeatRequest, request: Request, db: Session = Depends(get_db)) -> HeartbeatResponse:
    now = datetime.now(timezone.utc)
    ip_address = get_client_ip(request)
    try:
        claims = decode_activation_token(payload.activation_token)
    except TokenError as exc:
        return HeartbeatResponse(valid=False, reason=str(exc), device_id=payload.device_id, server_time=now, next_heartbeat_seconds=settings.heartbeat_interval_seconds)
    license_obj = db.get(License, int(claims["license_id"]))
    if not license_obj:
        return HeartbeatResponse(valid=False, reason="license not found", device_id=payload.device_id, server_time=now, next_heartbeat_seconds=settings.heartbeat_interval_seconds)
    reason = _license_invalid_reason(license_obj)
    if reason:
        return HeartbeatResponse(valid=False, reason=reason, license_status=license_obj.status, product=license_obj.product, device_id=payload.device_id, server_time=now, next_heartbeat_seconds=settings.heartbeat_interval_seconds)
    activation = db.execute(select(Activation).where(Activation.id == int(claims["activation_id"]), Activation.license_id == license_obj.id, Activation.device_id == str(claims["device_id"]))).scalar_one_or_none()
    if not activation:
        return HeartbeatResponse(valid=False, reason="activation no longer exists", license_status=license_obj.status, product=license_obj.product, device_id=payload.device_id, server_time=now, next_heartbeat_seconds=settings.heartbeat_interval_seconds)
    if payload.device_id != activation.device_id:
        record_heartbeat_failure(db, license_obj=license_obj, activation=activation, ip_address=ip_address, detail="heartbeat device mismatch")
        return HeartbeatResponse(valid=False, reason="device mismatch", license_status=license_obj.status, product=license_obj.product, device_id=activation.device_id, server_time=now, next_heartbeat_seconds=settings.heartbeat_interval_seconds)
    if payload.device_fingerprint != (activation.device_fingerprint or payload.device_fingerprint):
        record_heartbeat_failure(db, license_obj=license_obj, activation=activation, ip_address=ip_address, detail="heartbeat fingerprint mismatch")
        return HeartbeatResponse(valid=False, reason="device fingerprint mismatch", license_status=license_obj.status, product=license_obj.product, device_id=activation.device_id, server_time=now, next_heartbeat_seconds=settings.heartbeat_interval_seconds)
    track_ip_change(db, license_obj=license_obj, activation=activation, new_ip=ip_address)
    _touch_heartbeat(activation)
    db.add(activation)
    db.commit()
    refreshed_token, token_exp = build_activation_token(
        license_id=license_obj.id,
        activation_id=activation.id,
        license_key=str(claims.get("license_key", "")).strip(),
        device_id=activation.device_id,
        device_fingerprint=str(activation.device_fingerprint or payload.device_fingerprint),
        product=license_obj.product,
        license_status=license_obj.status,
        expiration_date=license_obj.expiration_date,
    )
    return HeartbeatResponse(
        valid=True,
        license_status=license_obj.status,
        product=license_obj.product,
        device_id=activation.device_id,
        server_time=now,
        next_heartbeat_seconds=settings.heartbeat_interval_seconds,
        token_expires_at=token_exp,
        activation_token=refreshed_token,
    )


@app.post("/security/event", response_model=SecurityEventResponse, dependencies=[Depends(require_signed_client_request), Depends(rate_limit_security_event)])
def security_event(payload: SecurityEventRequest, request: Request, db: Session = Depends(get_db)) -> SecurityEventResponse:
    ip_address = get_client_ip(request)
    license_obj = None
    activation = None
    if payload.activation_token:
        try:
            claims = decode_activation_token(payload.activation_token)
            license_obj = db.get(License, int(claims["license_id"]))
            if license_obj is not None:
                activation = db.get(Activation, int(claims["activation_id"]))
        except TokenError:
            pass
    if license_obj is None and payload.license_key:
        license_obj = _get_license_by_plain_key(db, payload.license_key)
    event_type = payload.event_type.strip().lower()
    if "tamper" in event_type or payload.severity == "critical":
        record_tamper_event(db, license_obj=license_obj, activation=activation, ip_address=ip_address, detail=f"{payload.event_type}: {payload.detail}")
        return SecurityEventResponse(accepted=True)
    log_security_event(db, event_type=payload.event_type, severity=payload.severity, detail=payload.detail, ip_address=ip_address, license_id=license_obj.id if license_obj else None, activation_id=activation.id if activation else None)
    db.commit()
    return SecurityEventResponse(accepted=True)


@app.post("/deactivate", response_model=DeactivateResponse)
def deactivate_license(payload: DeactivateRequest, db: Session = Depends(get_db), x_admin_token: Annotated[str | None, Header(alias=ADMIN_HEADER_NAME)] = None) -> DeactivateResponse:
    license_obj = _get_license_by_plain_key(db, payload.license_key)
    if not license_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="License not found")
    admin_ok = has_admin_access(x_admin_token)
    if not admin_ok:
        if not payload.activation_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin token or activation_token required")
        try:
            claims = decode_activation_token(payload.activation_token)
        except TokenError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        if int(claims["license_id"]) != license_obj.id or str(claims["device_id"]) != payload.device_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token does not match requested license/device")
    activation = db.execute(select(Activation).where(Activation.license_id == license_obj.id, Activation.device_id == payload.device_id)).scalar_one_or_none()
    if not activation:
        return DeactivateResponse(deactivated=False, remaining_activations=_activation_count(db, license_obj.id))
    db.delete(activation)
    db.commit()
    return DeactivateResponse(deactivated=True, remaining_activations=_activation_count(db, license_obj.id))


@app.post("/revoke", response_model=RevokeResponse, dependencies=[Depends(require_admin)])
def revoke_license(payload: RevokeRequest, db: Session = Depends(get_db)) -> RevokeResponse:
    license_obj = _get_license_by_plain_key(db, payload.license_key)
    if not license_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="License not found")
    license_obj.status = LicenseStatus.revoked.value
    license_obj.flagged_reason = "Manually revoked by admin"
    license_obj.flagged_at = datetime.now(timezone.utc)
    db.add(license_obj)
    db.commit()
    return RevokeResponse(revoked=True, status=license_obj.status)


@app.post("/revoke-by-id", response_model=RevokeResponse, dependencies=[Depends(require_admin)])
def revoke_license_by_id(payload: RevokeByIdRequest, db: Session = Depends(get_db)) -> RevokeResponse:
    license_obj = db.get(License, int(payload.license_id))
    if not license_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="License not found")
    license_obj.status = LicenseStatus.revoked.value
    license_obj.flagged_reason = "Manually revoked by admin"
    license_obj.flagged_at = datetime.now(timezone.utc)
    db.add(license_obj)
    db.commit()
    return RevokeResponse(revoked=True, status=license_obj.status)


@app.get("/licenses", response_model=LicenseListResponse, dependencies=[Depends(require_admin)])
def list_licenses(status_filter: str = Query(default="active", alias="status"), include_expired: bool = Query(default=False), db: Session = Depends(get_db)) -> LicenseListResponse:
    allowed = {"all", LicenseStatus.active.value, LicenseStatus.revoked.value, LicenseStatus.suspended.value}
    normalized_status = str(status_filter or "active").strip().lower()
    if normalized_status not in allowed:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="status must be one of: all, active, revoked, suspended")
    activation_counts = select(Activation.license_id.label("license_id"), func.count(Activation.id).label("activation_count")).group_by(Activation.license_id).subquery()
    stmt = select(License, func.coalesce(activation_counts.c.activation_count, 0).label("activation_count")).outerjoin(activation_counts, activation_counts.c.license_id == License.id)
    if normalized_status != "all":
        stmt = stmt.where(License.status == normalized_status)
    if not include_expired:
        today = date.today()
        stmt = stmt.where(or_(License.expiration_date.is_(None), License.expiration_date >= today))
    rows = db.execute(stmt.order_by(License.created_at.desc())).all()
    today = date.today()
    items = []
    for (license_obj, activation_count) in rows:
        display_key, full_key_available = _display_license_key(license_obj)
        items.append(LicenseSummaryOut(id=license_obj.id, license_key=display_key, full_key_available=full_key_available, product=license_obj.product, status=license_obj.status, max_devices=license_obj.max_devices, activation_count=int(activation_count or 0), expiration_date=license_obj.expiration_date, created_at=license_obj.created_at, is_expired=bool(license_obj.expiration_date and license_obj.expiration_date < today), flagged_reason=license_obj.flagged_reason, flagged_at=license_obj.flagged_at))
    return LicenseListResponse(total=len(items), items=items)


@app.get("/license/{key}", response_model=LicenseDetailsResponse, dependencies=[Depends(require_admin)])
def get_license(key: str, db: Session = Depends(get_db)) -> LicenseDetailsResponse:
    try:
        hashed = hash_license_key(key)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    license_obj = db.execute(select(License).where(License.license_key == hashed).options(joinedload(License.activations))).unique().scalar_one_or_none()
    if not license_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="License not found")
    activations = sorted(license_obj.activations, key=lambda row: row.activated_at, reverse=True)
    return LicenseDetailsResponse(id=license_obj.id, product=license_obj.product, status=license_obj.status, max_devices=license_obj.max_devices, expiration_date=license_obj.expiration_date, created_at=license_obj.created_at, flagged_reason=license_obj.flagged_reason, flagged_at=license_obj.flagged_at, activation_count=len(activations), activations=activations)


@app.get("/security/events", dependencies=[Depends(require_admin)])
def list_security_events(limit: int = Query(default=200, ge=1, le=2000), db: Session = Depends(get_db)) -> dict:
    rows = db.execute(select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(int(limit))).scalars().all()
    return {
        "total": len(rows),
        "items": [
            {
                "id": row.id,
                "event_type": row.event_type,
                "severity": row.severity,
                "detail": row.detail,
                "ip_address": row.ip_address,
                "license_id": row.license_id,
                "activation_id": row.activation_id,
                "created_at": row.created_at,
            }
            for row in rows
        ],
    }

