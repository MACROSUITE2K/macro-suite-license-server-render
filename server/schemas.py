from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .auth.token_manager import normalize_license_key

LicenseKeyField = Annotated[str, Field(pattern=r"^[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$")]
FingerprintField = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
HexSignatureField = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class GenerateLicenseRequest(BaseModel):
    product: str = Field(min_length=1, max_length=100)
    max_devices: int = Field(ge=1, le=500)
    expiration_date: date | None = None


class GenerateLicenseResponse(BaseModel):
    license_key: str
    product: str
    status: str
    max_devices: int
    expiration_date: date | None
    created_at: datetime


class ChallengeRequest(BaseModel):
    license_key: LicenseKeyField
    device_id: str = Field(min_length=6, max_length=128)
    device_name: str = Field(default="Unknown Device", min_length=1, max_length=128)
    device_fingerprint: FingerprintField

    @field_validator("license_key", mode="before")
    @classmethod
    def normalize_key(cls, value: str) -> str:
        return normalize_license_key(value)

    @field_validator("device_fingerprint", mode="before")
    @classmethod
    def normalize_fingerprint(cls, value: str) -> str:
        return str(value or "").strip().lower()


class ChallengeResponse(BaseModel):
    challenge_id: str
    nonce: str
    expires_at: datetime


class ChallengeVerifyRequest(BaseModel):
    challenge_id: str = Field(min_length=12, max_length=128)
    license_key: LicenseKeyField
    device_id: str = Field(min_length=6, max_length=128)
    device_fingerprint: FingerprintField
    timestamp: int = Field(ge=1)
    signature: HexSignatureField

    @field_validator("license_key", mode="before")
    @classmethod
    def normalize_key(cls, value: str) -> str:
        return normalize_license_key(value)

    @field_validator("device_fingerprint", mode="before")
    @classmethod
    def normalize_fingerprint(cls, value: str) -> str:
        return str(value or "").strip().lower()


class ChallengeVerifyResponse(BaseModel):
    verified: bool
    launch_token: str
    launch_token_expires_at: datetime


class ActivateRequest(BaseModel):
    license_key: LicenseKeyField
    device_id: str = Field(min_length=6, max_length=128)
    device_name: str = Field(default="Unknown Device", min_length=1, max_length=128)
    device_fingerprint: FingerprintField
    launch_token: str = Field(min_length=20)

    @field_validator("license_key", mode="before")
    @classmethod
    def normalize_key(cls, value: str) -> str:
        return normalize_license_key(value)

    @field_validator("device_fingerprint", mode="before")
    @classmethod
    def normalize_fingerprint(cls, value: str) -> str:
        return str(value or "").strip().lower()


class ActivationResponse(BaseModel):
    status: str
    activation_token: str
    token_expires_at: datetime
    device_id: str
    server_time: datetime
    license_status: str
    activations_used: int
    max_devices: int


class ValidateRequest(BaseModel):
    activation_token: str | None = Field(default=None, min_length=20)
    launch_token: str | None = Field(default=None, min_length=20)
    license_key: LicenseKeyField | None = None
    device_id: str | None = Field(default=None, min_length=6, max_length=128)
    device_fingerprint: FingerprintField | None = None

    @field_validator("license_key", mode="before")
    @classmethod
    def normalize_key(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return normalize_license_key(value)

    @field_validator("device_fingerprint", mode="before")
    @classmethod
    def normalize_fingerprint(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return str(value).strip().lower()

    @model_validator(mode="after")
    def require_valid_combo(self) -> "ValidateRequest":
        if self.activation_token:
            if not self.device_id or not self.device_fingerprint:
                raise ValueError("device_id and device_fingerprint are required with activation_token")
            return self

        if self.license_key and self.device_id and self.device_fingerprint and self.launch_token:
            return self

        raise ValueError(
            "Provide activation_token + device fields OR launch_token + license_key + device fields"
        )


class ValidateResponse(BaseModel):
    valid: bool
    reason: str | None = None
    license_status: str | None = None
    product: str | None = None
    token_expires_at: datetime | None = None
    activation_token: str | None = None
    device_id: str | None = None
    server_time: datetime | None = None


class HeartbeatRequest(BaseModel):
    activation_token: str = Field(min_length=20)
    device_id: str = Field(min_length=6, max_length=128)
    device_fingerprint: FingerprintField
    app_version: str | None = Field(default=None, max_length=50)
    uptime_seconds: int | None = Field(default=None, ge=0, le=60 * 60 * 24 * 90)

    @field_validator("device_fingerprint", mode="before")
    @classmethod
    def normalize_fingerprint(cls, value: str) -> str:
        return str(value or "").strip().lower()


class HeartbeatResponse(BaseModel):
    valid: bool
    reason: str | None = None
    license_status: str | None = None
    product: str | None = None
    device_id: str | None = None
    server_time: datetime
    next_heartbeat_seconds: int
    token_expires_at: datetime | None = None
    activation_token: str | None = None


class SecurityEventRequest(BaseModel):
    event_type: str = Field(min_length=3, max_length=64)
    severity: Literal["info", "warning", "critical"] = "warning"
    detail: str = Field(min_length=3, max_length=2000)
    activation_token: str | None = Field(default=None, min_length=20)
    license_key: LicenseKeyField | None = None
    device_id: str | None = Field(default=None, min_length=6, max_length=128)
    device_fingerprint: FingerprintField | None = None

    @field_validator("license_key", mode="before")
    @classmethod
    def normalize_key(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return normalize_license_key(value)

    @field_validator("device_fingerprint", mode="before")
    @classmethod
    def normalize_fingerprint(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return str(value).strip().lower()


class SecurityEventResponse(BaseModel):
    accepted: bool


class DeactivateRequest(BaseModel):
    license_key: LicenseKeyField
    device_id: str = Field(min_length=6, max_length=128)
    activation_token: str | None = Field(default=None, min_length=20)

    @field_validator("license_key", mode="before")
    @classmethod
    def normalize_key(cls, value: str) -> str:
        return normalize_license_key(value)


class DeactivateResponse(BaseModel):
    deactivated: bool
    remaining_activations: int


class RevokeRequest(BaseModel):
    license_key: LicenseKeyField

    @field_validator("license_key", mode="before")
    @classmethod
    def normalize_key(cls, value: str) -> str:
        return normalize_license_key(value)


class RevokeResponse(BaseModel):
    revoked: bool
    status: str


class RevokeByIdRequest(BaseModel):
    license_id: int = Field(ge=1)


class ActivationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_id: str
    device_name: str
    device_fingerprint: str | None
    ip_address: str | None
    activated_at: datetime
    last_heartbeat_at: datetime | None = None
    heartbeat_failures: int = 0
    ip_change_count: int = 0


class LicenseDetailsResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    product: str
    status: str
    max_devices: int
    expiration_date: date | None
    created_at: datetime
    flagged_reason: str | None = None
    flagged_at: datetime | None = None
    activation_count: int
    activations: list[ActivationOut]


class LicenseSummaryOut(BaseModel):
    id: int
    license_key: str
    full_key_available: bool
    product: str
    status: str
    max_devices: int
    activation_count: int
    expiration_date: date | None
    created_at: datetime
    is_expired: bool
    flagged_reason: str | None = None
    flagged_at: datetime | None = None


class LicenseListResponse(BaseModel):
    total: int
    items: list[LicenseSummaryOut]
