import enum
from datetime import date, datetime

from sqlalchemy import Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class LicenseStatus(str, enum.Enum):
    active = "active"
    revoked = "revoked"
    suspended = "suspended"


class License(Base):
    __tablename__ = "licenses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Stores a keyed hash (HMAC) of the user-facing license key.
    license_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)

    # Stores full license key for admin visibility (new licenses only).
    license_key_plain: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Stores the visible last 4 chars for fallback display.
    license_key_suffix: Mapped[str | None] = mapped_column(String(4), nullable=True)

    product: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=LicenseStatus.active.value)
    max_devices: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    expiration_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    # Abuse/anomaly flagging metadata.
    flagged_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    flagged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    activations: Mapped[list["Activation"]] = relationship(
        "Activation",
        back_populates="license",
        cascade="all, delete-orphan",
    )


class Activation(Base):
    __tablename__ = "activations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    license_id: Mapped[int] = mapped_column(Integer, ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False)
    device_id: Mapped[str] = mapped_column(String(128), nullable=False)
    device_name: Mapped[str] = mapped_column(String(128), nullable=False)
    device_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    heartbeat_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ip_change_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    license: Mapped[License] = relationship("License", back_populates="activations")

    __table_args__ = (
        UniqueConstraint("license_id", "device_id", name="uq_activation_license_device"),
    )


class ChallengeSession(Base):
    __tablename__ = "challenge_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    challenge_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    license_id: Mapped[int] = mapped_column(Integer, ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False)
    device_id: Mapped[str] = mapped_column(String(128), nullable=False)
    device_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    license_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("licenses.id", ondelete="SET NULL"), nullable=True)
    activation_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("activations.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
