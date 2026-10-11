"""SQLAlchemy 2.0 ORM models for inventory-service."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _now() -> datetime:
    from datetime import timezone
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    current_mac: Mapped[str] = mapped_column(String(17), nullable=False, index=True)
    current_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    device_type: Mapped[str] = mapped_column(String(32), default="unknown")
    hostname: Mapped[str | None] = mapped_column(String(253), nullable=True)
    user_label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_randomized_mac: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(32), default="unknown")
    trust_score: Mapped[int] = mapped_column(Integer, default=50)
    trust_reasons: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, onupdate=_now)

    sightings: Mapped[list[Sighting]] = relationship("Sighting", back_populates="device", lazy="select")
    services: Mapped[list[Service]] = relationship("Service", back_populates="device", lazy="select")
    alerts: Mapped[list[Alert]] = relationship("Alert", back_populates="device", lazy="select")


class Sighting(Base):
    __tablename__ = "sightings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id"), nullable=False, index=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    mac: Mapped[str] = mapped_column(String(17), nullable=False)
    scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    device: Mapped[Device] = relationship("Device", back_populates="sightings")


class Service(Base):
    __tablename__ = "services"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str] = mapped_column(String(36), ForeignKey("devices.id"), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # mdns | ssdp | port
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    device: Mapped[Device] = relationship("Device", back_populates="services")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    device_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("devices.id"), nullable=True, index=True)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)

    device: Mapped[Device | None] = relationship("Device", back_populates="alerts")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    type: Mapped[str] = mapped_column(String(16), default="quick")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    devices_found: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="running")


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)  # JSON value
