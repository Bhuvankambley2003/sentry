"""Shared Pydantic schemas (DTOs) used across all services."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


# Device classification & types
class DeviceType(str, Enum):
    phone = "phone"
    laptop = "laptop"
    tv = "tv"
    camera = "camera"
    printer = "printer"
    router = "router"
    iot = "iot"
    nas = "nas"
    unknown = "unknown"


class DeviceStatus(str, Enum):
    unknown = "unknown"
    trusted = "trusted"
    blocked_flag = "blocked_flag"
    ignored = "ignored"


class AlertSeverity(str, Enum):
    info = "info"
    warn = "warn"
    high = "high"


class AlertType(str, Enum):
    new_device = "new_device"
    risky_port = "risky_port"
    identity_change = "identity_change"
    gateway_mac_changed = "gateway_mac_changed"
    possible_known_device = "possible_known_device"


class ScanType(str, Enum):
    quick = "quick"
    full = "full"


# Trust scoring structures
class TrustReason(BaseModel):
    rule: str
    delta: int
    text: str


class TrustResult(BaseModel):
    device_id: UUID
    score: int = Field(ge=0, le=100)
    reasons: list[TrustReason]
    band: str  # "trusted" | "probably_fine" | "needs_attention" | "suspicious"


# Device entities and sighting logs
class ServiceRecord(BaseModel):
    id: UUID | None = None
    device_id: UUID | None = None
    kind: str  # mdns | ssdp | port
    name: str
    port: int | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    last_seen: datetime | None = None


class Sighting(BaseModel):
    id: UUID | None = None
    device_id: UUID | None = None
    ip: str
    mac: str
    scan_id: UUID | None = None
    seen_at: datetime


class DeviceResponse(BaseModel):
    id: UUID
    fingerprint: str | None = None
    current_mac: str
    current_ip: str | None = None
    vendor: str | None = None
    device_type: DeviceType = DeviceType.unknown
    hostname: str | None = None
    user_label: str | None = None
    is_randomized_mac: bool = False
    status: DeviceStatus = DeviceStatus.unknown
    trust_score: int = Field(50, ge=0, le=100)
    trust_reasons: list[TrustReason] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    online: bool = False
    services: list[ServiceRecord] = Field(default_factory=list)


class DevicePatch(BaseModel):
    user_label: str | None = None
    status: DeviceStatus | None = None


# Network scan models
class ScanCreate(BaseModel):
    type: ScanType = ScanType.quick


class ScanResponse(BaseModel):
    id: UUID
    type: ScanType
    started_at: datetime
    finished_at: datetime | None = None
    devices_found: int = 0
    status: str = "running"  # running | completed | failed


# System & security alerts
class AlertResponse(BaseModel):
    id: UUID
    device_id: UUID | None = None
    type: AlertType
    severity: AlertSeverity
    message: str
    created_at: datetime
    acknowledged: bool = False


# Local network environment
class NetworkInfo(BaseModel):
    subnet: str | None = None
    gateway_ip: str | None = None
    gateway_mac: str | None = None
    local_ip: str | None = None
    interface: str | None = None
    ssid: str | None = None
    warning: str | None = None


# Microservice health checks
class ServiceHealth(BaseModel):
    service: str
    status: str  # ok | degraded | down
    version: str = "0.1.0"
    detail: str | None = None


class AggregatedHealth(BaseModel):
    overall: str
    services: list[ServiceHealth]


# Session change diffs
class ChangeSummary(BaseModel):
    since: datetime
    new_devices: list[DeviceResponse] = Field(default_factory=list)
    gone_devices: list[DeviceResponse] = Field(default_factory=list)
    changed_devices: list[DeviceResponse] = Field(default_factory=list)
