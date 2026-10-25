"""Redis event topic names and event payload schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel

# Redis pub/sub topic names
SCAN_REQUESTED = "scan.requested"
SCAN_COMPLETED = "scan.completed"
DEVICE_SEEN = "device.seen"
DEVICE_ENRICHED = "device.enriched"
DEVICE_IDENTIFIED = "device.identified"
DEVICE_NEW = "device.new"
DEVICE_TRUST_CHANGED = "device.trust_changed"
ALERT_CREATED = "alert.created"


# Event data payloads published across topics
class ScanRequestedEvent(BaseModel):
    scan_id: UUID
    type: str = "quick"


class ScanCompletedEvent(BaseModel):
    scan_id: UUID
    devices_found: int
    duration_ms: int


class DeviceSeenEvent(BaseModel):
    ip: str
    mac: str
    ts: datetime
    scan_id: UUID | None = None
    hostname: str | None = None


class DeviceEnrichedEvent(BaseModel):
    mac: str
    hostname: str | None = None
    mdns_services: list[str] = []
    ssdp: dict[str, Any] = {}
    netbios: str | None = None


class DeviceIdentifiedEvent(BaseModel):
    device_id: UUID
    vendor: str | None = None
    type: str = "unknown"
    fingerprint: str | None = None
    is_randomized_mac: bool = False


class DeviceNewEvent(BaseModel):
    device_id: UUID
    first_seen: datetime


class DeviceTrustChangedEvent(BaseModel):
    device_id: UUID
    old_score: int
    new_score: int
    reasons: list[dict[str, Any]] = []


class AlertCreatedEvent(BaseModel):
    alert_id: UUID
    severity: str
    message: str
    device_id: UUID | None = None
