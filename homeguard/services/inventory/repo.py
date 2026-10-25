"""Database repository layer for inventory-service."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from services.inventory.models import Alert, Device, Scan, Service, Setting, Sighting
from libs.common.logging import get_logger
from libs.common.schemas import DeviceStatus

logger = get_logger(__name__, service="inventory")


# Device operations
async def upsert_device(
    session: AsyncSession,
    mac: str,
    ip: str | None = None,
    hostname: str | None = None,
    scan_id: str | None = None,
) -> tuple[Device, bool]:
    """Find or create a device by MAC. Returns (device, is_new) and appends sighting."""
    result = await session.execute(select(Device).where(Device.current_mac == mac))
    device = result.scalar_one_or_none()
    is_new = device is None
    now = datetime.now(timezone.utc)

    if is_new:
        device = Device(
            id=str(uuid.uuid4()),
            current_mac=mac,
            current_ip=ip,
            hostname=hostname,
            first_seen=now,
            last_seen=now,
        )
        session.add(device)
        logger.info("New device created", extra={"mac": mac})
    else:
        device.last_seen = now
        if ip:
            device.current_ip = ip
        if hostname and not device.hostname:
            device.hostname = hostname

    # Log sighting audit entry
    sighting = Sighting(
        id=str(uuid.uuid4()),
        device_id=device.id,
        ip=ip or "",
        mac=mac,
        scan_id=scan_id,
        seen_at=now,
    )
    session.add(sighting)
    await session.flush()
    return device, is_new


async def get_device(session: AsyncSession, device_id: str) -> Device | None:
    result = await session.execute(select(Device).where(Device.id == device_id))
    return result.scalar_one_or_none()


async def get_device_by_mac(session: AsyncSession, mac: str) -> Device | None:
    result = await session.execute(select(Device).where(Device.current_mac == mac))
    return result.scalar_one_or_none()


async def list_devices(
    session: AsyncSession,
    status: str | None = None,
    device_type: str | None = None,
    online_since: datetime | None = None,
    new_since: datetime | None = None,
) -> list[Device]:
    stmt = select(Device)
    filters = []
    if status:
        filters.append(Device.status == status)
    if device_type:
        filters.append(Device.device_type == device_type)
    if online_since:
        filters.append(Device.last_seen >= online_since)
    if new_since:
        filters.append(Device.first_seen >= new_since)
    if filters:
        stmt = stmt.where(and_(*filters))

    stmt = stmt.order_by(Device.last_seen.desc())
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def patch_device(
    session: AsyncSession,
    device_id: str,
    user_label: str | None = None,
    status: str | None = None,
    vendor: str | None = None,
    device_type: str | None = None,
    hostname: str | None = None,
    is_randomized_mac: bool | None = None,
    fingerprint: str | None = None,
    trust_score: int | None = None,
    trust_reasons: list[dict[str, Any]] | None = None,
) -> Device | None:
    device = await get_device(session, device_id)
    if device is None:
        return None

    if user_label is not None:
        device.user_label = user_label
    if status is not None:
        device.status = status
    if vendor is not None:
        device.vendor = vendor
    if device_type is not None:
        device.device_type = device_type
    if hostname is not None:
        device.hostname = hostname
    if is_randomized_mac is not None:
        device.is_randomized_mac = is_randomized_mac
    if fingerprint is not None:
        device.fingerprint = fingerprint
    if trust_score is not None:
        device.trust_score = trust_score
    if trust_reasons is not None:
        device.trust_reasons = json.dumps(trust_reasons)

    await session.flush()
    return device


# Sightings history
async def list_sightings(session: AsyncSession, device_id: str, limit: int = 50) -> list[Sighting]:
    result = await session.execute(
        select(Sighting)
        .where(Sighting.device_id == device_id)
        .order_by(Sighting.seen_at.desc())
        .limit(limit)
    )
    return list(result.scalars().all())


# Scan records
async def create_scan(session: AsyncSession, scan_type: str = "quick") -> Scan:
    scan = Scan(id=str(uuid.uuid4()), type=scan_type, status="running")
    session.add(scan)
    await session.flush()
    return scan


async def complete_scan(session: AsyncSession, scan_id: str, devices_found: int) -> Scan | None:
    result = await session.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan:
        scan.finished_at = datetime.now(timezone.utc)
        scan.devices_found = devices_found
        scan.status = "completed"
        await session.flush()
    return scan


async def get_scan(session: AsyncSession, scan_id: str) -> Scan | None:
    result = await session.execute(select(Scan).where(Scan.id == scan_id))
    return result.scalar_one_or_none()


async def list_scans(session: AsyncSession, limit: int = 20) -> list[Scan]:
    result = await session.execute(
        select(Scan).order_by(Scan.started_at.desc()).limit(limit)
    )
    return list(result.scalars().all())


# Alerts
async def create_alert(
    session: AsyncSession,
    alert_type: str,
    message: str,
    severity: str = "info",
    device_id: str | None = None,
) -> Alert:
    alert = Alert(
        id=str(uuid.uuid4()),
        device_id=device_id,
        type=alert_type,
        severity=severity,
        message=message,
    )
    session.add(alert)
    await session.flush()
    return alert


async def list_alerts(
    session: AsyncSession,
    unacknowledged_only: bool = False,
    limit: int = 100,
) -> list[Alert]:
    stmt = select(Alert)
    if unacknowledged_only:
        stmt = stmt.where(Alert.acknowledged.is_(False))
    stmt = stmt.order_by(Alert.created_at.desc()).limit(limit)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def acknowledge_alert(session: AsyncSession, alert_id: str) -> Alert | None:
    result = await session.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if alert:
        alert.acknowledged = True
        await session.flush()
    return alert


# Key-value settings
async def get_setting(session: AsyncSession, key: str, default: Any = None) -> Any:
    result = await session.execute(select(Setting).where(Setting.key == key))
    row = result.scalar_one_or_none()
    if row is None:
        return default
    return json.loads(row.value)


async def set_setting(session: AsyncSession, key: str, value: Any) -> None:
    result = await session.execute(select(Setting).where(Setting.key == key))
    row = result.scalar_one_or_none()
    if row is None:
        row = Setting(key=key, value=json.dumps(value, default=str))
        session.add(row)
    else:
        row.value = json.dumps(value, default=str)
    await session.flush()


# Changes and diffs
def _ensure_utc(dt: datetime) -> datetime:
    """Make datetime timezone-aware if sqlite returned naive UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def devices_changed_since(
    session: AsyncSession,
    since: datetime,
) -> dict[str, list[Device]]:
    since = _ensure_utc(since)
    all_devices = await list_devices(session)
    new_devices = [d for d in all_devices if _ensure_utc(d.first_seen) >= since]
    gone_devices = [d for d in all_devices if _ensure_utc(d.last_seen) < since]
    changed_devices = [
        d for d in all_devices
        if _ensure_utc(d.first_seen) < since
        and _ensure_utc(d.last_seen) >= since
        and d not in gone_devices
    ]
    return {"new": new_devices, "gone": gone_devices, "changed": changed_devices}
