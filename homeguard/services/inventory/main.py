"""Inventory service — the only service that owns the SQLite database."""
from __future__ import annotations

import json
import sys
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from libs.common.bus import get_bus
from libs.common.config import get_settings
from libs.common.events import (
    DEVICE_NEW,
    DEVICE_SEEN,
    DEVICE_ENRICHED,
    DEVICE_IDENTIFIED,
    SCAN_COMPLETED,
    ALERT_CREATED,
    DeviceNewEvent,
    AlertCreatedEvent,
)
from libs.common.logging import get_logger
from libs.common.schemas import (
    AlertResponse,
    AlertSeverity,
    AlertType,
    ChangeSummary,
    DevicePatch,
    DeviceResponse,
    DeviceStatus,
    DeviceType,
    ScanResponse,
    ScanType,
    ServiceRecord,
    Sighting as SightingSchema,
    TrustReason,
)
from services.inventory import models, repo
from services.inventory.models import Base

logger = get_logger(__name__, service="inventory")
settings = get_settings()

# expand ~ in db url if configured that way
_db_url = settings.database_url
if _db_url.startswith("sqlite+aiosqlite:///~"):
    _db_url = _db_url.replace("~", str(Path.home()), 1)
elif "~" in _db_url:
    _db_url = os.path.expanduser(_db_url)

# make sure parent dir exists before sqlite engine tries to open file
_db_path_str = _db_url.replace("sqlite+aiosqlite:///", "")
Path(_db_path_str).parent.mkdir(parents=True, exist_ok=True)

engine = create_async_engine(_db_url, echo=False, future=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


bus = get_bus()


# Background subscriber handler for redis events
async def handle_event(topic: str, data: dict[str, Any]) -> None:
    async with AsyncSessionLocal() as session:
        try:
            if topic == DEVICE_SEEN:
                mac = data.get("mac", "")
                ip = data.get("ip")
                hostname = data.get("hostname")
                scan_id = data.get("scan_id")
                if not mac:
                    return

                device, is_new = await repo.upsert_device(
                    session, mac=mac, ip=ip, hostname=hostname, scan_id=scan_id
                )
                if is_new:
                    await bus.publish(DEVICE_NEW, DeviceNewEvent(
                        device_id=device.id,
                        first_seen=device.first_seen,
                    ))
                    alert = await repo.create_alert(
                        session,
                        alert_type="new_device",
                        message=f"New device {mac} ({ip or 'unknown IP'}) joined the network",
                        severity="info",
                        device_id=device.id,
                    )
                    await bus.publish(ALERT_CREATED, AlertCreatedEvent(
                        alert_id=alert.id,
                        severity=alert.severity,
                        message=alert.message,
                        device_id=device.id,
                    ))
                await session.commit()

            elif topic == DEVICE_ENRICHED:
                mac = data.get("mac", "")
                if not mac:
                    return

                device = await repo.get_device_by_mac(session, mac)
                if device:
                    await repo.patch_device(
                        session,
                        device_id=device.id,
                        hostname=data.get("hostname"),
                    )
                    await session.commit()

            elif topic == DEVICE_IDENTIFIED:
                device_id = data.get("device_id", "")
                if not device_id:
                    return

                await repo.patch_device(
                    session,
                    device_id=device_id,
                    vendor=data.get("vendor"),
                    device_type=data.get("type"),
                    fingerprint=data.get("fingerprint"),
                    is_randomized_mac=data.get("is_randomized_mac", False),
                )
                await session.commit()

            elif topic == SCAN_COMPLETED:
                scan_id = str(data.get("scan_id", ""))
                devices_found = int(data.get("devices_found", 0))
                if scan_id:
                    await repo.complete_scan(session, scan_id=scan_id, devices_found=devices_found)
                    await session.commit()

        except Exception as exc:
            await session.rollback()
            logger.error("Event handling failed", extra={"topic": topic, "exc": str(exc)})


def _device_to_schema(d: models.Device) -> DeviceResponse:
    reasons: list[TrustReason] = []
    if d.trust_reasons:
        try:
            raw = json.loads(d.trust_reasons)
            reasons = [TrustReason(**r) for r in raw]
        except Exception:
            pass

    now = datetime.now(timezone.utc)
    # Consider "online" if last seen within 10 minutes
    online = (now - d.last_seen.replace(tzinfo=timezone.utc if d.last_seen.tzinfo is None else d.last_seen.tzinfo)).total_seconds() < 600

    return DeviceResponse(
        id=d.id,
        fingerprint=d.fingerprint,
        current_mac=d.current_mac,
        current_ip=d.current_ip,
        vendor=d.vendor,
        device_type=DeviceType(d.device_type) if d.device_type else DeviceType.unknown,
        hostname=d.hostname,
        user_label=d.user_label,
        is_randomized_mac=d.is_randomized_mac,
        status=DeviceStatus(d.status) if d.status else DeviceStatus.unknown,
        trust_score=d.trust_score,
        trust_reasons=reasons,
        first_seen=d.first_seen,
        last_seen=d.last_seen,
        online=online,
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # bootstrap sqlite tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created/verified")

    # Connect event bus and start redis subscriber loop
    await bus.connect()

    import asyncio
    topics = [DEVICE_SEEN, DEVICE_ENRICHED, DEVICE_IDENTIFIED, SCAN_COMPLETED]
    subscriber_task = asyncio.create_task(bus.subscribe(topics, handle_event))

    yield

    subscriber_task.cancel()
    await bus.close()
    await engine.dispose()


app = FastAPI(title="HomeGuard Inventory Service", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "inventory", "version": "0.1.0"}


# --- device routes ---

@app.get("/devices", response_model=list[DeviceResponse])
async def list_devices(
    status: str | None = None,
    device_type: str | None = None,
    online: bool | None = None,
    new_since: datetime | None = None,
    session: AsyncSession = Depends(get_session),
) -> list[DeviceResponse]:
    from datetime import timedelta
    online_since = None
    if online is True:
        online_since = datetime.now(timezone.utc) - timedelta(minutes=10)
    devices = await repo.list_devices(
        session,
        status=status,
        device_type=device_type,
        online_since=online_since,
        new_since=new_since,
    )
    return [_device_to_schema(d) for d in devices]


@app.get("/devices/{device_id}", response_model=DeviceResponse)
async def get_device(device_id: str, session: AsyncSession = Depends(get_session)) -> DeviceResponse:
    device = await repo.get_device(session, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return _device_to_schema(device)


@app.patch("/devices/{device_id}", response_model=DeviceResponse)
async def patch_device(
    device_id: str,
    patch: DevicePatch,
    session: AsyncSession = Depends(get_session),
) -> DeviceResponse:
    device = await repo.patch_device(
        session,
        device_id=device_id,
        user_label=patch.user_label,
        status=patch.status.value if patch.status else None,
    )
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return _device_to_schema(device)


@app.get("/devices/{device_id}/history", response_model=list[SightingSchema])
async def device_history(device_id: str, session: AsyncSession = Depends(get_session)) -> list[SightingSchema]:
    sightings = await repo.list_sightings(session, device_id)
    return [
        SightingSchema(
            id=s.id,
            device_id=s.device_id,
            ip=s.ip,
            mac=s.mac,
            scan_id=s.scan_id,
            seen_at=s.seen_at,
        )
        for s in sightings
    ]


@app.get("/devices/{device_id}/trust")
async def device_trust(device_id: str, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    device = await repo.get_device(session, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    reasons = []
    if device.trust_reasons:
        try:
            reasons = json.loads(device.trust_reasons)
        except Exception:
            pass
    return {"device_id": device_id, "score": device.trust_score, "reasons": reasons}


# --- scan records ---

@app.post("/scans", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_type: str = "quick",
    session: AsyncSession = Depends(get_session),
) -> ScanResponse:
    scan = await repo.create_scan(session, scan_type=scan_type)
    return ScanResponse(
        id=scan.id,
        type=ScanType(scan.type),
        started_at=scan.started_at,
        status=scan.status,
    )


@app.patch("/scans/{scan_id}/complete")
async def complete_scan(
    scan_id: str,
    devices_found: int = 0,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    scan = await repo.complete_scan(session, scan_id=scan_id, devices_found=devices_found)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"id": scan.id, "status": scan.status, "devices_found": scan.devices_found}


@app.get("/scans", response_model=list[ScanResponse])
async def list_scans(session: AsyncSession = Depends(get_session)) -> list[ScanResponse]:
    scans = await repo.list_scans(session)
    return [
        ScanResponse(
            id=s.id,
            type=ScanType(s.type),
            started_at=s.started_at,
            finished_at=s.finished_at,
            devices_found=s.devices_found,
            status=s.status,
        )
        for s in scans
    ]


@app.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_session)) -> ScanResponse:
    scan = await repo.get_scan(session, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse(
        id=scan.id,
        type=ScanType(scan.type),
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        devices_found=scan.devices_found,
        status=scan.status,
    )


# --- alert endpoints ---

@app.get("/alerts", response_model=list[AlertResponse])
async def list_alerts(
    unacknowledged: bool = False,
    session: AsyncSession = Depends(get_session),
) -> list[AlertResponse]:
    alerts = await repo.list_alerts(session, unacknowledged_only=unacknowledged)
    return [
        AlertResponse(
            id=a.id,
            device_id=a.device_id,
            type=AlertType(a.type),
            severity=AlertSeverity(a.severity),
            message=a.message,
            created_at=a.created_at,
            acknowledged=a.acknowledged,
        )
        for a in alerts
    ]


@app.post("/alerts/{alert_id}/ack")
async def ack_alert(alert_id: str, session: AsyncSession = Depends(get_session)) -> dict[str, str]:
    alert = await repo.acknowledge_alert(session, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "acknowledged"}


# --- change diffs ---

@app.get("/changes", response_model=ChangeSummary)
async def changes(
    since: datetime = Query(..., description="ISO8601 datetime"),
    session: AsyncSession = Depends(get_session),
) -> ChangeSummary:
    result = await repo.devices_changed_since(session, since)
    return ChangeSummary(
        since=since,
        new_devices=[_device_to_schema(d) for d in result["new"]],
        gone_devices=[_device_to_schema(d) for d in result["gone"]],
        changed_devices=[_device_to_schema(d) for d in result["changed"]],
    )


# --- kv settings ---

@app.get("/settings/{key}")
async def get_setting(key: str, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    value = await repo.get_setting(session, key)
    return {"key": key, "value": value}


@app.put("/settings/{key}")
async def put_setting(key: str, body: dict[str, Any], session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    await repo.set_setting(session, key, body.get("value"))
    return {"key": key, "status": "updated"}


if __name__ == "__main__":
    uvicorn.run("services.inventory.main:app", host="127.0.0.1", port=settings.inventory_port, reload=False)
