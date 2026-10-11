"""Tests for inventory-service repository layer."""
from __future__ import annotations

import pytest
import pytest_asyncio
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from services.inventory.models import Base
from services.inventory import repo


@pytest_asyncio.fixture
async def session():
    """In-memory SQLite session for tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
    async with SessionLocal() as s:
        yield s
        await s.rollback()
    await engine.dispose()


@pytest.mark.asyncio
async def test_upsert_new_device(session):
    device, is_new = await repo.upsert_device(session, mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.100")
    await session.commit()
    assert is_new is True
    assert device.current_mac == "AA:BB:CC:DD:EE:FF"
    assert device.current_ip == "192.168.1.100"


@pytest.mark.asyncio
async def test_upsert_existing_device(session):
    # First insert
    device1, is_new1 = await repo.upsert_device(session, mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.100")
    await session.commit()

    # Second insert — same MAC
    device2, is_new2 = await repo.upsert_device(session, mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.101")
    await session.commit()

    assert is_new1 is True
    assert is_new2 is False
    assert device1.id == device2.id
    assert device2.current_ip == "192.168.1.101"


@pytest.mark.asyncio
async def test_patch_device_label(session):
    device, _ = await repo.upsert_device(session, mac="BB:CC:DD:EE:FF:AA")
    await session.commit()

    patched = await repo.patch_device(session, device_id=device.id, user_label="Dad's Phone")
    await session.commit()
    assert patched is not None
    assert patched.user_label == "Dad's Phone"


@pytest.mark.asyncio
async def test_create_and_list_alerts(session):
    alert = await repo.create_alert(
        session,
        alert_type="new_device",
        message="Test alert",
        severity="info",
    )
    await session.commit()

    alerts = await repo.list_alerts(session)
    assert len(alerts) >= 1
    assert any(a.id == alert.id for a in alerts)


@pytest.mark.asyncio
async def test_acknowledge_alert(session):
    alert = await repo.create_alert(session, alert_type="new_device", message="Test")
    await session.commit()

    acked = await repo.acknowledge_alert(session, alert_id=alert.id)
    await session.commit()
    assert acked is not None
    assert acked.acknowledged is True


@pytest.mark.asyncio
async def test_create_and_complete_scan(session):
    scan = await repo.create_scan(session, scan_type="quick")
    await session.commit()
    assert scan.status == "running"

    completed = await repo.complete_scan(session, scan_id=scan.id, devices_found=5)
    await session.commit()
    assert completed is not None
    assert completed.status == "completed"
    assert completed.devices_found == 5


@pytest.mark.asyncio
async def test_settings(session):
    await repo.set_setting(session, "last_session_end", "2026-10-23T00:00:00+05:30")
    await session.commit()

    value = await repo.get_setting(session, "last_session_end")
    assert value == "2026-10-23T00:00:00+05:30"


@pytest.mark.asyncio
async def test_changes_since(session):
    past = datetime.now(timezone.utc) - timedelta(hours=2)
    # Old device
    old_device, _ = await repo.upsert_device(session, mac="CC:DD:EE:FF:AA:BB", ip="192.168.1.10")
    old_device.first_seen = past
    old_device.last_seen = past
    # New device
    await repo.upsert_device(session, mac="DD:EE:FF:AA:BB:CC", ip="192.168.1.20")
    await session.commit()

    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    result = await repo.devices_changed_since(session, since=cutoff)
    new_macs = [d.current_mac for d in result["new"]]
    assert "DD:EE:FF:AA:BB:CC" in new_macs
