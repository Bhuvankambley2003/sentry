"""Scanner service — ARP/ping sweep, publishes device.seen events."""
from __future__ import annotations

import asyncio
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from libs.common.bus import get_bus
from libs.common.config import get_settings
from libs.common.events import DEVICE_SEEN, SCAN_COMPLETED, DeviceSeenEvent, ScanCompletedEvent
from libs.common.logging import get_logger
from libs.common.schemas import NetworkInfo as NetworkInfoSchema
from services.scanner.arp import arp_sweep
from services.scanner.netinfo import get_network_info

logger = get_logger(__name__, service="scanner")
settings = get_settings()
bus = get_bus()

# Current network info (cached)
_net_info = None
_privileged = True  # set to False via --no-sudo


class ScanRequest(BaseModel):
    scan_id: str
    type: str = "quick"
    subnet: str | None = None


# ---------------------------------------------------------------------------
# Core scan logic
# ---------------------------------------------------------------------------

async def run_scan(scan_id: str, subnet: str | None = None, privileged: bool = True) -> int:
    """Execute one scan cycle. Returns count of discovered hosts."""
    global _net_info
    if _net_info is None:
        _net_info = get_network_info()

    if not _net_info:
        logger.error("Cannot scan: network info unavailable")
        return 0

    target_subnet = subnet or _net_info.subnet
    logger.info("Starting scan", extra={"scan_id": scan_id, "subnet": target_subnet})

    start = datetime.now(timezone.utc)
    try:
        hosts = await arp_sweep(target_subnet, privileged=privileged)
    except Exception as exc:
        logger.error("ARP sweep error", extra={"exc": str(exc)})
        return 0

    count = 0
    for host in hosts:
        await bus.publish(DEVICE_SEEN, DeviceSeenEvent(
            ip=host.ip,
            mac=host.mac,
            ts=datetime.now(timezone.utc),
            scan_id=uuid.UUID(scan_id) if scan_id else None,
            hostname=host.hostname,
        ))
        count += 1

    duration_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
    await bus.publish(SCAN_COMPLETED, ScanCompletedEvent(
        scan_id=uuid.UUID(scan_id),
        devices_found=count,
        duration_ms=duration_ms,
    ))
    logger.info("Scan complete", extra={"scan_id": scan_id, "devices_found": count, "duration_ms": duration_ms})
    return count


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    global _net_info
    await bus.connect()
    _net_info = get_network_info()
    if _net_info:
        logger.info("Network detected", extra={"subnet": _net_info.subnet, "iface": _net_info.interface})
    yield
    await bus.close()


app = FastAPI(title="HomeGuard Scanner Service", version="0.1.0", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "scanner", "version": "0.1.0"}


@app.post("/scan")
async def trigger_scan(req: ScanRequest) -> dict:
    """Trigger a scan asynchronously (fire-and-forget)."""
    asyncio.create_task(run_scan(req.scan_id, req.subnet, privileged=_privileged))
    return {"status": "started", "scan_id": req.scan_id}


@app.get("/network")
async def network_info() -> dict:
    info = get_network_info()
    if not info:
        return {"error": "Cannot detect network"}
    return {
        "interface": info.interface,
        "local_ip": info.local_ip,
        "subnet": info.subnet,
        "gateway_ip": info.gateway_ip,
        "ssid": info.ssid,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-sudo", action="store_true", help="Use ping sweep instead of ARP")
    args, _ = parser.parse_known_args()
    _privileged = not args.no_sudo
    uvicorn.run("services.scanner.main:app", host="127.0.0.1", port=settings.scanner_port, reload=False)
