"""API Gateway — public entry point, routes to internal services."""
from __future__ import annotations

import asyncio
import json
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

import httpx
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from libs.common.bus import get_bus
from libs.common.config import get_settings
from libs.common.events import (
    ALERT_CREATED,
    DEVICE_NEW,
    DEVICE_TRUST_CHANGED,
    SCAN_COMPLETED,
)
from libs.common.logging import get_logger
from libs.common.schemas import (
    AlertResponse,
    ChangeSummary,
    DevicePatch,
    DeviceResponse,
    NetworkInfo,
    ScanCreate,
    ScanResponse,
    ScanType,
)
from services.api_gateway.auth import get_current_token, require_token

logger = get_logger(__name__, service="api_gateway")
settings = get_settings()
bus = get_bus()

# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------

class ConnectionManager:
    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.discard(ws) if hasattr(self._connections, "discard") else None
        if ws in self._connections:
            self._connections.remove(ws)

    async def broadcast(self, data: dict[str, Any]) -> None:
        dead = []
        for ws in list(self._connections):
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


async def _event_fan_out(topic: str, data: dict[str, Any]) -> None:
    """Forward Redis events to WebSocket clients."""
    await manager.broadcast({"topic": topic, "data": data})


# ---------------------------------------------------------------------------
# Internal service client
# ---------------------------------------------------------------------------

_http_client: httpx.AsyncClient | None = None


def get_client() -> httpx.AsyncClient:
    assert _http_client is not None
    return _http_client


async def _call(method: str, svc: str, path: str, **kwargs: Any) -> Any:
    base = settings.service_url(svc)
    try:
        resp = await get_client().request(method, f"{base}{path}", **kwargs)
        resp.raise_for_status()
        return resp.json()
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail=f"Service '{svc}' is unavailable")
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=exc.response.status_code, detail=exc.response.text)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    global _http_client
    _http_client = httpx.AsyncClient(timeout=10.0)

    # Ensure token exists
    token = get_current_token()
    logger.info("API Gateway started", extra={"token_file": str(settings.token_file.expanduser())})

    # Connect event bus and subscribe for WebSocket fan-out
    await bus.connect()
    topics = [SCAN_COMPLETED, DEVICE_NEW, DEVICE_TRUST_CHANGED, ALERT_CREATED]
    _sub_task = asyncio.create_task(bus.subscribe(topics, _event_fan_out))

    yield

    _sub_task.cancel()
    await bus.close()
    await _http_client.aclose()


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="HomeGuard API Gateway",
    version="0.1.0",
    description="Single public entry point for HomeGuard. Auth: X-HomeGuard-Token header.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:*", "http://127.0.0.1:*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API = "/api/v1"

# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

SERVICES = ["scanner", "discovery", "identity", "trust", "notifier", "inventory"]


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "api_gateway", "version": "0.1.0"}


@app.get(f"{API}/health")
async def aggregated_health(_: str = Depends(require_token)) -> dict[str, Any]:
    results = []
    overall = "ok"
    for svc in SERVICES:
        try:
            base = settings.service_url(svc)
            resp = await get_client().get(f"{base}/health", timeout=2.0)
            data = resp.json()
            results.append({"service": svc, "status": data.get("status", "ok"), "version": data.get("version", "?")})
        except Exception:
            results.append({"service": svc, "status": "down"})
            overall = "degraded"
    return {"overall": overall, "services": results}


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

@app.post(f"{API}/scans", status_code=202)
async def start_scan(body: ScanCreate, _: str = Depends(require_token)) -> dict[str, Any]:
    # Create scan record in inventory
    scan_data = await _call("POST", "inventory", "/scans", params={"scan_type": body.type.value})
    scan_id = scan_data["id"]
    # Trigger scanner
    try:
        await _call("POST", "scanner", "/scan", json={"scan_id": scan_id, "type": body.type.value})
    except Exception:
        logger.warning("Scanner unavailable, scan created but not triggered", extra={"scan_id": scan_id})
    return scan_data


@app.get(f"{API}/scans/{'{scan_id}'}")
async def get_scan(scan_id: str, _: str = Depends(require_token)) -> dict[str, Any]:
    return await _call("GET", "inventory", f"/scans/{scan_id}")


@app.get(f"{API}/scans")
async def list_scans(_: str = Depends(require_token)) -> list[dict[str, Any]]:
    return await _call("GET", "inventory", "/scans")


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------

@app.get(f"{API}/devices")
async def list_devices(
    status: str | None = None,
    type: str | None = None,
    online: bool | None = None,
    new_since: datetime | None = None,
    _: str = Depends(require_token),
) -> list[dict[str, Any]]:
    params: dict[str, Any] = {}
    if status:
        params["status"] = status
    if type:
        params["device_type"] = type
    if online is not None:
        params["online"] = online
    if new_since:
        params["new_since"] = new_since.isoformat()
    return await _call("GET", "inventory", "/devices", params=params)


@app.get(f"{API}/devices/{'{device_id}'}")
async def get_device(device_id: str, _: str = Depends(require_token)) -> dict[str, Any]:
    return await _call("GET", "inventory", f"/devices/{device_id}")


@app.patch(f"{API}/devices/{'{device_id}'}")
async def patch_device(device_id: str, patch: DevicePatch, _: str = Depends(require_token)) -> dict[str, Any]:
    return await _call("PATCH", "inventory", f"/devices/{device_id}", json=patch.model_dump(exclude_none=True))


@app.get(f"{API}/devices/{'{device_id}'}/history")
async def device_history(device_id: str, _: str = Depends(require_token)) -> list[dict[str, Any]]:
    return await _call("GET", "inventory", f"/devices/{device_id}/history")


@app.get(f"{API}/devices/{'{device_id}'}/trust")
async def device_trust(device_id: str, _: str = Depends(require_token)) -> dict[str, Any]:
    return await _call("GET", "inventory", f"/devices/{device_id}/trust")


# ---------------------------------------------------------------------------
# Changes
# ---------------------------------------------------------------------------

@app.get(f"{API}/changes")
async def changes(
    since: datetime = Query(..., description="ISO8601 datetime"),
    _: str = Depends(require_token),
) -> dict[str, Any]:
    return await _call("GET", "inventory", "/changes", params={"since": since.isoformat()})


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@app.get(f"{API}/alerts")
async def list_alerts(unacknowledged: bool = False, _: str = Depends(require_token)) -> list[dict[str, Any]]:
    return await _call("GET", "inventory", "/alerts", params={"unacknowledged": unacknowledged})


@app.post(f"{API}/alerts/{'{alert_id}'}/ack")
async def ack_alert(alert_id: str, _: str = Depends(require_token)) -> dict[str, Any]:
    return await _call("POST", "inventory", f"/alerts/{alert_id}/ack")


# ---------------------------------------------------------------------------
# Network info
# ---------------------------------------------------------------------------

@app.get(f"{API}/network")
async def network(_: str = Depends(require_token)) -> dict[str, Any]:
    return await _call("GET", "scanner", "/network")


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@app.get(f"{API}/settings/{'{key}'}")
async def get_setting(key: str, _: str = Depends(require_token)) -> dict[str, Any]:
    return await _call("GET", "inventory", f"/settings/{key}")


@app.put(f"{API}/settings/{'{key}'}")
async def put_setting(key: str, body: dict[str, Any], _: str = Depends(require_token)) -> dict[str, Any]:
    return await _call("PUT", "inventory", f"/settings/{key}", json=body)


# ---------------------------------------------------------------------------
# WebSocket stream
# ---------------------------------------------------------------------------

@app.websocket(f"{API}/stream")
async def stream(websocket: WebSocket) -> None:
    # Basic token check via query param for WebSocket
    token = websocket.query_params.get("token")
    if not token or token != get_current_token():
        await websocket.close(code=4001)
        return
    await manager.connect(websocket)
    try:
        while True:
            # keep connection alive, wait for client ping
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run("services.api_gateway.main:app", host=settings.api_host, port=settings.api_port, reload=False)
