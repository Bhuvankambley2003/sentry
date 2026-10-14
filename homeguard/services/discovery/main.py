"""Discovery service stub — mDNS/SSDP/NetBIOS enrichment (Phase 2)."""
from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import uvicorn
from fastapi import FastAPI

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from libs.common.config import get_settings
from libs.common.logging import get_logger

logger = get_logger(__name__, service="discovery")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("Discovery service starting (Phase 2 — stub)")
    yield
    logger.info("Discovery service stopped")


app = FastAPI(title="HomeGuard Discovery Service", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "discovery", "version": "0.1.0", "detail": "stub — Phase 2"}


if __name__ == "__main__":
    uvicorn.run("services.discovery.main:app", host="127.0.0.1", port=settings.discovery_port, reload=False)
