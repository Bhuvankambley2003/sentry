"""Notifier service stub — macOS notifications + WebSocket alerts (Phase 3)."""
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

logger = get_logger(__name__, service="notifier")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    logger.info("Notifier service starting (Phase 3 — stub)")
    yield


app = FastAPI(title="HomeGuard Notifier Service", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "notifier", "version": "0.1.0", "detail": "stub — Phase 3"}


if __name__ == "__main__":
    uvicorn.run("services.notifier.main:app", host="127.0.0.1", port=settings.notifier_port, reload=False)
