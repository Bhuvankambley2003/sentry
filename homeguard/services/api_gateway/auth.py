"""API Gateway auth — static token checked on every request."""
from __future__ import annotations

import secrets
import string
from pathlib import Path

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from libs.common.config import get_settings
from libs.common.logging import get_logger

logger = get_logger(__name__, service="api_gateway")

_TOKEN_HEADER = APIKeyHeader(name="X-HomeGuard-Token", auto_error=False)


def _generate_token(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _token_path() -> Path:
    path = get_settings().token_file.expanduser()
    return path


def get_or_create_token() -> str:
    path = _token_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        token = path.read_text().strip()
        if token:
            return token
    token = _generate_token()
    path.write_text(token)
    path.chmod(0o600)
    logger.info("Generated new API token", extra={"token_file": str(path)})
    return token


_token: str | None = None


def get_current_token() -> str:
    global _token
    if _token is None:
        _token = get_or_create_token()
    return _token


async def require_token(api_key: str | None = Security(_TOKEN_HEADER)) -> str:
    valid = get_current_token()
    if not api_key or api_key != valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-HomeGuard-Token header",
        )
    return api_key
