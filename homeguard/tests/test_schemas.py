"""Tests for libs/common."""
from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, patch
from libs.common.schemas import DeviceResponse, DeviceType, DeviceStatus, TrustReason
from libs.common.events import DeviceSeenEvent, DEVICE_SEEN
from datetime import datetime, timezone
import uuid


def test_device_response_serialization() -> None:
    now = datetime.now(timezone.utc)
    d = DeviceResponse(
        id=uuid.uuid4(),
        current_mac="AA:BB:CC:DD:EE:FF",
        device_type=DeviceType.iot,
        status=DeviceStatus.unknown,
        trust_score=38,
        trust_reasons=[
            TrustReason(rule="unknown_label", delta=-15, text="Not confirmed"),
            TrustReason(rule="recently_joined", delta=-10, text="First seen recently"),
        ],
        first_seen=now,
        last_seen=now,
    )
    dumped = d.model_dump()
    assert dumped["device_type"] == "iot"
    assert dumped["trust_score"] == 38
    assert len(dumped["trust_reasons"]) == 2


def test_device_seen_event() -> None:
    event = DeviceSeenEvent(
        ip="192.168.1.42",
        mac="AC:67:B2:3F:2A:10",
        ts=datetime.now(timezone.utc),
        scan_id=uuid.uuid4(),
    )
    assert event.ip == "192.168.1.42"
    assert event.mac == "AC:67:B2:3F:2A:10"


def test_trust_score_clamp() -> None:
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        TrustReason(rule="test", delta=0, text="test")
        DeviceResponse(
            id=uuid.uuid4(),
            current_mac="AA:BB:CC:DD:EE:FF",
            trust_score=101,  # invalid (> 100)
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
