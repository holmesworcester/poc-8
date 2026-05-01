from __future__ import annotations

from ...events import (
    ParsedEvent,
    canonical_event_bytes,
    ensure_fields,
    event_id_for,
    string_field,
)
from .registry_meta import EVENT_TYPE


FIELDS = ("workspace_id", "user_id", "display_name", "created_at_ms")


def encode(workspace_id: str, user_id: str, display_name: str, created_at_ms: int) -> bytes:
    return canonical_event_bytes(
        EVENT_TYPE,
        {
            "workspace_id": workspace_id,
            "user_id": user_id,
            "display_name": display_name,
            "created_at_ms": created_at_ms,
        },
    )


def parse(event_id: str, canonical_bytes: bytes, payload: dict, origin_connection_id: str | None) -> ParsedEvent:
    ensure_fields(payload, FIELDS)
    workspace_id = string_field(payload, "workspace_id")
    string_field(payload, "user_id")
    string_field(payload, "display_name")
    if not isinstance(payload["created_at_ms"], int):
        raise ValueError("created_at_ms must be an integer")
    expected_id = event_id_for(canonical_bytes)
    if expected_id != event_id:
        raise ValueError("event id does not match canonical bytes")
    return ParsedEvent(
        event_id=event_id,
        event_type=EVENT_TYPE,
        payload=payload,
        canonical_bytes=canonical_bytes,
        workspace_id=workspace_id,
        scope="durable",
        dependencies=(),
        origin_connection_id=origin_connection_id,
    )
