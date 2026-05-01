from __future__ import annotations

from ...events import (
    ParsedEvent,
    canonical_event_bytes,
    ensure_fields,
    event_id_for,
    string_field,
)
from .registry_meta import EVENT_TYPE


FIELDS = ("connection_id", "workspace_id", "requested_event_id", "created_at_ms")


def encode(
    connection_id: str,
    workspace_id: str,
    requested_event_id: str,
    created_at_ms: int,
) -> bytes:
    return canonical_event_bytes(
        EVENT_TYPE,
        {
            "connection_id": connection_id,
            "workspace_id": workspace_id,
            "requested_event_id": requested_event_id,
            "created_at_ms": created_at_ms,
        },
    )


def parse(event_id: str, canonical_bytes: bytes, payload: dict, origin_connection_id: str | None) -> ParsedEvent:
    ensure_fields(payload, FIELDS)
    connection_id = string_field(payload, "connection_id")
    workspace_id = string_field(payload, "workspace_id")
    string_field(payload, "requested_event_id")
    if not isinstance(payload["created_at_ms"], int):
        raise ValueError("created_at_ms must be an integer")
    if origin_connection_id is not None and origin_connection_id != connection_id:
        raise ValueError("need event must arrive on its declared connection")
    if event_id_for(canonical_bytes) != event_id:
        raise ValueError("event id does not match canonical bytes")
    return ParsedEvent(
        event_id=event_id,
        event_type=EVENT_TYPE,
        payload=payload,
        canonical_bytes=canonical_bytes,
        workspace_id=workspace_id,
        scope="endpoint_local",
        dependencies=(),
        origin_connection_id=origin_connection_id,
    )
