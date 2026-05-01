from __future__ import annotations

from ...events import (
    ParsedEvent,
    canonical_event_bytes,
    dependency_list,
    ensure_fields,
    event_id_for,
    int_field,
    string_field,
)
from .registry_meta import EVENT_TYPE


FIELDS = (
    "workspace_id",
    "message_id",
    "author_user_id",
    "body",
    "author_event_id",
    "created_at_ms",
    "deps",
)


def encode(
    workspace_id: str,
    message_id: str,
    author_user_id: str,
    body: str,
    author_event_id: str,
    created_at_ms: int,
) -> bytes:
    return canonical_event_bytes(
        EVENT_TYPE,
        {
            "workspace_id": workspace_id,
            "message_id": message_id,
            "author_user_id": author_user_id,
            "body": body,
            "author_event_id": author_event_id,
            "created_at_ms": created_at_ms,
            "deps": [author_event_id],
        },
    )


def parse(event_id: str, canonical_bytes: bytes, payload: dict, origin_connection_id: str | None) -> ParsedEvent:
    ensure_fields(payload, FIELDS)
    workspace_id = string_field(payload, "workspace_id")
    string_field(payload, "message_id")
    string_field(payload, "author_user_id")
    string_field(payload, "body")
    author_event_id = string_field(payload, "author_event_id")
    int_field(payload, "created_at_ms")
    deps = dependency_list(payload)
    if deps != (author_event_id,):
        raise ValueError("message deps must contain exactly author_event_id")
    if event_id_for(canonical_bytes) != event_id:
        raise ValueError("event id does not match canonical bytes")
    return ParsedEvent(
        event_id=event_id,
        event_type=EVENT_TYPE,
        payload=payload,
        canonical_bytes=canonical_bytes,
        workspace_id=workspace_id,
        scope="durable",
        dependencies=deps,
        origin_connection_id=origin_connection_id,
    )
