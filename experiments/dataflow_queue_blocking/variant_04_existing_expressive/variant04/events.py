"""Canonical event helpers and projector result types."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Any, Mapping


def canonical_event_bytes(event_type: str, payload: Mapping[str, Any]) -> bytes:
    envelope = {"event_type": event_type, "payload": payload}
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")


def decode_envelope(canonical_bytes: bytes) -> tuple[str, dict[str, Any]]:
    envelope = json.loads(canonical_bytes.decode("utf-8"))
    if not isinstance(envelope, dict):
        raise ValueError("event envelope must be an object")
    event_type = envelope.get("event_type")
    payload = envelope.get("payload")
    if not isinstance(event_type, str):
        raise ValueError("event_type must be a string")
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    return event_type, payload


def event_id_for(canonical_bytes: bytes) -> str:
    return "evt_" + hashlib.sha256(canonical_bytes).hexdigest()[:24]


def wire_id_for(raw_bytes: bytes) -> str:
    return "wire_" + hashlib.sha256(raw_bytes).hexdigest()[:24]


@dataclass(frozen=True)
class ParsedEvent:
    event_id: str
    event_type: str
    payload: Mapping[str, Any]
    canonical_bytes: bytes
    workspace_id: str | None
    scope: str
    dependencies: tuple[str, ...] = ()
    origin_connection_id: str | None = None


@dataclass(frozen=True)
class ProjectionContext:
    event: ParsedEvent
    dependency_rows: Mapping[str, Mapping[str, Any]]


@dataclass(frozen=True)
class ProjectionResult:
    new_rows: Mapping[str, tuple[Mapping[str, Any], ...]] = field(default_factory=dict)
    purges: Mapping[str, tuple[Mapping[str, Any], ...]] = field(default_factory=dict)
    trace: Mapping[str, Any] = field(default_factory=dict)


def ensure_fields(payload: Mapping[str, Any], fields: tuple[str, ...]) -> None:
    missing = [field_name for field_name in fields if field_name not in payload]
    if missing:
        raise ValueError(f"missing fields: {', '.join(missing)}")


def string_field(payload: Mapping[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def int_field(payload: Mapping[str, Any], field_name: str) -> int:
    value = payload.get(field_name)
    if not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    return value


def dependency_list(payload: Mapping[str, Any]) -> tuple[str, ...]:
    raw = payload.get("deps", ())
    if not isinstance(raw, list):
        raise ValueError("deps must be a list")
    for item in raw:
        if not isinstance(item, str) or not item:
            raise ValueError("deps entries must be non-empty strings")
    return tuple(raw)
