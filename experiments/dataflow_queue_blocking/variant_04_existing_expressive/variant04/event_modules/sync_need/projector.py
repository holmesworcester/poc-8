from __future__ import annotations

from ...events import ProjectionContext, ProjectionResult
from ...state import StateStore


def project(context: ProjectionContext, store: StateStore) -> ProjectionResult:
    payload = context.event.payload
    connection = store.get("connections", (payload["connection_id"],))
    if connection is None or connection["status"] != "open":
        raise ValueError("need event references a non-open connection")

    requested = store.get("events", (payload["requested_event_id"],))
    if requested is None or requested["status"] != "applied":
        raise ValueError("need event references an unavailable event")

    shared_workspaces = tuple(connection["shared_workspaces"])
    if requested["workspace_id"] not in shared_workspaces:
        raise ValueError("requested event is outside the connection shared workspace set")
    if payload["workspace_id"] != requested["workspace_id"]:
        raise ValueError("need workspace does not match requested event workspace")

    return ProjectionResult(
        new_rows={
            "outbox": (
                {
                    "connection_id": payload["connection_id"],
                    "event_id": payload["requested_event_id"],
                    "queued_at_ms": payload["created_at_ms"],
                    "reason": "sync.need_event",
                },
            )
        },
        trace={
            "projector": "sync_need",
            "connection_id": payload["connection_id"],
            "requested_event_id": payload["requested_event_id"],
        },
    )
