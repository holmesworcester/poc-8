from __future__ import annotations

from ...events import ProjectionContext, ProjectionResult


def project(context: ProjectionContext) -> ProjectionResult:
    payload = context.event.payload
    return ProjectionResult(
        new_rows={
            "users": (
                {
                    "workspace_id": payload["workspace_id"],
                    "user_id": payload["user_id"],
                    "display_name": payload["display_name"],
                    "event_id": context.event.event_id,
                    "created_at_ms": payload["created_at_ms"],
                },
            )
        },
        trace={"projector": "content_user", "user_id": payload["user_id"]},
    )
