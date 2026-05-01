from __future__ import annotations

from ...events import ProjectionContext, ProjectionResult


def project(context: ProjectionContext) -> ProjectionResult:
    payload = context.event.payload
    author_event = context.dependency_rows[payload["author_event_id"]]
    return ProjectionResult(
        new_rows={
            "messages": (
                {
                    "workspace_id": payload["workspace_id"],
                    "message_id": payload["message_id"],
                    "author_user_id": payload["author_user_id"],
                    "body": payload["body"],
                    "event_id": context.event.event_id,
                    "author_event_id": author_event["event_id"],
                    "created_at_ms": payload["created_at_ms"],
                },
            )
        },
        trace={
            "projector": "content_message",
            "message_id": payload["message_id"],
            "author_event_id": author_event["event_id"],
        },
    )
