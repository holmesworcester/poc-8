from __future__ import annotations

from ...catalog import DerivedViewDecl, EventTypeDecl, IndexDecl, ModuleDecl, TableDecl, columns


MODULE_ID = "content_message"
EVENT_TYPE = "content.message.posted"


def declaration() -> ModuleDecl:
    return ModuleDecl(
        module_id=MODULE_ID,
        tables=(
            TableDecl(
                name="messages",
                owner_module=MODULE_ID,
                storage_class="durable",
                columns=columns(
                    {
                        "workspace_id": "text",
                        "message_id": "text",
                        "author_user_id": "text",
                        "body": "text",
                        "event_id": "text",
                        "author_event_id": "text",
                        "created_at_ms": "int",
                    }
                ),
                primary_key=("workspace_id", "message_id"),
                indexes=(
                    IndexDecl("by_event", ("event_id",), unique=True),
                    IndexDecl("by_author", ("workspace_id", "author_user_id", "created_at_ms")),
                    IndexDecl("by_created", ("workspace_id", "created_at_ms", "message_id")),
                ),
            ),
        ),
        event_types=(
            EventTypeDecl(
                event_type=EVENT_TYPE,
                owner_module=MODULE_ID,
                scope="durable",
                dependency_fields=("deps",),
            ),
        ),
        derived_views=(
            DerivedViewDecl(
                name="messages_by_author",
                owner_module=MODULE_ID,
                source_tables=("messages", "users"),
                purpose="Materialized message lookup keyed by workspace and author.",
            ),
        ),
    )
