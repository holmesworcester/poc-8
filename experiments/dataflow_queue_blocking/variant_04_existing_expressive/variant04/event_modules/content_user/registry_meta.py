from __future__ import annotations

from ...catalog import DerivedViewDecl, EventTypeDecl, IndexDecl, ModuleDecl, TableDecl, columns


MODULE_ID = "content_user"
EVENT_TYPE = "content.user.created"


def declaration() -> ModuleDecl:
    return ModuleDecl(
        module_id=MODULE_ID,
        tables=(
            TableDecl(
                name="users",
                owner_module=MODULE_ID,
                storage_class="durable",
                columns=columns(
                    {
                        "workspace_id": "text",
                        "user_id": "text",
                        "display_name": "text",
                        "event_id": "text",
                        "created_at_ms": "int",
                    }
                ),
                primary_key=("workspace_id", "user_id"),
                indexes=(
                    IndexDecl("by_event", ("event_id",), unique=True),
                    IndexDecl("by_workspace_name", ("workspace_id", "display_name", "user_id")),
                ),
            ),
        ),
        event_types=(
            EventTypeDecl(
                event_type=EVENT_TYPE,
                owner_module=MODULE_ID,
                scope="durable",
                dependency_fields=(),
            ),
        ),
        derived_views=(
            DerivedViewDecl(
                name="users_by_workspace",
                owner_module=MODULE_ID,
                source_tables=("users",),
                purpose="Stable user lookup used by message and auth projections.",
            ),
        ),
    )
