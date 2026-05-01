from __future__ import annotations

from ...catalog import DerivedViewDecl, EventTypeDecl, ModuleDecl


MODULE_ID = "sync_need"
EVENT_TYPE = "sync.need_event"


def declaration() -> ModuleDecl:
    return ModuleDecl(
        module_id=MODULE_ID,
        event_types=(
            EventTypeDecl(
                event_type=EVENT_TYPE,
                owner_module=MODULE_ID,
                scope="endpoint_local",
                dependency_fields=(),
            ),
        ),
        derived_views=(
            DerivedViewDecl(
                name="sendable_events_for_need",
                owner_module=MODULE_ID,
                source_tables=("events", "connections", "outbox"),
                purpose=(
                    "Projection-time check that a requested event is applied and belongs to "
                    "a workspace shared on the requesting connection."
                ),
            ),
        ),
    )
