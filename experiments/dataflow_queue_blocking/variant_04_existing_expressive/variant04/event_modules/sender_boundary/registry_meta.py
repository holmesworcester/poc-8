from __future__ import annotations

from ...catalog import DerivedViewDecl, IndexDecl, ModuleDecl, QueueBoundaryDecl, TableDecl, columns


MODULE_ID = "sender_boundary"


def declaration() -> ModuleDecl:
    outbox_refill = QueueBoundaryDecl(
        name="outbox_refill_candidates",
        table="outbox",
        owner_module=MODULE_ID,
        purpose="Per-connection send candidates consumed by the single sender owner.",
        order_by=("queued_at_ms", "event_id"),
        batch_hint=16,
    )
    return ModuleDecl(
        module_id=MODULE_ID,
        tables=(
            TableDecl(
                name="outbox",
                owner_module=MODULE_ID,
                storage_class="memory",
                columns=columns(
                    {
                        "connection_id": "text",
                        "event_id": "text",
                        "queued_at_ms": "int",
                        "reason": "text",
                    }
                ),
                primary_key=("connection_id", "event_id"),
                indexes=(
                    IndexDecl("by_connection", ("connection_id", "queued_at_ms", "event_id")),
                    IndexDecl("by_event", ("event_id", "connection_id")),
                ),
            ),
        ),
        derived_views=(
            DerivedViewDecl(
                name="outbox_refill_candidates",
                owner_module=MODULE_ID,
                source_tables=("outbox", "events", "connections"),
                purpose="Join of pending outbox rows with canonical event bytes for one connection.",
                boundary=outbox_refill,
            ),
        ),
    )
