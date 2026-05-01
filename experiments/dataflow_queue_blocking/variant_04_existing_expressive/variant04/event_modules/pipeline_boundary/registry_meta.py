from __future__ import annotations

from ...catalog import (
    DerivedViewDecl,
    IndexDecl,
    ModuleDecl,
    QueueBoundaryDecl,
    TableDecl,
    columns,
)


MODULE_ID = "pipeline_boundary"


def declaration() -> ModuleDecl:
    inbound_boundary = QueueBoundaryDecl(
        name="pending_inbound_bytes",
        table="inbound_bytes",
        owner_module=MODULE_ID,
        purpose="Transport ingress rows claimable by the control loop.",
        claim_statuses=("pending",),
        order_by=("created_at_ms", "wire_id"),
        batch_hint=4,
    )
    ready_events_boundary = QueueBoundaryDecl(
        name="ready_events",
        table="events",
        owner_module=MODULE_ID,
        purpose="Canonical events whose dependencies are satisfied and can be projected.",
        claim_statuses=("ready",),
        order_by=("created_at_ms", "event_id"),
        batch_hint=4,
    )

    return ModuleDecl(
        module_id=MODULE_ID,
        tables=(
            TableDecl(
                name="inbound_bytes",
                owner_module=MODULE_ID,
                storage_class="memory",
                columns=columns(
                    {
                        "wire_id": "text",
                        "raw_bytes": "bytes",
                        "origin_connection_id": "text",
                        "status": "text",
                        "attempts": "int",
                        "last_error": "text",
                        "created_at_ms": "int",
                        "updated_at_ms": "int",
                    },
                    nullable=("origin_connection_id", "last_error"),
                ),
                primary_key=("wire_id",),
                indexes=(
                    IndexDecl("by_status_created", ("status", "created_at_ms", "wire_id")),
                    IndexDecl("by_origin", ("origin_connection_id", "created_at_ms")),
                ),
            ),
            TableDecl(
                name="inbound_observations",
                owner_module=MODULE_ID,
                storage_class="memory",
                columns=columns(
                    {
                        "wire_id": "text",
                        "origin_connection_id": "text",
                        "seen_count": "int",
                        "first_seen_at_ms": "int",
                        "last_seen_at_ms": "int",
                    },
                    nullable=("origin_connection_id",),
                ),
                primary_key=("wire_id", "origin_connection_id"),
                indexes=(IndexDecl("by_wire", ("wire_id",)),),
            ),
            TableDecl(
                name="events",
                owner_module=MODULE_ID,
                storage_class="durable",
                columns=columns(
                    {
                        "event_id": "text",
                        "event_type": "text",
                        "workspace_id": "text",
                        "scope": "text",
                        "canonical_bytes": "bytes",
                        "deps": "tuple[text]",
                        "status": "text",
                        "created_at_ms": "int",
                        "updated_at_ms": "int",
                        "applied_at_ms": "int",
                        "last_error": "text",
                    },
                    nullable=("workspace_id", "applied_at_ms", "last_error"),
                ),
                primary_key=("event_id",),
                indexes=(
                    IndexDecl("by_status_created", ("status", "created_at_ms", "event_id")),
                    IndexDecl("by_workspace_status", ("workspace_id", "status", "event_id")),
                    IndexDecl("by_type_status", ("event_type", "status", "event_id")),
                ),
            ),
            TableDecl(
                name="blocked_by_event",
                owner_module=MODULE_ID,
                storage_class="durable",
                columns=columns(
                    {
                        "blocked_by_event_id": "text",
                        "event_id": "text",
                        "created_at_ms": "int",
                    }
                ),
                primary_key=("blocked_by_event_id", "event_id"),
                indexes=(
                    IndexDecl("by_blocked_event", ("event_id", "blocked_by_event_id")),
                    IndexDecl("by_blocker", ("blocked_by_event_id", "event_id")),
                ),
            ),
        ),
        derived_views=(
            DerivedViewDecl(
                name="pending_inbound_bytes",
                owner_module=MODULE_ID,
                source_tables=("inbound_bytes",),
                purpose="Rows with status=pending, ordered for bounded ingress work.",
                boundary=inbound_boundary,
            ),
            DerivedViewDecl(
                name="ready_events",
                owner_module=MODULE_ID,
                source_tables=("events", "blocked_by_event"),
                purpose="Events with status=ready; unblocked rows are exposed here but not drained recursively.",
                boundary=ready_events_boundary,
            ),
        ),
    )
