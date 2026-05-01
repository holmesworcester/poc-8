from __future__ import annotations

from ...catalog import DerivedViewDecl, IndexDecl, ModuleDecl, TableDecl, columns


MODULE_ID = "connection"


def declaration() -> ModuleDecl:
    return ModuleDecl(
        module_id=MODULE_ID,
        tables=(
            TableDecl(
                name="connections",
                owner_module=MODULE_ID,
                storage_class="durable",
                columns=columns(
                    {
                        "connection_id": "text",
                        "remote_endpoint_id": "text",
                        "shared_workspaces": "tuple[text]",
                        "status": "text",
                        "updated_at_ms": "int",
                    }
                ),
                primary_key=("connection_id",),
                indexes=(
                    IndexDecl("by_status", ("status", "connection_id")),
                    IndexDecl("by_remote", ("remote_endpoint_id", "connection_id")),
                ),
            ),
        ),
        derived_views=(
            DerivedViewDecl(
                name="open_connections",
                owner_module=MODULE_ID,
                source_tables=("connections",),
                purpose="Active endpoint-pair connections available for wrapping outbox events.",
            ),
        ),
    )
