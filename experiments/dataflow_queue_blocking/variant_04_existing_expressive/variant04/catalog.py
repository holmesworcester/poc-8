"""Catalog declarations materialized from event-module metadata.

The point of this demo is that state mechanics can stay generic while event
modules declare richer schema meaning: owned tables, indexes, derived views, and
queue boundaries. The in-memory store below uses these declarations for
validation and for named access paths; a database-backed implementation would
turn the same objects into DDL and migrations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping


@dataclass(frozen=True)
class ColumnDecl:
    name: str
    kind: str
    nullable: bool = False


@dataclass(frozen=True)
class IndexDecl:
    name: str
    columns: tuple[str, ...]
    unique: bool = False


@dataclass(frozen=True)
class QueueBoundaryDecl:
    name: str
    table: str
    owner_module: str
    purpose: str
    claim_statuses: tuple[str, ...] = ()
    order_by: tuple[str, ...] = ()
    batch_hint: int = 1


@dataclass(frozen=True)
class DerivedViewDecl:
    name: str
    owner_module: str
    source_tables: tuple[str, ...]
    purpose: str
    boundary: QueueBoundaryDecl | None = None


@dataclass(frozen=True)
class TableDecl:
    name: str
    owner_module: str
    storage_class: str
    columns: tuple[ColumnDecl, ...]
    primary_key: tuple[str, ...]
    indexes: tuple[IndexDecl, ...] = ()

    def required_columns(self) -> set[str]:
        return {column.name for column in self.columns if not column.nullable}

    def column_names(self) -> set[str]:
        return {column.name for column in self.columns}


@dataclass(frozen=True)
class EventTypeDecl:
    event_type: str
    owner_module: str
    scope: str
    dependency_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class ModuleDecl:
    module_id: str
    tables: tuple[TableDecl, ...] = ()
    event_types: tuple[EventTypeDecl, ...] = ()
    derived_views: tuple[DerivedViewDecl, ...] = ()


@dataclass(frozen=True)
class Catalog:
    modules: Mapping[str, ModuleDecl]
    tables: Mapping[str, TableDecl]
    event_types: Mapping[str, EventTypeDecl]
    derived_views: Mapping[str, DerivedViewDecl]
    boundaries: Mapping[str, QueueBoundaryDecl]

    @classmethod
    def from_modules(cls, module_decls: Iterable[ModuleDecl]) -> "Catalog":
        modules: dict[str, ModuleDecl] = {}
        tables: dict[str, TableDecl] = {}
        event_types: dict[str, EventTypeDecl] = {}
        derived_views: dict[str, DerivedViewDecl] = {}
        boundaries: dict[str, QueueBoundaryDecl] = {}

        for module in module_decls:
            if module.module_id in modules:
                raise ValueError(f"duplicate module {module.module_id}")
            modules[module.module_id] = module

            for table in module.tables:
                if table.name in tables:
                    raise ValueError(f"duplicate table {table.name}")
                missing_pk = set(table.primary_key) - table.column_names()
                if missing_pk:
                    raise ValueError(
                        f"table {table.name} primary key columns not declared: {sorted(missing_pk)}"
                    )
                for index in table.indexes:
                    missing_index = set(index.columns) - table.column_names()
                    if missing_index:
                        raise ValueError(
                            f"table {table.name} index {index.name} columns not declared: "
                            f"{sorted(missing_index)}"
                        )
                tables[table.name] = table

            for event_type in module.event_types:
                if event_type.event_type in event_types:
                    raise ValueError(f"duplicate event type {event_type.event_type}")
                event_types[event_type.event_type] = event_type

            for view in module.derived_views:
                if view.name in derived_views:
                    raise ValueError(f"duplicate derived view {view.name}")
                derived_views[view.name] = view
                if view.boundary is not None:
                    if view.boundary.name in boundaries:
                        raise ValueError(f"duplicate boundary {view.boundary.name}")
                    boundaries[view.boundary.name] = view.boundary

        for view in derived_views.values():
            missing_sources = set(view.source_tables) - set(tables)
            if missing_sources:
                raise ValueError(
                    f"view {view.name} references missing tables: {sorted(missing_sources)}"
                )

        for boundary in boundaries.values():
            if boundary.table not in tables:
                raise ValueError(
                    f"boundary {boundary.name} references missing table {boundary.table}"
                )

        return cls(
            modules=modules,
            tables=tables,
            event_types=event_types,
            derived_views=derived_views,
            boundaries=boundaries,
        )

    def owned_tables(self, module_id: str) -> tuple[TableDecl, ...]:
        return tuple(table for table in self.tables.values() if table.owner_module == module_id)


def columns(spec: Mapping[str, str], nullable: Iterable[str] = ()) -> tuple[ColumnDecl, ...]:
    nullable_set = set(nullable)
    return tuple(
        ColumnDecl(name=name, kind=kind, nullable=name in nullable_set)
        for name, kind in spec.items()
    )
