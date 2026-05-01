"""In-memory state store driven by the event-module catalog."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Iterator, Mapping

from .catalog import Catalog, IndexDecl, TableDecl
from .trace import Trace


Row = dict[str, Any]


@dataclass
class Table:
    decl: TableDecl
    rows: dict[tuple[Any, ...], Row]

    def primary_key_for(self, row: Mapping[str, Any]) -> tuple[Any, ...]:
        return tuple(row[column] for column in self.decl.primary_key)


class StateStore:
    def __init__(self, catalog: Catalog, trace: Trace | None = None) -> None:
        self.catalog = catalog
        self.trace = trace or Trace()
        self.tables: dict[str, Table] = {
            name: Table(decl=decl, rows={}) for name, decl in catalog.tables.items()
        }
        self._next_tx = 1

    @contextmanager
    def transaction(self, name: str, **detail: Any) -> Iterator[int]:
        tx = self._next_tx
        self._next_tx += 1
        self.trace.record("tx.begin", tx=tx, name=name, **detail)
        try:
            yield tx
        except Exception as exc:
            self.trace.record("tx.abort", tx=tx, error=str(exc))
            raise
        else:
            self.trace.record("tx.commit", tx=tx, name=name)

    def insert_ignore(self, table_name: str, row: Mapping[str, Any], tx: int | None = None) -> bool:
        table = self.tables[table_name]
        self._validate_row(table.decl, row)
        key = table.primary_key_for(row)
        if key in table.rows:
            self.trace.record("row.ignored", tx=tx, table=table_name, key=key)
            return False
        table.rows[key] = dict(row)
        self.trace.record("row.inserted", tx=tx, table=table_name, key=key)
        return True

    def upsert(self, table_name: str, row: Mapping[str, Any], tx: int | None = None) -> None:
        table = self.tables[table_name]
        self._validate_row(table.decl, row)
        key = table.primary_key_for(row)
        existed = key in table.rows
        table.rows[key] = dict(row)
        self.trace.record("row.upserted", tx=tx, table=table_name, key=key, existed=existed)

    def update_pk(
        self, table_name: str, key_values: tuple[Any, ...], updates: Mapping[str, Any], tx: int | None = None
    ) -> None:
        table = self.tables[table_name]
        if key_values not in table.rows:
            raise KeyError(f"{table_name} row missing: {key_values}")
        table.rows[key_values].update(updates)
        self.trace.record("row.updated", tx=tx, table=table_name, key=key_values, updates=dict(updates))

    def delete_pk(self, table_name: str, key_values: tuple[Any, ...], tx: int | None = None) -> bool:
        table = self.tables[table_name]
        existed = table.rows.pop(key_values, None) is not None
        if existed:
            self.trace.record("row.deleted", tx=tx, table=table_name, key=key_values)
        return existed

    def delete_where(
        self, table_name: str, predicate: Callable[[Row], bool], tx: int | None = None
    ) -> list[Row]:
        table = self.tables[table_name]
        deleted: list[Row] = []
        for key, row in list(table.rows.items()):
            if predicate(row):
                deleted.append(row)
                del table.rows[key]
                self.trace.record("row.deleted", tx=tx, table=table_name, key=key)
        return deleted

    def get(self, table_name: str, key_values: tuple[Any, ...]) -> Row | None:
        row = self.tables[table_name].rows.get(key_values)
        return None if row is None else dict(row)

    def rows(self, table_name: str) -> list[Row]:
        return [dict(row) for row in self.tables[table_name].rows.values()]

    def select_where(
        self,
        table_name: str,
        predicate: Callable[[Row], bool],
        order_by: tuple[str, ...] = (),
        limit: int | None = None,
    ) -> list[Row]:
        rows = [dict(row) for row in self.tables[table_name].rows.values() if predicate(row)]
        if order_by:
            rows.sort(key=lambda row: tuple(row[column] for column in order_by))
        if limit is not None:
            rows = rows[:limit]
        return rows

    def select_by_index(
        self,
        table_name: str,
        index_name: str,
        values: Mapping[str, Any],
        order_by: tuple[str, ...] = (),
        limit: int | None = None,
    ) -> list[Row]:
        table = self.tables[table_name]
        index = self._index(table.decl, index_name)
        missing = set(values) - set(index.columns)
        if missing:
            raise ValueError(
                f"values {sorted(missing)} are not part of {table_name}.{index_name}"
            )
        return self.select_where(
            table_name,
            lambda row: all(row[column] == value for column, value in values.items()),
            order_by=order_by,
            limit=limit,
        )

    def claim_by_status(
        self,
        table_name: str,
        status: str,
        new_status: str,
        limit: int,
        order_by: tuple[str, ...],
        tx: int | None = None,
    ) -> list[Row]:
        claimed = self.select_where(
            table_name,
            lambda row: row.get("status") == status,
            order_by=order_by,
            limit=limit,
        )
        for row in claimed:
            key = tuple(row[column] for column in self.tables[table_name].decl.primary_key)
            self.update_pk(table_name, key, {"status": new_status}, tx=tx)
        return claimed

    def _validate_row(self, decl: TableDecl, row: Mapping[str, Any]) -> None:
        missing = decl.required_columns() - set(row)
        if missing:
            raise ValueError(f"{decl.name} row missing required columns {sorted(missing)}")
        unknown = set(row) - decl.column_names()
        if unknown:
            raise ValueError(f"{decl.name} row has unknown columns {sorted(unknown)}")

    @staticmethod
    def _index(decl: TableDecl, index_name: str) -> IndexDecl:
        for index in decl.indexes:
            if index.name == index_name:
                return index
        raise KeyError(f"{decl.name} has no index {index_name}")


def apply_new_rows(store: StateStore, new_rows: Mapping[str, Iterable[Mapping[str, Any]]], tx: int) -> None:
    for table_name, rows in new_rows.items():
        for row in rows:
            store.insert_ignore(table_name, row, tx=tx)
