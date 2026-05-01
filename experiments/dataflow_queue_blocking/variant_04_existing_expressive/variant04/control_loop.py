"""Single-writer control loop for the Variant 4 demo."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from .events import (
    ParsedEvent,
    ProjectionContext,
    decode_envelope,
    event_id_for,
    wire_id_for,
)
from .registry import RuntimeRegistry
from .state import StateStore, apply_new_rows
from .trace import Trace


@dataclass(frozen=True)
class WorkBudget:
    inbound_bytes: int = 0
    ready_events: int = 0


class ControlLoop:
    def __init__(self, registry: RuntimeRegistry, store: StateStore, trace: Trace) -> None:
        self.registry = registry
        self.store = store
        self.trace = trace
        self.now_ms = 1_000

    def enqueue_inbound(
        self,
        raw_bytes: bytes,
        origin_connection_id: str | None,
        now_ms: int | None = None,
    ) -> str:
        at_ms = self._tick(now_ms)
        wire_id = wire_id_for(raw_bytes)
        with self.store.transaction("inbound.enqueue", wire_id=wire_id) as tx:
            inserted = self.store.insert_ignore(
                "inbound_bytes",
                {
                    "wire_id": wire_id,
                    "raw_bytes": raw_bytes,
                    "origin_connection_id": origin_connection_id,
                    "status": "pending",
                    "attempts": 0,
                    "last_error": None,
                    "created_at_ms": at_ms,
                    "updated_at_ms": at_ms,
                },
                tx=tx,
            )
            obs_key = (wire_id, origin_connection_id)
            observation = self.store.get("inbound_observations", obs_key)
            if observation is None:
                self.store.insert_ignore(
                    "inbound_observations",
                    {
                        "wire_id": wire_id,
                        "origin_connection_id": origin_connection_id,
                        "seen_count": 1,
                        "first_seen_at_ms": at_ms,
                        "last_seen_at_ms": at_ms,
                    },
                    tx=tx,
                )
            else:
                self.store.update_pk(
                    "inbound_observations",
                    obs_key,
                    {
                        "seen_count": observation["seen_count"] + 1,
                        "last_seen_at_ms": at_ms,
                    },
                    tx=tx,
                )
            self.trace.record(
                "inbound.enqueued",
                tx=tx,
                wire_id=wire_id,
                inserted=inserted,
                origin_connection_id=origin_connection_id,
            )
        return wire_id

    def run_once(self, budget: WorkBudget) -> None:
        if budget.inbound_bytes:
            self._claim_and_process_inbound(budget.inbound_bytes)
        if budget.ready_events:
            self._claim_and_process_ready_events(budget.ready_events)

    def seed_open_connection(
        self,
        connection_id: str,
        remote_endpoint_id: str,
        shared_workspaces: tuple[str, ...],
        now_ms: int | None = None,
    ) -> None:
        at_ms = self._tick(now_ms)
        with self.store.transaction("connection.seed", connection_id=connection_id) as tx:
            self.store.insert_ignore(
                "connections",
                {
                    "connection_id": connection_id,
                    "remote_endpoint_id": remote_endpoint_id,
                    "shared_workspaces": shared_workspaces,
                    "status": "open",
                    "updated_at_ms": at_ms,
                },
                tx=tx,
            )

    def _claim_and_process_inbound(self, limit: int) -> None:
        with self.store.transaction("inbound.claim", limit=limit) as tx:
            claimed = self.store.claim_by_status(
                "inbound_bytes",
                status="pending",
                new_status="processing",
                limit=limit,
                order_by=("created_at_ms", "wire_id"),
                tx=tx,
            )
            self.trace.record("inbound.claimed", tx=tx, count=len(claimed), limit=limit)
        for row in claimed:
            self._process_inbound(row["wire_id"])

    def _claim_and_process_ready_events(self, limit: int) -> None:
        with self.store.transaction("ready.claim", limit=limit) as tx:
            claimed = self.store.claim_by_status(
                "events",
                status="ready",
                new_status="processing",
                limit=limit,
                order_by=("created_at_ms", "event_id"),
                tx=tx,
            )
            self.trace.record("ready.claimed", tx=tx, count=len(claimed), limit=limit)
        for row in claimed:
            self._project_existing_event(row["event_id"], row["canonical_bytes"])

    def _process_inbound(self, wire_id: str) -> None:
        row = self.store.get("inbound_bytes", (wire_id,))
        if row is None:
            return
        raw_bytes = row["raw_bytes"]
        event_id = event_id_for(raw_bytes)
        now_ms = self._tick(None)

        with self.store.transaction("inbound.process", wire_id=wire_id, event_id=event_id) as tx:
            existing = self.store.get("events", (event_id,))
            if existing is not None:
                self.store.update_pk(
                    "inbound_bytes",
                    (wire_id,),
                    {"status": "duplicate", "updated_at_ms": now_ms},
                    tx=tx,
                )
                self.trace.record(
                    "event.duplicate",
                    tx=tx,
                    event_id=event_id,
                    existing_status=existing["status"],
                )
                return

            try:
                event_type, payload = decode_envelope(raw_bytes)
                module = self.registry.module_for_event(event_type)
                parsed = module.parse(event_id, raw_bytes, payload, row["origin_connection_id"])
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                self.store.update_pk(
                    "inbound_bytes",
                    (wire_id,),
                    {
                        "status": "invalid",
                        "last_error": str(exc),
                        "attempts": row["attempts"] + 1,
                        "updated_at_ms": now_ms,
                    },
                    tx=tx,
                )
                self.trace.record("inbound.invalid", tx=tx, wire_id=wire_id, error=str(exc))
                return

            self._insert_event_row(parsed, status="processing", now_ms=now_ms, tx=tx)
            self.store.update_pk(
                "inbound_bytes",
                (wire_id,),
                {"status": "applied", "updated_at_ms": now_ms},
                tx=tx,
            )
            self.trace.record(
                "event.admitted",
                tx=tx,
                event_id=parsed.event_id,
                event_type=parsed.event_type,
                module_id=module.module_id,
            )
            self._apply_or_block(parsed, tx=tx, now_ms=now_ms)

    def _project_existing_event(self, event_id: str, canonical_bytes: bytes) -> None:
        now_ms = self._tick(None)
        with self.store.transaction("event.project_ready", event_id=event_id) as tx:
            event_type, payload = decode_envelope(canonical_bytes)
            module = self.registry.module_for_event(event_type)
            parsed = module.parse(event_id, canonical_bytes, payload, origin_connection_id=None)
            self._apply_or_block(parsed, tx=tx, now_ms=now_ms)

    def _apply_or_block(self, parsed: ParsedEvent, tx: int, now_ms: int) -> None:
        blockers = self._missing_dependencies(parsed)
        if blockers:
            self.store.update_pk(
                "events",
                (parsed.event_id,),
                {"status": "blocked", "updated_at_ms": now_ms, "last_error": None},
                tx=tx,
            )
            for blocker in blockers:
                self.store.insert_ignore(
                    "blocked_by_event",
                    {
                        "blocked_by_event_id": blocker,
                        "event_id": parsed.event_id,
                        "created_at_ms": now_ms,
                    },
                    tx=tx,
                )
            self.trace.record(
                "event.blocked",
                tx=tx,
                event_id=parsed.event_id,
                blockers=blockers,
            )
            return

        module = self.registry.module_for_event(parsed.event_type)
        dependency_rows = {
            dep_id: self.store.get("events", (dep_id,)) for dep_id in parsed.dependencies
        }
        context = ProjectionContext(event=parsed, dependency_rows=dependency_rows)
        try:
            result = module.project(context, self.store)
            apply_new_rows(self.store, result.new_rows, tx=tx)
            self.store.update_pk(
                "events",
                (parsed.event_id,),
                {
                    "status": "applied",
                    "updated_at_ms": now_ms,
                    "applied_at_ms": now_ms,
                    "last_error": None,
                },
                tx=tx,
            )
            self.trace.record(
                "event.applied",
                tx=tx,
                event_id=parsed.event_id,
                event_type=parsed.event_type,
                **dict(result.trace),
            )
            self._unblock_dependents(parsed.event_id, tx=tx, now_ms=now_ms)
        except Exception as exc:
            self.store.update_pk(
                "events",
                (parsed.event_id,),
                {"status": "rejected", "updated_at_ms": now_ms, "last_error": str(exc)},
                tx=tx,
            )
            self.trace.record(
                "event.rejected",
                tx=tx,
                event_id=parsed.event_id,
                event_type=parsed.event_type,
                error=str(exc),
            )

    def _insert_event_row(self, parsed: ParsedEvent, status: str, now_ms: int, tx: int) -> None:
        self.store.insert_ignore(
            "events",
            {
                "event_id": parsed.event_id,
                "event_type": parsed.event_type,
                "workspace_id": parsed.workspace_id,
                "scope": parsed.scope,
                "canonical_bytes": parsed.canonical_bytes,
                "deps": parsed.dependencies,
                "status": status,
                "created_at_ms": now_ms,
                "updated_at_ms": now_ms,
                "applied_at_ms": None,
                "last_error": None,
            },
            tx=tx,
        )

    def _missing_dependencies(self, parsed: ParsedEvent) -> tuple[str, ...]:
        missing: list[str] = []
        for dep_id in parsed.dependencies:
            row = self.store.get("events", (dep_id,))
            if row is None or row["status"] != "applied":
                missing.append(dep_id)
        return tuple(missing)

    def _unblock_dependents(self, applied_event_id: str, tx: int, now_ms: int) -> None:
        removed_edges = self.store.delete_where(
            "blocked_by_event",
            lambda row: row["blocked_by_event_id"] == applied_event_id,
            tx=tx,
        )
        affected = sorted({row["event_id"] for row in removed_edges})
        for event_id in affected:
            remaining = self.store.select_by_index(
                "blocked_by_event",
                "by_blocked_event",
                {"event_id": event_id},
            )
            if not remaining:
                event = self.store.get("events", (event_id,))
                if event is not None and event["status"] == "blocked":
                    self.store.update_pk(
                        "events",
                        (event_id,),
                        {"status": "ready", "updated_at_ms": now_ms},
                        tx=tx,
                    )
                    self.trace.record(
                        "event.unblocked_ready",
                        tx=tx,
                        blocker=applied_event_id,
                        event_id=event_id,
                    )

    def _tick(self, now_ms: int | None) -> int:
        if now_ms is not None:
            self.now_ms = max(self.now_ms, now_ms)
        else:
            self.now_ms += 1
        return self.now_ms
