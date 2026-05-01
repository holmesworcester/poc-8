"""Variant 6: SQL control loop with explicit hot arrangement caches.

The demo keeps durable facts in SQLite and mirrors four hot relations into
memory after each successful commit:

* events_by_id
* blocked_by_dep
* outbox_by_connection
* negentropy_leaves

Projectors read the arrangements for dependency checks, unblock fanout, outbox
dedupe, and negentropy-leaf dedupe. SQLite remains the authority: a restart
rebuilds every arrangement from committed rows.
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass
import hashlib
import json
import os
import sqlite3
import tempfile
from typing import Any, Deque, Iterable, Mapping


REL_EVENTS = "events"
REL_BLOCKED = "blocked_by_dep"
REL_OUTBOX = "outbox"
REL_NEGENTROPY = "negentropy_leaves"


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class Event:
    event_id: str
    workspace_id: str
    event_type: str
    body: str
    connection_ids: tuple[str, ...]
    dep_id: str | None
    canonical: bytes

    @classmethod
    def create(
        cls,
        *,
        workspace_id: str,
        event_type: str,
        body: str,
        connection_ids: Iterable[str] = (),
        dep_id: str | None = None,
    ) -> "Event":
        canonical = _json_bytes(
            {
                "workspace_id": workspace_id,
                "event_type": event_type,
                "body": body,
                "connection_ids": sorted(connection_ids),
                "dep_id": dep_id,
            }
        )
        # The production design uses canonical bytes as the identity boundary.
        # This demo uses SHA-256 from the standard library to keep the example
        # runnable without external dependencies.
        event_id = hashlib.sha256(canonical).hexdigest()[:16]
        return cls(
            event_id=event_id,
            workspace_id=workspace_id,
            event_type=event_type,
            body=body,
            connection_ids=tuple(sorted(connection_ids)),
            dep_id=dep_id,
            canonical=canonical,
        )


@dataclass(frozen=True)
class EventRow:
    event_id: str
    workspace_id: str
    event_type: str
    body: str
    connection_ids: tuple[str, ...]
    dep_id: str | None
    canonical: bytes
    event_seq: int

    @classmethod
    def from_event(cls, event: Event, event_seq: int) -> "EventRow":
        return cls(
            event_id=event.event_id,
            workspace_id=event.workspace_id,
            event_type=event.event_type,
            body=event.body,
            connection_ids=event.connection_ids,
            dep_id=event.dep_id,
            canonical=event.canonical,
            event_seq=event_seq,
        )


@dataclass(frozen=True)
class BlockedRow:
    dep_id: str
    event_id: str


@dataclass(frozen=True)
class OutboxRow:
    connection_id: str
    event_id: str
    queue_seq: int


@dataclass(frozen=True)
class NegentropyLeaf:
    workspace_id: str
    bucket: str
    event_id: str
    leaf_hash: str


@dataclass(frozen=True)
class Delta:
    op: str
    relation: str
    row: EventRow | BlockedRow | OutboxRow | NegentropyLeaf


@dataclass(frozen=True)
class Frame:
    connection_id: str
    event_id: str
    payload: bytes


class ArrangementCaches:
    """Hot read arrangements rebuilt from, and updated by, committed SQL rows."""

    def __init__(self) -> None:
        self.events_by_id: dict[str, EventRow] = {}
        self.blocked_by_dep: dict[str, set[str]] = defaultdict(set)
        self.outbox_by_connection: dict[str, OrderedDict[str, OutboxRow]] = defaultdict(
            OrderedDict
        )
        self.negentropy_leaves: dict[tuple[str, str], set[str]] = defaultdict(set)

    @classmethod
    def rebuild(cls, conn: sqlite3.Connection) -> "ArrangementCaches":
        caches = cls()
        for row in conn.execute(
            """
            SELECT event_id, workspace_id, event_type, body, connections_json,
                   dep_id, canonical, event_seq
            FROM events
            ORDER BY event_seq
            """
        ):
            event = EventRow(
                event_id=row[0],
                workspace_id=row[1],
                event_type=row[2],
                body=row[3],
                connection_ids=tuple(json.loads(row[4])),
                dep_id=row[5],
                canonical=row[6],
                event_seq=row[7],
            )
            caches.events_by_id[event.event_id] = event

        for dep_id, event_id in conn.execute(
            "SELECT dep_id, event_id FROM blocked_by_dep ORDER BY dep_id, event_id"
        ):
            caches.blocked_by_dep[dep_id].add(event_id)

        for connection_id, event_id, queue_seq in conn.execute(
            """
            SELECT connection_id, event_id, queue_seq
            FROM outbox
            ORDER BY connection_id, queue_seq
            """
        ):
            caches.outbox_by_connection[connection_id][event_id] = OutboxRow(
                connection_id=connection_id, event_id=event_id, queue_seq=queue_seq
            )

        for workspace_id, bucket, event_id, leaf_hash in conn.execute(
            """
            SELECT workspace_id, bucket, event_id, leaf_hash
            FROM negentropy_leaves
            ORDER BY workspace_id, bucket, event_id
            """
        ):
            caches.negentropy_leaves[(workspace_id, bucket)].add(event_id)

        return caches

    def apply_committed(self, deltas: Iterable[Delta]) -> None:
        for delta in deltas:
            if delta.relation == REL_EVENTS:
                row = _expect(delta.row, EventRow)
                if delta.op == "insert":
                    self.events_by_id[row.event_id] = row
                else:
                    self.events_by_id.pop(row.event_id, None)
            elif delta.relation == REL_BLOCKED:
                row = _expect(delta.row, BlockedRow)
                blocked = self.blocked_by_dep[row.dep_id]
                if delta.op == "insert":
                    blocked.add(row.event_id)
                else:
                    blocked.discard(row.event_id)
                    if not blocked:
                        self.blocked_by_dep.pop(row.dep_id, None)
            elif delta.relation == REL_OUTBOX:
                row = _expect(delta.row, OutboxRow)
                outbox = self.outbox_by_connection[row.connection_id]
                if delta.op == "insert":
                    outbox[row.event_id] = row
                    self.outbox_by_connection[row.connection_id] = OrderedDict(
                        sorted(outbox.items(), key=lambda item: item[1].queue_seq)
                    )
                else:
                    outbox.pop(row.event_id, None)
                    if not outbox:
                        self.outbox_by_connection.pop(row.connection_id, None)
            elif delta.relation == REL_NEGENTROPY:
                row = _expect(delta.row, NegentropyLeaf)
                leaves = self.negentropy_leaves[(row.workspace_id, row.bucket)]
                if delta.op == "insert":
                    leaves.add(row.event_id)
                else:
                    leaves.discard(row.event_id)
                    if not leaves:
                        self.negentropy_leaves.pop((row.workspace_id, row.bucket), None)
            else:
                raise ValueError(f"unknown relation {delta.relation!r}")

    def has_event(self, event_id: str) -> bool:
        return event_id in self.events_by_id

    def outbox_event_ids(self, connection_id: str) -> list[str]:
        return list(self.outbox_by_connection.get(connection_id, {}).keys())

    def snapshot(self) -> dict[str, Any]:
        return {
            "events_by_id": sorted(self.events_by_id),
            "blocked_by_dep": {
                dep_id: sorted(event_ids)
                for dep_id, event_ids in sorted(self.blocked_by_dep.items())
            },
            "outbox_by_connection": {
                connection_id: list(rows.keys())
                for connection_id, rows in sorted(self.outbox_by_connection.items())
            },
            "negentropy_leaves": {
                f"{workspace_id}:{bucket}": sorted(event_ids)
                for (workspace_id, bucket), event_ids in sorted(
                    self.negentropy_leaves.items()
                )
            },
        }


class HybridKernel:
    """Single-writer control loop backed by SQL and hot arrangements."""

    def __init__(self, db_path: str, conn: sqlite3.Connection) -> None:
        self.db_path = db_path
        self.conn = conn
        self.caches = ArrangementCaches.rebuild(conn)

    @classmethod
    def open(cls, db_path: str) -> "HybridKernel":
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        init_schema(conn)
        return cls(db_path, conn)

    def close(self) -> None:
        self.conn.close()

    def restart(self) -> "HybridKernel":
        self.close()
        return self.open(self.db_path)

    def ingest(self, event: Event) -> list[str]:
        """Admit one event and project it if its dependency is available."""

        trace: list[str] = []
        if self.caches.has_event(event.event_id):
            trace.append(
                f"duplicate {event.event_id}: events_by_id already has committed row"
            )
            return trace

        deltas: list[Delta] = []
        inserted_events: dict[str, EventRow] = {}
        inserted_outbox: set[tuple[str, str]] = set()
        inserted_leaves: set[tuple[str, str, str]] = set()
        projected_events: set[str] = set()

        self.conn.execute("BEGIN")
        try:
            event_seq = self._next_counter("event_seq")
            event_row = EventRow.from_event(event, event_seq)
            self._insert_event_row(event_row)
            inserted_events[event_row.event_id] = event_row
            deltas.append(Delta("insert", REL_EVENTS, event_row))
            trace.append(
                f"commit-stage events[{event.event_id}] inserted into SQL log"
            )

            def event_known(event_id: str) -> bool:
                return event_id in inserted_events or self.caches.has_event(event_id)

            def outbox_known(connection_id: str, event_id: str) -> bool:
                return (
                    event_id in self.caches.outbox_by_connection.get(connection_id, {})
                    or (connection_id, event_id) in inserted_outbox
                )

            def leaf_known(workspace_id: str, bucket: str, event_id: str) -> bool:
                return (
                    event_id in self.caches.negentropy_leaves.get(
                        (workspace_id, bucket), set()
                    )
                    or (workspace_id, bucket, event_id) in inserted_leaves
                )

            def project_ready(row: EventRow, reason: str) -> None:
                if row.event_id in projected_events:
                    return
                projected_events.add(row.event_id)
                trace.append(
                    f"project {row.event_id}: {reason}; projector reads hot "
                    "outbox and negentropy arrangements for dedupe"
                )
                for connection_id in row.connection_ids:
                    if outbox_known(connection_id, row.event_id):
                        continue
                    queue_seq = self._next_counter("outbox_seq")
                    outbox_row = OutboxRow(connection_id, row.event_id, queue_seq)
                    self.conn.execute(
                        """
                        INSERT INTO outbox(connection_id, event_id, queue_seq)
                        VALUES (?, ?, ?)
                        """,
                        (connection_id, row.event_id, queue_seq),
                    )
                    inserted_outbox.add((connection_id, row.event_id))
                    deltas.append(Delta("insert", REL_OUTBOX, outbox_row))
                    trace.append(
                        f"  outbox_by_connection[{connection_id}] += {row.event_id}"
                    )

                bucket = negentropy_bucket(row)
                if not leaf_known(row.workspace_id, bucket, row.event_id):
                    leaf = NegentropyLeaf(
                        workspace_id=row.workspace_id,
                        bucket=bucket,
                        event_id=row.event_id,
                        leaf_hash=negentropy_leaf_hash(row),
                    )
                    self.conn.execute(
                        """
                        INSERT INTO negentropy_leaves(
                            workspace_id, bucket, event_id, leaf_hash
                        )
                        VALUES (?, ?, ?, ?)
                        """,
                        (leaf.workspace_id, leaf.bucket, leaf.event_id, leaf.leaf_hash),
                    )
                    inserted_leaves.add((leaf.workspace_id, leaf.bucket, leaf.event_id))
                    deltas.append(Delta("insert", REL_NEGENTROPY, leaf))
                    trace.append(
                        f"  negentropy_leaves[{row.workspace_id}:{bucket}] += "
                        f"{row.event_id}"
                    )

            if event.dep_id is not None and not event_known(event.dep_id):
                blocked = BlockedRow(dep_id=event.dep_id, event_id=event.event_id)
                self.conn.execute(
                    """
                    INSERT INTO blocked_by_dep(dep_id, event_id)
                    VALUES (?, ?)
                    """,
                    (blocked.dep_id, blocked.event_id),
                )
                deltas.append(Delta("insert", REL_BLOCKED, blocked))
                trace.append(
                    f"block {event.event_id}: dep {event.dep_id} missing from "
                    "events_by_id arrangement"
                )
            else:
                project_ready(event_row, "dependency present in read arrangement")

            waiter_ids = sorted(self.caches.blocked_by_dep.get(event.event_id, set()))
            if waiter_ids:
                trace.append(
                    f"unblock scan: blocked_by_dep[{event.event_id}] -> {waiter_ids}"
                )
            for waiter_id in waiter_ids:
                waiter = self.caches.events_by_id[waiter_id]
                blocked = BlockedRow(dep_id=event.event_id, event_id=waiter_id)
                self.conn.execute(
                    """
                    DELETE FROM blocked_by_dep
                    WHERE dep_id = ? AND event_id = ?
                    """,
                    (blocked.dep_id, blocked.event_id),
                )
                deltas.append(Delta("delete", REL_BLOCKED, blocked))
                trace.append(f"  blocked_by_dep[{event.event_id}] -= {waiter_id}")
                project_ready(waiter, f"dep {event.event_id} committed in this batch")

            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        self.caches.apply_committed(deltas)
        trace.append(
            "arrangements updated after commit: "
            f"{len(deltas)} committed relation deltas applied"
        )
        return trace

    def delete_outbox_after_send(self, connection_id: str, event_id: str) -> list[str]:
        """Commit sender progress and update outbox_by_connection after commit."""

        row = self.caches.outbox_by_connection.get(connection_id, {}).get(event_id)
        if row is None:
            return [f"ack {connection_id}/{event_id}: no committed outbox row"]

        self.conn.execute("BEGIN")
        try:
            self.conn.execute(
                "DELETE FROM outbox WHERE connection_id = ? AND event_id = ?",
                (connection_id, event_id),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

        self.caches.apply_committed([Delta("delete", REL_OUTBOX, row)])
        return [
            f"ack {connection_id}/{event_id}: committed outbox delete; "
            "outbox_by_connection updated from delta"
        ]

    def stage_then_rollback_for_test(self, event: Event) -> list[Delta]:
        """Testing hook proving arrangements only follow committed deltas."""

        self.conn.execute("BEGIN")
        event_seq = self._next_counter("event_seq")
        event_row = EventRow.from_event(event, event_seq)
        self._insert_event_row(event_row)
        deltas = [Delta("insert", REL_EVENTS, event_row)]
        self.conn.rollback()
        return deltas

    def sender(self, connection_id: str, capacity: int) -> "SenderOwner":
        return SenderOwner(self, connection_id, capacity)

    def _next_counter(self, name: str) -> int:
        current = self.conn.execute(
            "SELECT value FROM meta WHERE key = ?", (name,)
        ).fetchone()
        if current is None:
            raise RuntimeError(f"missing meta counter {name!r}")
        next_value = int(current[0]) + 1
        self.conn.execute(
            "UPDATE meta SET value = ? WHERE key = ?", (str(next_value), name)
        )
        return next_value

    def _insert_event_row(self, row: EventRow) -> None:
        self.conn.execute(
            """
            INSERT INTO events(
                event_id, workspace_id, event_type, body, connections_json,
                dep_id, canonical, event_seq
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row.event_id,
                row.workspace_id,
                row.event_type,
                row.body,
                json.dumps(list(row.connection_ids)),
                row.dep_id,
                row.canonical,
                row.event_seq,
            ),
        )


class SenderOwner:
    """One bounded sender queue per connection.

    The durable outbox remains the source of truth. This owner only stages a
    bounded number of frames from outbox_by_connection so a slow connection
    cannot grow unbounded memory.
    """

    def __init__(self, kernel: HybridKernel, connection_id: str, capacity: int) -> None:
        if capacity < 1:
            raise ValueError("sender capacity must be positive")
        self.kernel = kernel
        self.connection_id = connection_id
        self.capacity = capacity
        self.memory_queue: Deque[str] = deque()
        self.in_flight: set[str] = set()

    def refill_from_arrangement(self) -> list[str]:
        available = self.capacity - len(self.memory_queue) - len(self.in_flight)
        if available <= 0:
            return []

        loaded: list[str] = []
        already_local = set(self.memory_queue) | self.in_flight
        for event_id in self.kernel.caches.outbox_event_ids(self.connection_id):
            if len(loaded) >= available:
                break
            if event_id in already_local:
                continue
            self.memory_queue.append(event_id)
            loaded.append(event_id)
            already_local.add(event_id)
        return loaded

    def on_writable(self) -> Frame | None:
        if not self.memory_queue:
            self.refill_from_arrangement()
        if not self.memory_queue:
            return None
        event_id = self.memory_queue.popleft()
        self.in_flight.add(event_id)
        event = self.kernel.caches.events_by_id[event_id]
        return Frame(self.connection_id, event_id, event.canonical)

    def ack_written(self, event_id: str) -> list[str]:
        self.in_flight.discard(event_id)
        return self.kernel.delete_outbox_after_send(self.connection_id, event_id)

    def memory_event_ids(self) -> list[str]:
        return list(self.memory_queue)


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        INSERT OR IGNORE INTO meta(key, value) VALUES ('event_seq', '0');
        INSERT OR IGNORE INTO meta(key, value) VALUES ('outbox_seq', '0');

        CREATE TABLE IF NOT EXISTS events(
            event_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            body TEXT NOT NULL,
            connections_json TEXT NOT NULL,
            dep_id TEXT,
            canonical BLOB NOT NULL,
            event_seq INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS blocked_by_dep(
            dep_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            PRIMARY KEY(dep_id, event_id),
            FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS outbox(
            connection_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            queue_seq INTEGER NOT NULL,
            PRIMARY KEY(connection_id, event_id),
            FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS outbox_by_connection_idx
            ON outbox(connection_id, queue_seq);

        CREATE TABLE IF NOT EXISTS negentropy_leaves(
            workspace_id TEXT NOT NULL,
            bucket TEXT NOT NULL,
            event_id TEXT NOT NULL,
            leaf_hash TEXT NOT NULL,
            PRIMARY KEY(workspace_id, bucket, event_id),
            FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
        );
        """
    )
    conn.commit()


def negentropy_bucket(row: EventRow) -> str:
    return row.event_id[:2]


def negentropy_leaf_hash(row: EventRow) -> str:
    return hashlib.sha256(b"leaf:" + row.canonical).hexdigest()[:24]


def run_worked_trace() -> list[str]:
    with tempfile.TemporaryDirectory(prefix="variant06-") as tempdir:
        db_path = os.path.join(tempdir, "kernel.sqlite3")
        kernel = HybridKernel.open(db_path)
        parent = Event.create(
            workspace_id="workspace-alpha",
            event_type="message",
            body="parent fact",
            connection_ids=("conn-east",),
        )
        child = Event.create(
            workspace_id="workspace-alpha",
            event_type="message",
            body="child fact waits for parent",
            connection_ids=("conn-east",),
            dep_id=parent.event_id,
        )

        trace = [
            "worked trace: child arrives before parent",
            f"parent id = {parent.event_id}",
            f"child id = {child.event_id}",
        ]
        trace.extend(kernel.ingest(child))
        trace.extend(kernel.ingest(parent))

        sender = kernel.sender("conn-east", capacity=1)
        loaded = sender.refill_from_arrangement()
        trace.append(
            "sender refill: loaded "
            f"{loaded}; remaining durable outbox = "
            f"{kernel.caches.outbox_event_ids('conn-east')}"
        )
        frame = sender.on_writable()
        if frame is not None:
            trace.append(
                f"sender writable: wrote {frame.event_id}; outbox row stays durable"
            )
            trace.extend(sender.ack_written(frame.event_id))
        loaded = sender.refill_from_arrangement()
        trace.append(f"sender refill after ack: loaded {loaded}")

        snapshot_before = kernel.caches.snapshot()
        restarted = kernel.restart()
        trace.append(
            "restart rebuild: arrangements match committed SQL = "
            f"{snapshot_before == restarted.caches.snapshot()}"
        )
        restarted.close()
        return trace


def _expect(value: object, cls: type[Any]) -> Any:
    if not isinstance(value, cls):
        raise TypeError(f"expected {cls.__name__}, got {type(value).__name__}")
    return value


if __name__ == "__main__":
    print("\n".join(run_worked_trace()))
