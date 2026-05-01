#!/usr/bin/env python3
"""Runnable SQLite demo for Variant 03: Existing-minimal.

This file is a small control-loop simulator over schema.sql. It has no
Differential dependency. The production plan uses BLAKE3 event ids; this
demo uses SHA-256 from the Python standard library so the scenario remains
self-contained and deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Iterable, Sequence


SCHEMA_PATH = Path(__file__).with_name("schema.sql")


@dataclass(frozen=True)
class ParsedEvent:
    event_id: str
    event_type: str
    workspace_id: str
    name: str
    deps: tuple[str, ...]
    body: str
    canonical_event_bytes: bytes


@dataclass(frozen=True)
class InboundResult:
    wire_id: str
    event_id: str | None
    event_status: str
    blocked_by: tuple[str, ...] = ()
    error: str | None = None


def connect(path: str = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.isolation_level = None
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.execute(
        """
        CREATE TEMP TABLE IF NOT EXISTS apply_unblock_candidates (
          event_id TEXT PRIMARY KEY
        ) WITHOUT ROWID
        """
    )
    return conn


def event_id_for(canonical_event_bytes: bytes) -> str:
    return "e_" + hashlib.sha256(canonical_event_bytes).hexdigest()[:16]


def message_bytes(
    name: str,
    *,
    workspace_id: str = "ws-main",
    deps: Sequence[str] = (),
    body: str | None = None,
) -> bytes:
    """Return deterministic canonical bytes for the demo message codec."""

    doc = {
        "body": body if body is not None else f"body:{name}",
        "deps": list(deps),
        "name": name,
        "type": "message",
        "workspace_id": workspace_id,
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_event(canonical_event_bytes: bytes) -> ParsedEvent:
    try:
        doc = json.loads(canonical_event_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid canonical JSON: {exc}") from exc

    required = ("type", "workspace_id", "name", "deps", "body")
    missing = [key for key in required if key not in doc]
    if missing:
        raise ValueError(f"missing canonical fields: {', '.join(missing)}")
    if doc["type"] != "message":
        raise ValueError(f"unsupported event type: {doc['type']!r}")
    if not isinstance(doc["deps"], list) or not all(isinstance(dep, str) for dep in doc["deps"]):
        raise ValueError("deps must be a list of event-id strings")

    return ParsedEvent(
        event_id=event_id_for(canonical_event_bytes),
        event_type=doc["type"],
        workspace_id=doc["workspace_id"],
        name=doc["name"],
        deps=tuple(doc["deps"]),
        body=doc["body"],
        canonical_event_bytes=canonical_event_bytes,
    )


def seed_workspace_connection(
    conn: sqlite3.Connection,
    *,
    workspace_id: str = "ws-main",
    connection_id: str = "conn-peer",
) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO workspace_connections(workspace_id, connection_id)
        VALUES (?, ?)
        """,
        (workspace_id, connection_id),
    )


def ingest_inbound(
    conn: sqlite3.Connection,
    *,
    wire_id: str,
    canonical_event_bytes: bytes,
    origin_connection_id: str = "conn-origin",
    now_ms: int,
) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO inbound_bytes(
          wire_id,
          origin_connection_id,
          canonical_event_bytes,
          status,
          received_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, 'pending', ?, ?)
        """,
        (wire_id, origin_connection_id, canonical_event_bytes, now_ms, now_ms),
    )


def claim_inbound_batch(conn: sqlite3.Connection, *, limit: int, now_ms: int) -> list[sqlite3.Row]:
    conn.execute("BEGIN IMMEDIATE")
    rows = conn.execute(
        """
        SELECT wire_id, canonical_event_bytes
          FROM inbound_bytes
         WHERE status = 'pending'
           AND not_before_ms <= ?
         ORDER BY received_at_ms, wire_id
         LIMIT ?
        """,
        (now_ms, limit),
    ).fetchall()
    if rows:
        conn.executemany(
            """
            UPDATE inbound_bytes
               SET status = 'processing',
                   attempts = attempts + 1,
                   updated_at_ms = ?
             WHERE wire_id = ?
               AND status = 'pending'
            """,
            [(now_ms, row["wire_id"]) for row in rows],
        )
    conn.execute("COMMIT")
    return rows


def process_inbound_batch(conn: sqlite3.Connection, *, limit: int, now_ms: int) -> list[InboundResult]:
    rows = claim_inbound_batch(conn, limit=limit, now_ms=now_ms)
    return [
        process_claimed_inbound(
            conn,
            wire_id=row["wire_id"],
            canonical_event_bytes=row["canonical_event_bytes"],
            now_ms=now_ms,
        )
        for row in rows
    ]


def process_claimed_inbound(
    conn: sqlite3.Connection,
    *,
    wire_id: str,
    canonical_event_bytes: bytes,
    now_ms: int,
) -> InboundResult:
    event_id = event_id_for(canonical_event_bytes)
    conn.execute("BEGIN IMMEDIATE")
    try:
        inserted = conn.execute(
            """
            INSERT OR IGNORE INTO events(
              event_id,
              canonical_event_bytes,
              scope,
              status,
              created_at_ms,
              updated_at_ms
            )
            VALUES (?, ?, 'durable', 'processing', ?, ?)
            """,
            (event_id, canonical_event_bytes, now_ms, now_ms),
        ).rowcount

        if inserted == 0:
            conn.execute(
                """
                UPDATE inbound_bytes
                   SET status = 'processed',
                       last_error = 'duplicate known event_id',
                       updated_at_ms = ?
                 WHERE wire_id = ?
                """,
                (now_ms, wire_id),
            )
            conn.execute("COMMIT")
            return InboundResult(wire_id=wire_id, event_id=event_id, event_status="duplicate")

        try:
            parsed = parse_event(canonical_event_bytes)
        except ValueError as exc:
            conn.execute("DELETE FROM events WHERE event_id = ? AND status = 'processing'", (event_id,))
            conn.execute(
                """
                UPDATE inbound_bytes
                   SET status = 'invalid',
                       last_error = ?,
                       updated_at_ms = ?
                 WHERE wire_id = ?
                """,
                (str(exc), now_ms, wire_id),
            )
            conn.execute("COMMIT")
            return InboundResult(wire_id=wire_id, event_id=None, event_status="invalid", error=str(exc))

        conn.executemany(
            """
            INSERT OR IGNORE INTO event_dependencies(event_id, depends_on_event_id)
            VALUES (?, ?)
            """,
            [(parsed.event_id, dep) for dep in parsed.deps],
        )
        missing_deps = tuple(
            dep
            for dep in parsed.deps
            if conn.execute(
                "SELECT 1 FROM events WHERE event_id = ? AND status = 'applied'",
                (dep,),
            ).fetchone()
            is None
        )
        status = "blocked" if missing_deps else "ready"
        conn.execute(
            """
            UPDATE events
               SET event_type = ?,
                   workspace_id = ?,
                   status = ?,
                   updated_at_ms = ?
             WHERE event_id = ?
            """,
            (parsed.event_type, parsed.workspace_id, status, now_ms, parsed.event_id),
        )
        conn.executemany(
            """
            INSERT OR IGNORE INTO blocked_by_event(blocked_by_event_id, event_id, created_at_ms)
            VALUES (?, ?, ?)
            """,
            [(dep, parsed.event_id, now_ms) for dep in missing_deps],
        )
        conn.execute(
            """
            UPDATE inbound_bytes
               SET status = 'processed',
                   updated_at_ms = ?
             WHERE wire_id = ?
            """,
            (now_ms, wire_id),
        )
        conn.execute("COMMIT")
        return InboundResult(
            wire_id=wire_id,
            event_id=parsed.event_id,
            event_status=status,
            blocked_by=missing_deps,
        )
    except Exception:
        conn.execute("ROLLBACK")
        raise


def claim_ready_events(conn: sqlite3.Connection, *, limit: int, now_ms: int) -> list[str]:
    conn.execute("BEGIN IMMEDIATE")
    rows = conn.execute(
        """
        SELECT event_id
          FROM events
         WHERE status = 'ready'
         ORDER BY created_at_ms, event_id
         LIMIT ?
        """,
        (limit,),
    ).fetchall()
    event_ids = [row["event_id"] for row in rows]
    if event_ids:
        conn.executemany(
            """
            UPDATE events
               SET status = 'processing',
                   updated_at_ms = ?
             WHERE event_id = ?
               AND status = 'ready'
            """,
            [(now_ms, event_id) for event_id in event_ids],
        )
    conn.execute("COMMIT")
    return event_ids


def apply_event(conn: sqlite3.Connection, event_id: str, *, now_ms: int) -> None:
    """Project one claimed event and unblock dependents in one transaction."""

    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            """
            SELECT event_id, canonical_event_bytes, status
              FROM events
             WHERE event_id = ?
            """,
            (event_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown event_id: {event_id}")
        if row["status"] != "processing":
            raise ValueError(f"event {event_id} must be processing before apply, got {row['status']}")

        parsed = parse_event(row["canonical_event_bytes"])
        missing_deps = tuple(
            dep
            for dep in parsed.deps
            if conn.execute(
                "SELECT 1 FROM events WHERE event_id = ? AND status = 'applied'",
                (dep,),
            ).fetchone()
            is None
        )
        if missing_deps:
            conn.executemany(
                """
                INSERT OR IGNORE INTO blocked_by_event(blocked_by_event_id, event_id, created_at_ms)
                VALUES (?, ?, ?)
                """,
                [(dep, parsed.event_id, now_ms) for dep in missing_deps],
            )
            conn.execute(
                """
                UPDATE events
                   SET status = 'blocked',
                       updated_at_ms = ?
                 WHERE event_id = ?
                """,
                (now_ms, parsed.event_id),
            )
            conn.execute("COMMIT")
            return

        conn.execute(
            """
            INSERT OR IGNORE INTO content_messages(
              event_id,
              workspace_id,
              message_name,
              body,
              applied_at_ms
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (parsed.event_id, parsed.workspace_id, parsed.name, parsed.body, now_ms),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO outbox(connection_id, event_id, queued_at_ms)
            SELECT connection_id, ?, ?
              FROM workspace_connections
             WHERE workspace_id = ?
            """,
            (parsed.event_id, now_ms, parsed.workspace_id),
        )
        conn.execute(
            """
            UPDATE events
               SET status = 'applied',
                   updated_at_ms = ?
             WHERE event_id = ?
            """,
            (now_ms, parsed.event_id),
        )

        conn.execute("DELETE FROM apply_unblock_candidates")
        conn.execute(
            """
            INSERT OR IGNORE INTO apply_unblock_candidates(event_id)
            SELECT event_id
              FROM blocked_by_event
             WHERE blocked_by_event_id = ?
            """,
            (parsed.event_id,),
        )
        conn.execute(
            """
            DELETE FROM blocked_by_event
             WHERE blocked_by_event_id = ?
            """,
            (parsed.event_id,),
        )
        conn.execute(
            """
            UPDATE events
               SET status = 'ready',
                   updated_at_ms = ?
             WHERE status = 'blocked'
               AND event_id IN (SELECT event_id FROM apply_unblock_candidates)
               AND NOT EXISTS (
                 SELECT 1
                   FROM blocked_by_event
                  WHERE blocked_by_event.event_id = events.event_id
               )
            """,
            (now_ms,),
        )
        conn.execute("DELETE FROM apply_unblock_candidates")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def apply_ready_batch(conn: sqlite3.Connection, *, limit: int, now_ms: int) -> list[str]:
    event_ids = claim_ready_events(conn, limit=limit, now_ms=now_ms)
    for event_id in event_ids:
        apply_event(conn, event_id, now_ms=now_ms)
    return event_ids


def refill_hot_queue(
    conn: sqlite3.Connection,
    *,
    connection_id: str,
    byte_budget: int,
    present: Iterable[str] = (),
) -> list[tuple[str, bytes]]:
    """Return the next bounded sender hot-queue refill without doing socket IO."""

    present_ids = set(present)
    queued: list[tuple[str, bytes]] = []
    used = 0
    rows = conn.execute(
        """
        SELECT o.event_id, e.canonical_event_bytes
          FROM outbox AS o
          JOIN events AS e ON e.event_id = o.event_id
         WHERE o.connection_id = ?
           AND e.status = 'applied'
         ORDER BY o.queued_at_ms, o.event_id
        """,
        (connection_id,),
    ).fetchall()
    for row in rows:
        if row["event_id"] in present_ids:
            continue
        frame_cost = len(row["canonical_event_bytes"]) + 4
        if queued and used + frame_cost > byte_budget:
            break
        if not queued and frame_cost > byte_budget:
            break
        queued.append((row["event_id"], row["canonical_event_bytes"]))
        used += frame_cost
    return queued


def seed_out_of_order_dependency_scenario(conn: sqlite3.Connection) -> dict[str, str]:
    seed_workspace_connection(conn, workspace_id="ws-main", connection_id="conn-peer")

    a_bytes = message_bytes("A")
    a_id = event_id_for(a_bytes)
    b_bytes = message_bytes("B", deps=(a_id,))
    b_id = event_id_for(b_bytes)
    c_bytes = message_bytes("C", deps=(b_id,))
    c_id = event_id_for(c_bytes)

    ingest_inbound(conn, wire_id="wire-C", canonical_event_bytes=c_bytes, now_ms=10)
    ingest_inbound(conn, wire_id="wire-B", canonical_event_bytes=b_bytes, now_ms=20)
    ingest_inbound(conn, wire_id="wire-A", canonical_event_bytes=a_bytes, now_ms=30)

    return {"A": a_id, "B": b_id, "C": c_id}


def fetch_statuses(conn: sqlite3.Connection) -> dict[str, str]:
    return {
        row["event_id"]: row["status"]
        for row in conn.execute("SELECT event_id, status FROM events ORDER BY event_id")
    }


def fetch_blockers(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    return [
        (row["blocked_by_event_id"], row["event_id"])
        for row in conn.execute(
            """
            SELECT blocked_by_event_id, event_id
              FROM blocked_by_event
             ORDER BY blocked_by_event_id, event_id
            """
        )
    ]


def fetch_outbox(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    return [
        (row["connection_id"], row["event_id"])
        for row in conn.execute(
            """
            SELECT connection_id, event_id
              FROM outbox
             ORDER BY connection_id, queued_at_ms, event_id
            """
        )
    ]


def main() -> None:
    conn = connect()
    ids = seed_out_of_order_dependency_scenario(conn)
    print("ids", ids)
    print("inbound batch 1", process_inbound_batch(conn, limit=2, now_ms=100))
    print("ready batch 1", apply_ready_batch(conn, limit=1, now_ms=110))
    print("statuses", fetch_statuses(conn))
    print("blockers", fetch_blockers(conn))
    print("inbound batch 2", process_inbound_batch(conn, limit=2, now_ms=200))
    print("ready batch 2", apply_ready_batch(conn, limit=1, now_ms=210))
    print("ready batch 3", apply_ready_batch(conn, limit=1, now_ms=220))
    print("ready batch 4", apply_ready_batch(conn, limit=1, now_ms=230))
    print("statuses", fetch_statuses(conn))
    print("blockers", fetch_blockers(conn))
    print("outbox", fetch_outbox(conn))


if __name__ == "__main__":
    main()
