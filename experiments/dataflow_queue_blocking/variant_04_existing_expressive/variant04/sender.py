"""Byte-bounded outbox refill for one connection sender."""

from __future__ import annotations

from dataclasses import dataclass, field

from .state import StateStore
from .trace import Trace


@dataclass
class HotFrame:
    event_id: str
    canonical_bytes: bytes
    frame_bytes: bytes


@dataclass
class ConnectionSender:
    connection_id: str
    store: StateStore
    trace: Trace
    hot_queue: list[HotFrame] = field(default_factory=list)
    present: set[str] = field(default_factory=set)

    def refill(self, byte_budget: int, max_events: int = 16) -> int:
        """Move pending outbox rows into the sender hot queue.

        The refill joins outbox rows to event bytes and connection metadata, but
        it does not delete outbox rows. Deletion happens only after a complete
        frame is accepted by the socket owner.
        """

        used = sum(len(frame.frame_bytes) for frame in self.hot_queue)
        loaded = 0
        connection = self.store.get("connections", (self.connection_id,))
        if connection is None or connection["status"] != "open":
            self.trace.record("sender.refill_skipped", connection_id=self.connection_id, reason="closed")
            return 0

        candidates = self.store.select_by_index(
            "outbox",
            "by_connection",
            {"connection_id": self.connection_id},
            order_by=("queued_at_ms", "event_id"),
            limit=max_events,
        )
        with self.store.transaction("sender.refill", connection_id=self.connection_id) as tx:
            for candidate in candidates:
                if candidate["event_id"] in self.present:
                    self.trace.record(
                        "sender.refill_present",
                        tx=tx,
                        connection_id=self.connection_id,
                        event_id=candidate["event_id"],
                    )
                    continue
                event = self.store.get("events", (candidate["event_id"],))
                if event is None or event["status"] != "applied":
                    self.trace.record(
                        "sender.refill_missing_event",
                        tx=tx,
                        connection_id=self.connection_id,
                        event_id=candidate["event_id"],
                    )
                    continue
                if event["workspace_id"] not in tuple(connection["shared_workspaces"]):
                    self.trace.record(
                        "sender.refill_denied",
                        tx=tx,
                        connection_id=self.connection_id,
                        event_id=candidate["event_id"],
                    )
                    continue

                frame_bytes = self._wrap(event["event_id"], event["canonical_bytes"])
                if loaded > 0 and used + len(frame_bytes) > byte_budget:
                    break
                if used + len(frame_bytes) > byte_budget and self.hot_queue:
                    break

                self.hot_queue.append(
                    HotFrame(
                        event_id=event["event_id"],
                        canonical_bytes=event["canonical_bytes"],
                        frame_bytes=frame_bytes,
                    )
                )
                self.present.add(event["event_id"])
                used += len(frame_bytes)
                loaded += 1
                self.trace.record(
                    "sender.refilled",
                    tx=tx,
                    connection_id=self.connection_id,
                    event_id=event["event_id"],
                    frame_bytes=len(frame_bytes),
                    used_bytes=used,
                    byte_budget=byte_budget,
                )
        return loaded

    def flush_success(self, max_frames: int) -> list[str]:
        sent: list[str] = []
        with self.store.transaction("sender.flush_success", connection_id=self.connection_id) as tx:
            for frame in list(self.hot_queue[:max_frames]):
                self.hot_queue.remove(frame)
                self.present.remove(frame.event_id)
                self.store.delete_pk("outbox", (self.connection_id, frame.event_id), tx=tx)
                sent.append(frame.event_id)
                self.trace.record(
                    "sender.sent",
                    tx=tx,
                    connection_id=self.connection_id,
                    event_id=frame.event_id,
                )
        return sent

    def fail_and_backoff(self) -> None:
        with self.store.transaction("sender.failure", connection_id=self.connection_id) as tx:
            failed = [frame.event_id for frame in self.hot_queue]
            self.hot_queue.clear()
            self.present.clear()
            self.trace.record(
                "sender.backoff",
                tx=tx,
                connection_id=self.connection_id,
                retained_outbox=failed,
            )

    def _wrap(self, event_id: str, canonical_bytes: bytes) -> bytes:
        header = f"conn:{self.connection_id}:event:{event_id}:".encode("utf-8")
        return header + canonical_bytes
