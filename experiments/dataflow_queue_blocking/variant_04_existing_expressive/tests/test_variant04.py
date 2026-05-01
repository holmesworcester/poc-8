from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from variant04.control_loop import ControlLoop, WorkBudget
from variant04.event_modules.content_message import codec as message_codec
from variant04.event_modules.content_user import codec as user_codec
from variant04.event_modules.sync_need import codec as need_codec
from variant04.events import event_id_for
from variant04.registry import build_registry
from variant04.sender import ConnectionSender
from variant04.state import StateStore
from variant04.trace import Trace


def new_system() -> tuple[Trace, StateStore, ControlLoop]:
    trace = Trace()
    registry = build_registry()
    store = StateStore(registry.catalog, trace=trace)
    loop = ControlLoop(registry, store, trace)
    loop.seed_open_connection(
        connection_id="conn-a",
        remote_endpoint_id="endpoint-b",
        shared_workspaces=("workspace-1",),
        now_ms=1_000,
    )
    return trace, store, loop


def apply_user(loop: ControlLoop, user_bytes: bytes) -> str:
    event_id = event_id_for(user_bytes)
    loop.enqueue_inbound(user_bytes, origin_connection_id="conn-a")
    loop.run_once(WorkBudget(inbound_bytes=1))
    return event_id


def apply_message(loop: ControlLoop, message_bytes: bytes) -> str:
    event_id = event_id_for(message_bytes)
    loop.enqueue_inbound(message_bytes, origin_connection_id="conn-a")
    loop.run_once(WorkBudget(inbound_bytes=1, ready_events=1))
    return event_id


class Variant04Tests(unittest.TestCase):
    def test_inbound_message_blocks_then_dependency_unblocks_in_same_transaction(self) -> None:
        trace, store, loop = new_system()
        user_bytes = user_codec.encode("workspace-1", "user-1", "Ada", 1_010)
        user_event_id = event_id_for(user_bytes)
        message_bytes = message_codec.encode(
            "workspace-1",
            "msg-1",
            "user-1",
            "hello from a blocked event",
            user_event_id,
            1_020,
        )
        message_event_id = event_id_for(message_bytes)

        loop.enqueue_inbound(message_bytes, origin_connection_id="conn-a")
        loop.run_once(WorkBudget(inbound_bytes=1))

        self.assertEqual(store.get("events", (message_event_id,))["status"], "blocked")
        self.assertEqual(
            store.get("blocked_by_event", (user_event_id, message_event_id))["event_id"],
            message_event_id,
        )

        loop.enqueue_inbound(user_bytes, origin_connection_id="conn-a")
        loop.run_once(WorkBudget(inbound_bytes=1))

        self.assertEqual(store.get("events", (user_event_id,))["status"], "applied")
        self.assertEqual(store.get("events", (message_event_id,))["status"], "ready")
        self.assertIsNone(store.get("blocked_by_event", (user_event_id, message_event_id)))

        unblock_entries = trace.steps("event.unblocked_ready")
        self.assertEqual(len(unblock_entries), 1)
        user_apply_entries = [
            entry
            for entry in trace.steps("event.applied")
            if entry.detail["event_id"] == user_event_id
        ]
        self.assertEqual(unblock_entries[0].tx, user_apply_entries[0].tx)

        loop.run_once(WorkBudget(ready_events=1))

        self.assertEqual(store.get("events", (message_event_id,))["status"], "applied")
        self.assertEqual(
            store.get("messages", ("workspace-1", "msg-1"))["author_event_id"],
            user_event_id,
        )

    def test_ready_work_is_bounded_and_not_recursively_drained(self) -> None:
        _trace, store, loop = new_system()
        user_bytes = user_codec.encode("workspace-1", "user-1", "Ada", 1_010)
        user_event_id = event_id_for(user_bytes)
        messages = [
            message_codec.encode(
                "workspace-1",
                f"msg-{index}",
                "user-1",
                f"blocked {index}",
                user_event_id,
                1_020 + index,
            )
            for index in (1, 2)
        ]
        message_ids = [event_id_for(item) for item in messages]

        for message in messages:
            loop.enqueue_inbound(message, origin_connection_id="conn-a")
        loop.run_once(WorkBudget(inbound_bytes=2))
        self.assertEqual(
            [store.get("events", (event_id,))["status"] for event_id in message_ids],
            ["blocked", "blocked"],
        )

        loop.enqueue_inbound(user_bytes, origin_connection_id="conn-a")
        loop.run_once(WorkBudget(inbound_bytes=1))
        self.assertEqual(
            [store.get("events", (event_id,))["status"] for event_id in message_ids],
            ["ready", "ready"],
        )
        self.assertEqual(store.rows("messages"), [])

        loop.run_once(WorkBudget(ready_events=1))
        statuses = [store.get("events", (event_id,))["status"] for event_id in message_ids]
        self.assertEqual(statuses.count("applied"), 1)
        self.assertEqual(statuses.count("ready"), 1)
        self.assertEqual(len(store.rows("messages")), 1)

    def test_invalid_inbound_bytes_stop_before_event_admission(self) -> None:
        trace, store, loop = new_system()
        wire_id = loop.enqueue_inbound(b'{"event_type":42,"payload":{}}', origin_connection_id="conn-a")

        loop.run_once(WorkBudget(inbound_bytes=1))

        self.assertEqual(store.get("inbound_bytes", (wire_id,))["status"], "invalid")
        self.assertEqual(store.rows("events"), [])
        self.assertEqual(len(trace.steps("inbound.invalid")), 1)

    def test_need_event_queues_outbox_and_sender_refill_respects_byte_budget(self) -> None:
        trace, store, loop = new_system()
        user_bytes = user_codec.encode("workspace-1", "user-1", "Ada", 1_010)
        user_event_id = apply_user(loop, user_bytes)
        message_bytes = message_codec.encode(
            "workspace-1",
            "msg-1",
            "user-1",
            "send this event",
            user_event_id,
            1_020,
        )
        message_event_id = apply_message(loop, message_bytes)

        need_user_bytes = need_codec.encode("conn-a", "workspace-1", user_event_id, 1_030)
        need_message_bytes = need_codec.encode("conn-a", "workspace-1", message_event_id, 1_031)
        loop.enqueue_inbound(need_user_bytes, origin_connection_id="conn-a")
        loop.enqueue_inbound(need_message_bytes, origin_connection_id="conn-a")
        loop.run_once(WorkBudget(inbound_bytes=2))

        self.assertEqual(len(store.rows("outbox")), 2)

        sender = ConnectionSender("conn-a", store, trace)
        first_frame_budget = len(sender._wrap(user_event_id, user_bytes)) + 1
        loaded = sender.refill(byte_budget=first_frame_budget, max_events=16)
        self.assertEqual(loaded, 1)
        self.assertEqual(len(sender.hot_queue), 1)
        self.assertEqual(len(store.rows("outbox")), 2)

        sent = sender.flush_success(max_frames=1)
        self.assertEqual(sent, [user_event_id])
        self.assertIsNone(store.get("outbox", ("conn-a", user_event_id)))
        self.assertIsNotNone(store.get("outbox", ("conn-a", message_event_id)))
        self.assertEqual(len(trace.steps("sender.refilled")), 1)
        self.assertEqual(len(trace.steps("sender.sent")), 1)


if __name__ == "__main__":
    unittest.main()
