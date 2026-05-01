from __future__ import annotations

from variant04.control_loop import ControlLoop, WorkBudget
from variant04.event_modules.content_message import codec as message_codec
from variant04.event_modules.content_user import codec as user_codec
from variant04.event_modules.sync_need import codec as need_codec
from variant04.events import event_id_for
from variant04.registry import build_registry
from variant04.sender import ConnectionSender
from variant04.state import StateStore
from variant04.trace import Trace


def main() -> None:
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

    user_bytes = user_codec.encode("workspace-1", "user-1", "Ada", 1_010)
    user_event_id = event_id_for(user_bytes)
    message_bytes = message_codec.encode(
        "workspace-1",
        "msg-1",
        "user-1",
        "message arrives before author dependency",
        user_event_id,
        1_020,
    )
    message_event_id = event_id_for(message_bytes)

    loop.enqueue_inbound(message_bytes, origin_connection_id="conn-a")
    loop.run_once(WorkBudget(inbound_bytes=1))

    loop.enqueue_inbound(user_bytes, origin_connection_id="conn-a")
    loop.run_once(WorkBudget(inbound_bytes=1))
    loop.run_once(WorkBudget(ready_events=1))

    need_bytes = need_codec.encode("conn-a", "workspace-1", message_event_id, 1_030)
    loop.enqueue_inbound(need_bytes, origin_connection_id="conn-a")
    loop.run_once(WorkBudget(inbound_bytes=1))

    sender = ConnectionSender("conn-a", store, trace)
    sender.refill(byte_budget=512)
    sender.flush_success(max_frames=1)

    print("Variant 4: existing-expressive trace")
    print("------------------------------------")
    print(trace.render())
    print()
    print("Final rows")
    print("----------")
    print(f"message event: {store.get('events', (message_event_id,))}")
    print(f"message row:   {store.get('messages', ('workspace-1', 'msg-1'))}")
    print(f"outbox rows:   {store.rows('outbox')}")


if __name__ == "__main__":
    main()
