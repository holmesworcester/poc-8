from __future__ import annotations

import tempfile
import unittest

from hybrid_arrangements_demo import Event, HybridKernel


class HybridArrangementDemoTests(unittest.TestCase):
    def open_kernel(self) -> tuple[tempfile.TemporaryDirectory[str], HybridKernel]:
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        kernel = HybridKernel.open(f"{tempdir.name}/kernel.sqlite3")
        self.addCleanup(kernel.close)
        return tempdir, kernel

    def parent_and_child(self) -> tuple[Event, Event]:
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
        return parent, child

    def test_child_blocks_then_parent_unblocks_and_projects_both_events(self) -> None:
        _, kernel = self.open_kernel()
        parent, child = self.parent_and_child()

        child_trace = kernel.ingest(child)

        self.assertIn(parent.event_id, kernel.caches.blocked_by_dep)
        self.assertEqual(
            {child.event_id}, kernel.caches.blocked_by_dep[parent.event_id]
        )
        self.assertNotIn("conn-east", kernel.caches.outbox_by_connection)
        self.assertTrue(
            any("missing from events_by_id arrangement" in line for line in child_trace)
        )

        parent_trace = kernel.ingest(parent)

        self.assertNotIn(parent.event_id, kernel.caches.blocked_by_dep)
        self.assertEqual(
            [parent.event_id, child.event_id],
            kernel.caches.outbox_event_ids("conn-east"),
        )
        leaf_event_ids = {
            event_id
            for event_ids in kernel.caches.negentropy_leaves.values()
            for event_id in event_ids
        }
        self.assertEqual({parent.event_id, child.event_id}, leaf_event_ids)
        self.assertTrue(
            any("blocked_by_dep" in line and child.event_id in line for line in parent_trace)
        )

    def test_restart_rebuilds_arrangements_from_committed_sql_rows(self) -> None:
        tempdir, kernel = self.open_kernel()
        parent, child = self.parent_and_child()
        kernel.ingest(child)
        kernel.ingest(parent)
        expected = kernel.caches.snapshot()

        kernel.close()
        restarted = HybridKernel.open(f"{tempdir.name}/kernel.sqlite3")
        self.addCleanup(restarted.close)

        self.assertEqual(expected, restarted.caches.snapshot())

    def test_sender_backpressure_keeps_extra_outbox_rows_durable_until_ack(self) -> None:
        _, kernel = self.open_kernel()
        parent, child = self.parent_and_child()
        kernel.ingest(child)
        kernel.ingest(parent)

        sender = kernel.sender("conn-east", capacity=1)

        self.assertEqual([parent.event_id], sender.refill_from_arrangement())
        self.assertEqual([parent.event_id], sender.memory_event_ids())
        self.assertEqual(
            [parent.event_id, child.event_id],
            kernel.caches.outbox_event_ids("conn-east"),
        )
        self.assertEqual([], sender.refill_from_arrangement())

        frame = sender.on_writable()
        self.assertIsNotNone(frame)
        assert frame is not None
        self.assertEqual(parent.event_id, frame.event_id)
        self.assertEqual([], sender.memory_event_ids())
        self.assertEqual([], sender.refill_from_arrangement())
        self.assertEqual(
            [parent.event_id, child.event_id],
            kernel.caches.outbox_event_ids("conn-east"),
        )

        sender.ack_written(parent.event_id)

        self.assertEqual([child.event_id], kernel.caches.outbox_event_ids("conn-east"))
        self.assertEqual([child.event_id], sender.refill_from_arrangement())
        self.assertEqual([child.event_id], sender.memory_event_ids())

    def test_rolled_back_sql_deltas_do_not_update_arrangements(self) -> None:
        _, kernel = self.open_kernel()
        event = Event.create(
            workspace_id="workspace-alpha",
            event_type="message",
            body="rolled back fact",
            connection_ids=("conn-east",),
        )

        staged_deltas = kernel.stage_then_rollback_for_test(event)

        self.assertEqual(1, len(staged_deltas))
        self.assertNotIn(event.event_id, kernel.caches.events_by_id)
        row_count = kernel.conn.execute(
            "SELECT COUNT(*) FROM events WHERE event_id = ?", (event.event_id,)
        ).fetchone()[0]
        self.assertEqual(0, row_count)


if __name__ == "__main__":
    unittest.main()
