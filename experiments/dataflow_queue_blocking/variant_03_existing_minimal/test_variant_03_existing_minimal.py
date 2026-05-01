#!/usr/bin/env python3
"""Tests for Variant 03: Existing-minimal."""

from __future__ import annotations

import unittest

import demo


class ExistingMinimalVariantTest(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = demo.connect()
        self.ids = demo.seed_out_of_order_dependency_scenario(self.conn)

    def tearDown(self) -> None:
        self.conn.close()

    def status(self, name: str) -> str:
        row = self.conn.execute(
            "SELECT status FROM events WHERE event_id = ?",
            (self.ids[name],),
        ).fetchone()
        self.assertIsNotNone(row)
        return row["status"]

    def test_out_of_order_dependencies_unblock_without_recursive_apply(self) -> None:
        first_results = demo.process_inbound_batch(self.conn, limit=2, now_ms=100)
        self.assertEqual([result.wire_id for result in first_results], ["wire-C", "wire-B"])
        self.assertEqual(self.status("C"), "blocked")
        self.assertEqual(self.status("B"), "blocked")
        self.assertEqual(
            set(demo.fetch_blockers(self.conn)),
            {(self.ids["B"], self.ids["C"]), (self.ids["A"], self.ids["B"])},
        )
        self.assertEqual(demo.apply_ready_batch(self.conn, limit=1, now_ms=110), [])

        second_results = demo.process_inbound_batch(self.conn, limit=2, now_ms=200)
        self.assertEqual([result.wire_id for result in second_results], ["wire-A"])
        self.assertEqual(self.status("A"), "ready")

        self.assertEqual(demo.apply_ready_batch(self.conn, limit=1, now_ms=210), [self.ids["A"]])
        self.assertEqual(self.status("A"), "applied")
        self.assertEqual(self.status("B"), "ready")
        self.assertEqual(self.status("C"), "blocked")
        self.assertEqual(demo.fetch_blockers(self.conn), [(self.ids["B"], self.ids["C"])])

        self.assertEqual(demo.apply_ready_batch(self.conn, limit=1, now_ms=220), [self.ids["B"]])
        self.assertEqual(self.status("B"), "applied")
        self.assertEqual(self.status("C"), "ready")
        self.assertEqual(demo.fetch_blockers(self.conn), [])

        self.assertEqual(demo.apply_ready_batch(self.conn, limit=1, now_ms=230), [self.ids["C"]])
        self.assertEqual(
            {name: self.status(name) for name in ("A", "B", "C")},
            {"A": "applied", "B": "applied", "C": "applied"},
        )
        self.assertEqual(
            demo.fetch_outbox(self.conn),
            [
                ("conn-peer", self.ids["A"]),
                ("conn-peer", self.ids["B"]),
                ("conn-peer", self.ids["C"]),
            ],
        )

    def test_duplicate_inbound_stops_before_second_projection(self) -> None:
        demo.process_inbound_batch(self.conn, limit=3, now_ms=100)
        while demo.apply_ready_batch(self.conn, limit=1, now_ms=200):
            pass

        a_bytes = self.conn.execute(
            "SELECT canonical_event_bytes FROM events WHERE event_id = ?",
            (self.ids["A"],),
        ).fetchone()["canonical_event_bytes"]
        demo.ingest_inbound(self.conn, wire_id="wire-A-duplicate", canonical_event_bytes=a_bytes, now_ms=400)
        result = demo.process_inbound_batch(self.conn, limit=1, now_ms=410)[0]

        self.assertEqual(result.event_status, "duplicate")
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) AS n FROM content_messages WHERE event_id = ?",
                (self.ids["A"],),
            ).fetchone()["n"],
            1,
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) AS n FROM outbox WHERE event_id = ?",
                (self.ids["A"],),
            ).fetchone()["n"],
            1,
        )

    def test_sender_hot_queue_refill_is_bounded_by_estimated_bytes(self) -> None:
        demo.process_inbound_batch(self.conn, limit=3, now_ms=100)
        while demo.apply_ready_batch(self.conn, limit=1, now_ms=200):
            pass
        while demo.apply_ready_batch(self.conn, limit=1, now_ms=300):
            pass

        first_event_bytes = self.conn.execute(
            """
            SELECT e.canonical_event_bytes
              FROM outbox AS o
              JOIN events AS e ON e.event_id = o.event_id
             WHERE o.connection_id = 'conn-peer'
             ORDER BY o.queued_at_ms, o.event_id
             LIMIT 1
            """
        ).fetchone()["canonical_event_bytes"]
        one_frame_budget = len(first_event_bytes) + 4

        hot_queue = demo.refill_hot_queue(
            self.conn,
            connection_id="conn-peer",
            byte_budget=one_frame_budget,
        )
        self.assertEqual(len(hot_queue), 1)
        self.assertLessEqual(sum(len(event_bytes) + 4 for _, event_bytes in hot_queue), one_frame_budget)

        skipped = demo.refill_hot_queue(
            self.conn,
            connection_id="conn-peer",
            byte_budget=10_000,
            present=[event_id for event_id, _ in hot_queue],
        )
        self.assertEqual(
            set(event_id for event_id, _ in skipped),
            {self.ids["A"], self.ids["B"], self.ids["C"]} - {event_id for event_id, _ in hot_queue},
        )


if __name__ == "__main__":
    unittest.main()
