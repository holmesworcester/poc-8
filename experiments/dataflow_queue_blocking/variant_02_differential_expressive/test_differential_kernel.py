import pathlib
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from differential_kernel import DifferentialQueueKernel, EventFact, dependency_cascade_demo


class DifferentialKernelTests(unittest.TestCase):
    def test_dependency_cascade_respects_one_event_of_fuel(self) -> None:
        kernel = DifferentialQueueKernel()
        kernel.ingest_batch(connections=[("conn-1", "w")])
        kernel.ingest_batch(
            events=[
                EventFact("D", "w", ("C",)),
                EventFact("C", "w", ("B",)),
                EventFact("B", "w", ("A",)),
            ]
        )

        self.assertEqual(
            kernel.blocked_by_event,
            {("A", "B"), ("B", "C"), ("C", "D")},
        )
        self.assertEqual(
            kernel.statuses(),
            {"B": "blocked", "C": "blocked", "D": "blocked"},
        )

        kernel.ingest_batch(events=[EventFact("A", "w")])
        self.assertEqual(kernel.status("A"), "ready")

        first = kernel.tick(fuel=1)
        self.assertEqual(first.processed, ("A",))
        self.assertEqual(first.fuel_remaining, 0)
        self.assertEqual(kernel.status("B"), "ready")
        self.assertEqual(kernel.status("C"), "blocked")
        self.assertEqual(kernel.status("D"), "blocked")
        self.assertIn(("A", "B"), {(row.key[0], row.key[1]) for row in kernel.trace if row.collection == "unblock"})
        self.assertIn(("conn-1", "A"), kernel.outbox)

        second = kernel.tick(fuel=1)
        third = kernel.tick(fuel=1)
        fourth = kernel.tick(fuel=1)

        self.assertEqual(second.processed, ("B",))
        self.assertEqual(third.processed, ("C",))
        self.assertEqual(fourth.processed, ("D",))
        self.assertEqual(kernel.statuses(), {event_id: "applied" for event_id in "ABCD"})
        self.assertEqual(
            kernel.outbox,
            {("conn-1", event_id) for event_id in "ABCD"},
        )
        self.assertEqual(kernel.frontier.pending_event_count, 0)

    def test_dependency_presence_does_not_satisfy_until_applied(self) -> None:
        kernel = DifferentialQueueKernel()
        kernel.ingest_batch(
            events=[
                EventFact("child", "w", ("root",)),
                EventFact("root", "w"),
            ]
        )

        self.assertEqual(kernel.status("root"), "ready")
        self.assertEqual(kernel.status("child"), "blocked")
        self.assertEqual(kernel.blocked_by_event, {("root", "child")})

        result = kernel.tick(fuel=2)

        self.assertEqual(result.processed, ("root", "child"))
        self.assertEqual(kernel.status("child"), "applied")
        self.assertIn(
            ("root", "child"),
            {(row.key[0], row.key[1]) for row in kernel.trace if row.collection == "unblock"},
        )

    def test_outbox_is_deduped_and_reacts_to_late_connection_fact(self) -> None:
        kernel = DifferentialQueueKernel()
        event = EventFact("A", "w")
        kernel.ingest_batch(events=[event])
        kernel.tick(fuel=1)

        self.assertEqual(kernel.outbox, set())

        kernel.ingest_batch(events=[event], connections=[("conn-1", "w")])
        self.assertEqual(kernel.outbox, {("conn-1", "A")})

        kernel.ingest_batch(events=[event], connections=[("conn-1", "w")])
        self.assertEqual(kernel.outbox, {("conn-1", "A")})
        self.assertEqual(
            [row for row in kernel.trace if row.collection == "outbox" and row.diff == 1],
            [row for row in kernel.trace if row.collection == "outbox"],
        )

    def test_demo_trace_reaches_expected_cascade_shape(self) -> None:
        kernel, summaries = dependency_cascade_demo(fuel_per_tick=1)

        labels = [summary["label"] for summary in summaries]
        self.assertEqual(
            labels,
            [
                "connect conn-alpha to workspace-main",
                "ingest dependent tail before root",
                "ingest root",
                "tick 1",
                "tick 2",
                "tick 3",
                "tick 4",
            ],
        )
        self.assertEqual(kernel.statuses(), {event_id: "applied" for event_id in "ABCD"})
        self.assertEqual(
            kernel.arrangements()["outbox_by_connection"],
            {"conn-alpha": ("A", "B", "C", "D")},
        )


if __name__ == "__main__":
    unittest.main()
