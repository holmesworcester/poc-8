import unittest

from demo import Delta, OutboxRow, Store, apply_delta, derive, event, worked_trace


class DifferentialMinimalDemoTests(unittest.TestCase):
    def test_worked_trace_unblocks_events_as_facts_arrive(self) -> None:
        steps = worked_trace()

        self.assertEqual([row.event_id for row, diff in steps[0].blocked_delta if diff > 0], ["B", "C"])
        self.assertEqual([row.event_id for row, diff in steps[0].ready_delta if diff > 0], ["A"])
        self.assertEqual(steps[0].outbox_delta, ((OutboxRow("peer-1", "A"), +1),))

        self.assertEqual([row.event_id for row, diff in steps[1].blocked_delta], ["B"])
        self.assertEqual(steps[1].blocked_delta[0][1], -1)
        self.assertEqual([row.event_id for row, diff in steps[1].ready_delta if diff > 0], ["B"])
        self.assertEqual(steps[1].outbox_delta, ((OutboxRow("peer-1", "B"), +1),))

        self.assertEqual([row.event_id for row, diff in steps[2].blocked_delta], ["C"])
        self.assertEqual(steps[2].blocked_delta[0][1], -1)
        self.assertEqual([row.event_id for row, diff in steps[2].ready_delta if diff > 0], ["C"])
        self.assertEqual(steps[2].outbox_delta, ((OutboxRow("peer-1", "C"), +1),))
        self.assertEqual([row.event_id for row in steps[2].snapshot.ready], ["A", "B", "C"])

    def test_event_is_blocked_until_all_dependencies_are_facts(self) -> None:
        store = Store()
        store = apply_delta(
            store,
            Delta(
                inbound=((event("D", ["event:A", "event:B"]), +1),),
                facts=(("event:A", +1),),
            ),
        )
        snapshot = derive(store)

        self.assertEqual([row.event_id for row in snapshot.blocked], ["D"])
        self.assertEqual(snapshot.ready, ())
        self.assertEqual([edge.required_fact_id for edge in snapshot.missing_deps], ["event:B"])

        snapshot = derive(apply_delta(store, Delta(facts=(("event:B", +1),))))
        self.assertEqual(snapshot.blocked, ())
        self.assertEqual([row.event_id for row in snapshot.ready], ["D"])
        self.assertEqual(snapshot.outbox, (OutboxRow("peer-1", "D"),))

    def test_unrelated_fact_does_not_create_outbox_delta(self) -> None:
        store = apply_delta(
            Store(),
            Delta(
                inbound=((event("B", ["event:A"]), +1),),
                facts=(("workspace:W", +1),),
            ),
        )
        before = derive(store)
        after = derive(apply_delta(store, Delta(facts=(("event:Z", +1),))))

        self.assertEqual(before.blocked, after.blocked)
        self.assertEqual(before.ready, after.ready)
        self.assertEqual(before.outbox, after.outbox)

    def test_negative_collection_weight_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            apply_delta(Store(), Delta(facts=(("missing", -1),)))


if __name__ == "__main__":
    unittest.main()
