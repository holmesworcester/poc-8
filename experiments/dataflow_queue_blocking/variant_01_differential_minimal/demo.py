"""Differential-minimal queue blocking demo.

The model is intentionally small: mutable state is only the input collections
(`inbound`, `facts`). Everything queue-like is derived with antijoins and
semijoins over arrangements.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, TypeVar


T = TypeVar("T")
K = TypeVar("K")


@dataclass(frozen=True, order=True)
class InboundEvent:
    event_id: str
    deps: tuple[str, ...]
    connection_id: str = "peer-1"


@dataclass(frozen=True, order=True)
class DepEdge:
    event_id: str
    required_fact_id: str


@dataclass(frozen=True, order=True)
class OutboxRow:
    connection_id: str
    event_id: str


@dataclass(frozen=True)
class Delta:
    inbound: tuple[tuple[InboundEvent, int], ...] = ()
    facts: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True)
class Store:
    inbound: Counter[InboundEvent] = field(default_factory=Counter)
    facts: Counter[str] = field(default_factory=Counter)


@dataclass(frozen=True)
class Snapshot:
    parsed: tuple[InboundEvent, ...]
    dep_edges: tuple[DepEdge, ...]
    missing_deps: tuple[DepEdge, ...]
    blocked: tuple[InboundEvent, ...]
    ready: tuple[InboundEvent, ...]
    outbox: tuple[OutboxRow, ...]


@dataclass(frozen=True)
class TraceStep:
    label: str
    snapshot: Snapshot
    missing_delta: tuple[tuple[DepEdge, int], ...]
    blocked_delta: tuple[tuple[InboundEvent, int], ...]
    ready_delta: tuple[tuple[InboundEvent, int], ...]
    outbox_delta: tuple[tuple[OutboxRow, int], ...]


def event(event_id: str, deps: Iterable[str], connection_id: str = "peer-1") -> InboundEvent:
    """Create a stable event row; dependency order is not semantic."""

    return InboundEvent(event_id, tuple(sorted(deps)), connection_id)


def apply_delta(store: Store, delta: Delta) -> Store:
    inbound = store.inbound.copy()
    facts = store.facts.copy()
    _apply_weighted_changes(inbound, delta.inbound)
    _apply_weighted_changes(facts, delta.facts)
    return Store(inbound=inbound, facts=facts)


def derive(store: Store) -> Snapshot:
    parsed = _positive_rows(store.inbound)
    facts = _positive_rows(store.facts)

    dep_edges = tuple(
        sorted(
            DepEdge(inbound.event_id, required_fact_id)
            for inbound in parsed
            for required_fact_id in inbound.deps
        )
    )

    facts_by_id = arrange_by(facts, lambda fact_id: fact_id)
    missing_deps = antijoin(
        dep_edges,
        facts_by_id,
        lambda edge: edge.required_fact_id,
    )

    missing_by_event = arrange_by(missing_deps, lambda edge: edge.event_id)
    blocked = semijoin(parsed, missing_by_event, lambda inbound: inbound.event_id)
    ready = antijoin(parsed, missing_by_event, lambda inbound: inbound.event_id)
    outbox = tuple(sorted(OutboxRow(row.connection_id, row.event_id) for row in ready))

    return Snapshot(
        parsed=parsed,
        dep_edges=dep_edges,
        missing_deps=missing_deps,
        blocked=blocked,
        ready=ready,
        outbox=outbox,
    )


def arrange_by(rows: Iterable[T], key: Callable[[T], K]) -> Mapping[K, tuple[T, ...]]:
    arranged: dict[K, list[T]] = defaultdict(list)
    for row in rows:
        arranged[key(row)].append(row)
    return {k: tuple(v) for k, v in arranged.items()}


def semijoin(
    left: Iterable[T],
    right_arrangement: Mapping[K, object],
    key: Callable[[T], K],
) -> tuple[T, ...]:
    return tuple(sorted(row for row in left if key(row) in right_arrangement))


def antijoin(
    left: Iterable[T],
    right_arrangement: Mapping[K, object],
    key: Callable[[T], K],
) -> tuple[T, ...]:
    return tuple(sorted(row for row in left if key(row) not in right_arrangement))


def worked_trace() -> tuple[TraceStep, ...]:
    store = apply_delta(Store(), Delta(facts=(("workspace:W", +1),)))
    previous = derive(store)
    steps: list[TraceStep] = []

    for label, delta in (
        (
            "t1 +inbound(A,B,C)",
            Delta(
                inbound=(
                    (event("A", ["workspace:W"]), +1),
                    (event("B", ["event:A"]), +1),
                    (event("C", ["event:B"]), +1),
                )
            ),
        ),
        ("t2 +fact(event:A)", Delta(facts=(("event:A", +1),))),
        ("t3 +fact(event:B)", Delta(facts=(("event:B", +1),))),
    ):
        store = apply_delta(store, delta)
        current = derive(store)
        steps.append(_trace_step(label, previous, current))
        previous = current

    return tuple(steps)


def _trace_step(label: str, previous: Snapshot, current: Snapshot) -> TraceStep:
    return TraceStep(
        label=label,
        snapshot=current,
        missing_delta=_collection_delta(previous.missing_deps, current.missing_deps),
        blocked_delta=_collection_delta(previous.blocked, current.blocked),
        ready_delta=_collection_delta(previous.ready, current.ready),
        outbox_delta=_collection_delta(previous.outbox, current.outbox),
    )


def _collection_delta(before: Iterable[T], after: Iterable[T]) -> tuple[tuple[T, int], ...]:
    counts = Counter(after)
    counts.subtract(Counter(before))
    return tuple(sorted((row, diff) for row, diff in counts.items() if diff))


def _positive_rows(counter: Counter[T]) -> tuple[T, ...]:
    return tuple(sorted(row for row, weight in counter.items() if weight > 0))


def _apply_weighted_changes(counter: Counter[T], changes: Iterable[tuple[T, int]]) -> None:
    for row, diff in changes:
        next_weight = counter[row] + diff
        if next_weight < 0:
            raise ValueError(f"negative collection weight for {row!r}")
        if next_weight == 0:
            counter.pop(row, None)
        else:
            counter[row] = next_weight


def _format_delta(rows: Iterable[tuple[object, int]]) -> str:
    parts = []
    for row, diff in rows:
        sign = "+" if diff > 0 else ""
        parts.append(f"{sign}{diff} {row}")
    return ", ".join(parts) if parts else "(no change)"


def main() -> None:
    print("Differential-minimal queue blocking trace")
    for step in worked_trace():
        print(f"\n{step.label}")
        print(f"  missing_deps delta: {_format_delta(step.missing_delta)}")
        print(f"  blocked delta:      {_format_delta(step.blocked_delta)}")
        print(f"  ready delta:        {_format_delta(step.ready_delta)}")
        print(f"  outbox delta:       {_format_delta(step.outbox_delta)}")
        print(f"  ready snapshot:     {[row.event_id for row in step.snapshot.ready]}")
        print(f"  blocked snapshot:   {[row.event_id for row in step.snapshot.blocked]}")


if __name__ == "__main__":
    main()
