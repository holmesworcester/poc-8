"""Differential-expressive event/fact kernel toy.

The implementation is intentionally small, but the API surface mirrors the
kernel shape this variant is trying to evaluate:

* modules declare collections, arrangements, and rules;
* blocked/ready/outbox are derived collections;
* dependency waiting is an anti-join against applied events;
* bounded work is represented as explicit fuel admitted to a tick.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import DefaultDict, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


Key = Tuple[str, ...]


@dataclass(frozen=True)
class CollectionDecl:
    name: str
    key: Tuple[str, ...]
    storage: str
    doc: str


@dataclass(frozen=True)
class ArrangementDecl:
    name: str
    source: str
    key: Tuple[str, ...]
    doc: str


@dataclass(frozen=True)
class RuleDecl:
    name: str
    output: str
    expression: str
    inputs: Tuple[str, ...]


@dataclass(frozen=True)
class ModuleDecl:
    name: str
    collections: Tuple[CollectionDecl, ...]
    arrangements: Tuple[ArrangementDecl, ...]
    rules: Tuple[RuleDecl, ...]


@dataclass(frozen=True, order=True)
class LogicalTime:
    epoch: int
    iteration: int = 0

    def label(self) -> str:
        return f"{self.epoch}.{self.iteration}"


@dataclass(frozen=True)
class Change:
    time: LogicalTime
    collection: str
    key: Key
    diff: int
    reason: str

    def as_dict(self) -> Mapping[str, object]:
        return {
            "time": self.time.label(),
            "collection": self.collection,
            "key": list(self.key),
            "diff": self.diff,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class EventFact:
    event_id: str
    workspace_id: str
    deps: Tuple[str, ...] = ()
    scope: str = "durable"
    payload: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "deps", tuple(self.deps))


@dataclass(frozen=True)
class Frontier:
    input_epoch: int
    completed_iteration: int
    ready_count: int
    blocked_count: int
    pending_event_count: int


@dataclass(frozen=True)
class TickResult:
    processed: Tuple[str, ...]
    fuel_used: int
    fuel_remaining: int
    frontier: Frontier


def queue_kernel_module() -> ModuleDecl:
    """Return the declarative surface for this variant."""

    return ModuleDecl(
        name="queue_blocking.differential_expressive",
        collections=(
            CollectionDecl(
                "events",
                ("event_id",),
                "durable",
                "Canonical event facts with workspace, scope, and bytes/payload metadata.",
            ),
            CollectionDecl(
                "depends_on",
                ("event_id", "dep_id"),
                "durable",
                "Declared dependency edges extracted from event schema metadata.",
            ),
            CollectionDecl(
                "applied",
                ("event_id",),
                "durable",
                "Events whose projector has committed state updates.",
            ),
            CollectionDecl(
                "connection_workspace",
                ("connection_id", "workspace_id"),
                "memory",
                "Membership facts used by the outbox derivation.",
            ),
            CollectionDecl(
                "fuel_budget",
                ("tick_id",),
                "memory",
                "Control-loop fuel admitted for one bounded step.",
            ),
            CollectionDecl(
                "missing_dep",
                ("dep_id", "event_id"),
                "derived",
                "Dependency edges whose dep_id is not in applied.",
            ),
            CollectionDecl(
                "blocked_by_event",
                ("blocked_by_event_id", "event_id"),
                "derived/durable-boundary",
                "Wait edges used to explain why an event is blocked.",
            ),
            CollectionDecl(
                "blocked",
                ("event_id",),
                "derived",
                "Reduction count of missing deps by blocked event.",
            ),
            CollectionDecl(
                "ready",
                ("event_id",),
                "derived/claimable-boundary",
                "Present events that have no missing dependency and are not applied.",
            ),
            CollectionDecl(
                "unblock",
                ("blocked_by_event_id", "event_id", "time"),
                "derived stream",
                "Edges removed when an applied dependency lets a dependent event proceed.",
            ),
            CollectionDecl(
                "outbox",
                ("connection_id", "event_id"),
                "derived/io-boundary",
                "Deduped send work. A sender owner drains this per connection.",
            ),
        ),
        arrangements=(
            ArrangementDecl(
                "deps_by_event",
                "depends_on",
                ("event_id",),
                "Find all dependencies declared by one event.",
            ),
            ArrangementDecl(
                "deps_by_dep",
                "depends_on",
                ("dep_id",),
                "Find events affected when one dependency changes state.",
            ),
            ArrangementDecl(
                "applied_by_event",
                "applied",
                ("event_id",),
                "Membership test for the anti-join in missing_dep.",
            ),
            ArrangementDecl(
                "blockers_by_dep",
                "blocked_by_event",
                ("blocked_by_event_id",),
                "Find blocked events affected by an applied dependency.",
            ),
            ArrangementDecl(
                "outbox_by_connection",
                "outbox",
                ("connection_id",),
                "Per-connection sender refill arrangement.",
            ),
        ),
        rules=(
            RuleDecl(
                "derive_missing_dep",
                "missing_dep",
                "depends_on(event_id, dep_id).anti_join(applied(dep_id))",
                ("depends_on", "applied"),
            ),
            RuleDecl(
                "derive_blocked_by_event",
                "blocked_by_event",
                "missing_dep(dep_id, event_id)",
                ("missing_dep",),
            ),
            RuleDecl(
                "derive_blocked",
                "blocked",
                "missing_dep(dep_id, event_id).reduce(count by event_id)",
                ("missing_dep",),
            ),
            RuleDecl(
                "derive_ready",
                "ready",
                "events(event_id).anti_join(blocked(event_id)).anti_join(applied(event_id))",
                ("events", "blocked", "applied"),
            ),
            RuleDecl(
                "derive_unblock",
                "unblock",
                "removed(blocked_by_event).join(ready(event_id))",
                ("blocked_by_event", "ready"),
            ),
            RuleDecl(
                "derive_outbox",
                "outbox",
                "applied(event_id).join(events).join(connection_workspace by workspace_id)",
                ("applied", "events", "connection_workspace"),
            ),
        ),
    )


class DifferentialQueueKernel:
    """Small seminaive evaluator for the variant 02 dataflow."""

    DERIVED_COLLECTIONS = (
        "missing_dep",
        "blocked_by_event",
        "blocked",
        "ready",
        "unblock",
        "outbox",
    )

    def __init__(self) -> None:
        self.events: Dict[str, EventFact] = {}
        self.depends_on: Set[Tuple[str, str]] = set()
        self.applied: Set[str] = set()
        self.connection_workspace: Set[Tuple[str, str]] = set()
        self.fuel_budget: Set[Tuple[str, str]] = set()

        self.missing_dep: Set[Tuple[str, str]] = set()
        self.blocked_by_event: Set[Tuple[str, str]] = set()
        self.blocked: Dict[str, int] = {}
        self.ready: Set[str] = set()
        self.unblock: Set[Tuple[str, str, str]] = set()
        self.outbox: Set[Tuple[str, str]] = set()

        self.trace: List[Change] = []
        self.frontier = Frontier(0, 0, 0, 0, 0)
        self._epoch = 0
        self._snapshots: Dict[str, Set[Key]] = {
            name: set() for name in self.DERIVED_COLLECTIONS
        }

    def ingest_batch(
        self,
        events: Iterable[EventFact] = (),
        connections: Iterable[Tuple[str, str]] = (),
    ) -> None:
        """Add input facts and advance the dataflow by one input epoch."""

        self._epoch += 1
        time = LogicalTime(self._epoch, 0)

        for connection_id, workspace_id in sorted(set(connections)):
            key = (connection_id, workspace_id)
            if key not in self.connection_workspace:
                self.connection_workspace.add(key)
                self._record(time, "connection_workspace", key, +1, "ingest")

        for event in sorted(events, key=lambda item: item.event_id):
            existing = self.events.get(event.event_id)
            if existing is not None:
                if existing != event:
                    raise ValueError(
                        f"conflicting facts for event_id {event.event_id!r}: "
                        f"{existing!r} != {event!r}"
                    )
                continue

            self.events[event.event_id] = event
            self._record(
                time,
                "events",
                (event.event_id, event.workspace_id, event.scope),
                +1,
                "ingest",
            )
            for dep_id in sorted(set(event.deps)):
                dep_key = (event.event_id, dep_id)
                self.depends_on.add(dep_key)
                self._record(time, "depends_on", dep_key, +1, "ingest")

        self._derive(time, "ingest")

    def tick(self, fuel: int) -> TickResult:
        """Process up to fuel ready events and maintain derived collections."""

        if fuel < 0:
            raise ValueError("fuel must be non-negative")

        self._epoch += 1
        fuel_remaining = fuel
        processed: List[str] = []
        time = LogicalTime(self._epoch, 0)
        tick_id = f"tick-{self._epoch}"
        self.fuel_budget.add((tick_id, str(fuel)))
        self._record(time, "fuel_budget", (tick_id, str(fuel)), +1, "tick")
        self._derive(time, "tick")

        iteration = 0
        while fuel_remaining > 0 and self.ready:
            event_id = sorted(self.ready)[0]
            iteration += 1
            time = LogicalTime(self._epoch, iteration)
            self.applied.add(event_id)
            processed.append(event_id)
            fuel_remaining -= 1
            self._record(time, "applied", (event_id,), +1, "apply")
            self._derive(time, f"apply:{event_id}")

        return TickResult(
            processed=tuple(processed),
            fuel_used=fuel - fuel_remaining,
            fuel_remaining=fuel_remaining,
            frontier=self.frontier,
        )

    def status(self, event_id: str) -> str:
        if event_id in self.applied:
            return "applied"
        if event_id in self.ready:
            return "ready"
        if event_id in self.blocked:
            return "blocked"
        if event_id in self.events:
            return "present"
        return "unknown"

    def statuses(self) -> Mapping[str, str]:
        return {event_id: self.status(event_id) for event_id in sorted(self.events)}

    def arrangements(self) -> Mapping[str, Mapping[str, Tuple[str, ...]]]:
        deps_by_event: DefaultDict[str, List[str]] = defaultdict(list)
        deps_by_dep: DefaultDict[str, List[str]] = defaultdict(list)
        blockers_by_dep: DefaultDict[str, List[str]] = defaultdict(list)
        outbox_by_connection: DefaultDict[str, List[str]] = defaultdict(list)

        for event_id, dep_id in self.depends_on:
            deps_by_event[event_id].append(dep_id)
            deps_by_dep[dep_id].append(event_id)
        for dep_id, event_id in self.blocked_by_event:
            blockers_by_dep[dep_id].append(event_id)
        for connection_id, event_id in self.outbox:
            outbox_by_connection[connection_id].append(event_id)

        return {
            "deps_by_event": self._freeze_index(deps_by_event),
            "deps_by_dep": self._freeze_index(deps_by_dep),
            "blockers_by_dep": self._freeze_index(blockers_by_dep),
            "outbox_by_connection": self._freeze_index(outbox_by_connection),
        }

    def snapshot(self) -> Mapping[str, object]:
        return {
            "frontier": asdict(self.frontier),
            "statuses": dict(self.statuses()),
            "blocked_by_event": [list(row) for row in sorted(self.blocked_by_event)],
            "ready": sorted(self.ready),
            "unblock": [list(row) for row in sorted(self.unblock)],
            "outbox": [list(row) for row in sorted(self.outbox)],
        }

    def _derive(self, time: LogicalTime, reason: str) -> None:
        previous_blocked = set(self.blocked_by_event)

        next_missing: Set[Tuple[str, str]] = set()
        for event_id, event in self.events.items():
            if event_id in self.applied:
                continue
            for dep_id in event.deps:
                if dep_id not in self.applied:
                    next_missing.add((dep_id, event_id))

        blocked_counts: DefaultDict[str, int] = defaultdict(int)
        for _dep_id, event_id in next_missing:
            blocked_counts[event_id] += 1

        next_ready = {
            event_id
            for event_id in self.events
            if event_id not in self.applied and event_id not in blocked_counts
        }

        removed_edges = previous_blocked - next_missing
        for dep_id, event_id in sorted(removed_edges):
            if event_id not in self.applied and event_id in next_ready:
                self.unblock.add((dep_id, event_id, time.label()))

        next_outbox = self._derive_outbox()

        self.missing_dep = next_missing
        self.blocked_by_event = set(next_missing)
        self.blocked = dict(blocked_counts)
        self.ready = next_ready
        self.outbox = next_outbox
        self._emit_derived_diffs(time, reason)
        self.frontier = Frontier(
            input_epoch=self._epoch,
            completed_iteration=time.iteration,
            ready_count=len(self.ready),
            blocked_count=len(self.blocked),
            pending_event_count=len(self.events) - len(self.applied),
        )

    def _derive_outbox(self) -> Set[Tuple[str, str]]:
        rows: Set[Tuple[str, str]] = set()
        for event_id in self.applied:
            event = self.events[event_id]
            if event.scope == "local":
                continue
            for connection_id, workspace_id in self.connection_workspace:
                if workspace_id == event.workspace_id:
                    rows.add((connection_id, event_id))
        return rows

    def _emit_derived_diffs(self, time: LogicalTime, reason: str) -> None:
        views = self._derived_views()
        for collection in self.DERIVED_COLLECTIONS:
            old = self._snapshots[collection]
            new = views[collection]
            for key in sorted(old - new):
                self._record(time, collection, key, -1, reason)
            for key in sorted(new - old):
                self._record(time, collection, key, +1, reason)
            self._snapshots[collection] = set(new)

    def _derived_views(self) -> Mapping[str, Set[Key]]:
        return {
            "missing_dep": set(self.missing_dep),
            "blocked_by_event": set(self.blocked_by_event),
            "blocked": {(event_id, str(count)) for event_id, count in self.blocked.items()},
            "ready": {(event_id,) for event_id in self.ready},
            "unblock": set(self.unblock),
            "outbox": set(self.outbox),
        }

    def _record(
        self,
        time: LogicalTime,
        collection: str,
        key: Sequence[str],
        diff: int,
        reason: str,
    ) -> None:
        self.trace.append(Change(time, collection, tuple(key), diff, reason))

    @staticmethod
    def _freeze_index(index: Mapping[str, Sequence[str]]) -> Mapping[str, Tuple[str, ...]]:
        return {key: tuple(sorted(values)) for key, values in sorted(index.items())}


def dependency_cascade_demo(fuel_per_tick: int = 1) -> Tuple[DifferentialQueueKernel, List[Mapping[str, object]]]:
    kernel = DifferentialQueueKernel()
    summaries: List[Mapping[str, object]] = []

    def add_summary(label: str, result: Optional[TickResult] = None) -> None:
        row: Dict[str, object] = {"label": label}
        if result is not None:
            row["processed"] = list(result.processed)
            row["fuel_used"] = result.fuel_used
            row["fuel_remaining"] = result.fuel_remaining
        row.update(kernel.snapshot())
        summaries.append(row)

    kernel.ingest_batch(connections=[("conn-alpha", "workspace-main")])
    add_summary("connect conn-alpha to workspace-main")

    kernel.ingest_batch(
        events=[
            EventFact("D", "workspace-main", ("C",), payload="publish digest"),
            EventFact("C", "workspace-main", ("B",), payload="build index"),
            EventFact("B", "workspace-main", ("A",), payload="decrypt message"),
        ]
    )
    add_summary("ingest dependent tail before root")

    kernel.ingest_batch(
        events=[EventFact("A", "workspace-main", (), payload="workspace root")]
    )
    add_summary("ingest root")

    for tick_number in range(1, 5):
        result = kernel.tick(fuel_per_tick)
        add_summary(f"tick {tick_number}", result)

    return kernel, summaries


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fuel", type=int, default=1, help="fuel units per cascade tick")
    parser.add_argument(
        "--trace",
        action="store_true",
        help="include the collection diff trace in the JSON output",
    )
    args = parser.parse_args(argv)

    kernel, summaries = dependency_cascade_demo(args.fuel)
    output: Dict[str, object] = {
        "module": asdict(queue_kernel_module()),
        "summaries": summaries,
    }
    if args.trace:
        output["trace"] = [change.as_dict() for change in kernel.trace]
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
