"""Small structured trace used by the demo and tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TraceEntry:
    tx: int | None
    step: str
    detail: dict[str, Any]


class Trace:
    def __init__(self) -> None:
        self.entries: list[TraceEntry] = []

    def record(self, step: str, tx: int | None = None, **detail: Any) -> None:
        self.entries.append(TraceEntry(tx=tx, step=step, detail=detail))

    def steps(self, step: str) -> list[TraceEntry]:
        return [entry for entry in self.entries if entry.step == step]

    def tx_steps(self, tx: int) -> list[TraceEntry]:
        return [entry for entry in self.entries if entry.tx == tx]

    def render(self) -> str:
        lines = []
        for entry in self.entries:
            tx = "-" if entry.tx is None else str(entry.tx)
            fields = " ".join(f"{key}={value}" for key, value in sorted(entry.detail.items()))
            lines.append(f"tx={tx} {entry.step} {fields}".rstrip())
        return "\n".join(lines)
