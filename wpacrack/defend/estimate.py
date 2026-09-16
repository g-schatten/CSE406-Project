"""Crack-time estimator using a measured candidate rate."""

from __future__ import annotations

from dataclasses import dataclass

from ..candidates import MASK_CHARSETS


@dataclass
class Estimate:
    keyspace: int
    rate: float
    worst_seconds: float
    expected_seconds: float
    verdict: str  # WEAK / OK

    def report(self) -> str:
        return (
            f"keyspace={self.keyspace:,}  rate={self.rate:,.0f}/s\n"
            f"  expected (half): {human_time(self.expected_seconds)}\n"
            f"  worst  (full):  {human_time(self.worst_seconds)}\n"
            f"  verdict: {self.verdict}"
        )


def charset_size(name: str) -> int:
    cs = MASK_CHARSETS.get(name)
    return len(cs) if cs else 0


def estimate(charset: str, length: int, rate: float) -> Estimate:
    """charset is a mask token letter (d/l/u/s/a)."""
    size = charset_size(charset)
    keyspace = size ** length if size else 0
    worst = keyspace / rate if rate > 0 else float("inf")
    expected = worst / 2
    verdict = "WEAK" if worst < 365 * 24 * 3600 else "OK"
    return Estimate(keyspace, rate, worst, expected, verdict)


def human_time(seconds: float) -> str:
    if seconds == float("inf"):
        return "infinite"
    units = [("y", 365 * 24 * 3600), ("d", 24 * 3600), ("h", 3600), ("m", 60), ("s", 1)]
    for name, size in units:
        if seconds >= size:
            return f"{seconds / size:.1f}{name}"
    return f"{seconds:.2f}s"
