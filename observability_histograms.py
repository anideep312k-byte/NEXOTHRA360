"""
Histogram extension for the Prometheus exposition output.

This module is imported by observability.py to add histogram support
without a circular import. It is intentionally small and stdlib-only.

A histogram is a list of monotonically increasing bucket upper bounds
(the last is +Inf implicitly). Each observation increments one bucket
(the smallest upper bound >= the value) plus the +Inf bucket. We also
track _count and _sum.

Reference: Prometheus exposition format, public specification.
No Prometheus source code is copied.
"""
from __future__ import annotations
import math
import threading
from typing import Dict, Iterable, List, Tuple


DEFAULT_LATENCY_BUCKETS = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
                           0.5, 1.0, 2.5, 5.0, 10.0)


class Histogram:
    """
    Thread-safe histogram with fixed bucket boundaries.

    Buckets: tuple of float upper bounds, monotonically increasing.
    The +Inf bucket is implicit and always present.
    """

    def __init__(self, name: str, buckets: Iterable[float],
                 help_text: str = "", labels: Dict[str, str] = None) -> None:
        bs = tuple(sorted(set(float(b) for b in buckets)))
        if not bs:
            raise ValueError("histogram requires at least one bucket bound")
        self.name = name
        self.buckets: Tuple[float, ...] = bs
        self.help_text = help_text
        self.labels = dict(labels or {})
        self._counts: List[int] = [0] * (len(bs) + 1)  # last is +Inf
        self._count: int = 0
        self._sum: float = 0.0
        self._lock = threading.Lock()

    def observe(self, value: float) -> None:
        v = float(value)
        if math.isnan(v):
            return
        with self._lock:
            for i, bound in enumerate(self.buckets):
                if v <= bound:
                    self._counts[i] += 1
                    break
            else:
                self._counts[-1] += 1
            self._count += 1
            self._sum += v

    def snapshot(self) -> Tuple[List[int], int, float]:
        with self._lock:
            return list(self._counts), self._count, self._sum


_HISTOGRAMS: Dict[str, Histogram] = {}
_HIST_LOCK = threading.Lock()


def get_histogram(name: str, buckets: Iterable[float] = None,
                  help_text: str = "") -> Histogram:
    """Return or create the named histogram. Thread-safe."""
    with _HIST_LOCK:
        h = _HISTOGRAMS.get(name)
        if h is None:
            b = buckets if buckets is not None else DEFAULT_LATENCY_BUCKETS
            h = Histogram(name, b, help_text)
            _HISTOGRAMS[name] = h
        return h


def all_histograms() -> Dict[str, Histogram]:
    with _HIST_LOCK:
        return dict(_HISTOGRAMS)


def _sanitize_name(name: str) -> str:
    out = []
    for ch in name:
        if ch.isalnum() or ch == "_":
            out.append(ch)
        else:
            out.append("_")
    if not out or not (out[0].isalpha() or out[0] == "_"):
        out.insert(0, "_")
    s = "".join(out)
    if not s.startswith("kavach_"):
        s = "kavach_" + s
    return s


def _format_bound(b: float) -> str:
    if math.isinf(b):
        return "+Inf"
    # use shortest representation
    return repr(float(b))


def render_histograms() -> str:
    """
    Render every registered histogram in Prometheus text exposition
    format. Produces three lines per histogram: _bucket, _count, _sum.
    """
    lines: List[str] = []
    for name, h in sorted(all_histograms().items()):
        base = _sanitize_name(name)
        lines.append(f"# HELP {base} {h.help_text or 'Histogram'}")
        lines.append(f"# TYPE {base} histogram")
        counts, count, total = h.snapshot()
        cumulative = 0
        for i, bound in enumerate(h.buckets):
            cumulative += counts[i]
            lines.append(f"{base}_bucket{{le=\"{_format_bound(bound)}\"}} {cumulative}")
        cumulative += counts[-1]
        lines.append(f"{base}_bucket{{le=\"+Inf\"}} {cumulative}")
        lines.append(f"{base}_count {count}")
        lines.append(f"{base}_sum {total!r}")
    return "\n".join(lines) + ("\n" if lines else "")


# KAVACH360-patch-s14a-applied
# Session 14 — instrumentation helpers shared by the main file
# and the postgres backend. Both are best-effort and never raise.
def observe_pg_write(seconds: float) -> None:
    try:
        get_histogram(
            "postgres_write_seconds",
            help_text="PostgresStorage operation duration",
        ).observe(seconds)
    except Exception:
        pass


def observe_bus_op(op: str, seconds: float) -> None:
    try:
        get_histogram(
            f"bus_{op}_seconds",
            help_text=f"DurableBus.{op} duration",
        ).observe(seconds)
    except Exception:
        pass
