"""
Prometheus-format metrics endpoint helpers.

Produces text in the Prometheus text exposition format (v0.0.4):

    # HELP metric_name description
    # TYPE metric_name counter
    metric_name{label="value"} 42

The counters come from the existing in-memory METRICS object. Queue
depth and a small number of DB-backed gauges are computed on demand
from AppContext. Output is bounded (a fixed set of metric names) and
does not fan out per tenant.

Reference: https://prometheus.io/docs/instrumenting/exposition_formats/
The Prometheus exposition format is a public specification; no code
is copied.
"""
from __future__ import annotations
# KAVACH360-patch-11a-applied
# KAVACH360-patch-10c-obs-applied
from typing import Any, Dict, Iterable, List, Tuple


def _fmt_value(v: Any) -> str:
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        # Prometheus accepts standard float notation.
        return repr(v)
    return str(v)


def _sanitize_metric_name(name: str) -> str:
    """Metric names must match [a-zA-Z_][a-zA-Z0-9_]*.

    Note: Prometheus does NOT allow dots or colons inside the
    metric name portion when it is written without a namespace
    (colons are reserved for recording rules). To be safe for
    any Prometheus version, we restrict to letters, digits, and
    underscore, and replace everything else with "_".
    """
    out = []
    for ch in name:
        if ch.isalnum() or ch == "_":
            out.append(ch)
        else:
            out.append("_")
    if not out or not (out[0].isalpha() or out[0] == "_"):
        out.insert(0, "_")
    return "".join(out)


def _escape_label(v: str) -> str:
    return (str(v).replace("\\", "\\\\")
                  .replace("\"", "\\\"")
                  .replace("\n", "\\n"))


def render_prometheus(counters: Dict[str, int],
                      gauges: Dict[str, float],
                      extra_gauges: Iterable[Tuple[str, str, float, str]] = (),
                      help_map: Dict[str, str] = None,
                      type_map: Dict[str, str] = None) -> str:
    """
    Render a Prometheus exposition block.

    counters: name -> int
    gauges:   name -> number (or bool)
    extra_gauges: iterable of (name, description, value, type_str)
    help_map/type_map: optional overrides for HELP and TYPE lines.

    Metric names are prefixed with `kavach_` if not already prefixed, to
    avoid collisions when scraped into a shared Prometheus.
    """
    help_map = dict(help_map or {})
    type_map = dict(type_map or {})
    lines: List[str] = []
    seen_help: set = set()
    seen_type: set = set()

    def _prefixed(n: str) -> str:
        n = _sanitize_metric_name(n)
        if not n.startswith("kavach_"):
            n = "kavach_" + n
        return n

    def _emit(name: str, value: Any, kind: str, description: str = None):
        full = _prefixed(name)
        if full not in seen_help and (description or name in help_map):
            lines.append(f"# HELP {full} {description or help_map.get(name, '')}")
            seen_help.add(full)
        if full not in seen_type:
            lines.append(f"# TYPE {full} {kind}")
            seen_type.add(full)
        lines.append(f"{full} {_fmt_value(value)}")

    # counters first
    for k, v in sorted(counters.items()):
        if not isinstance(v, (int, float)):
            try:
                v = int(v)
            except Exception:
                continue
        _emit(k, v, "counter", description=help_map.get(k))

    # gauges
    for k, v in sorted(gauges.items()):
        _emit(k, v, "gauge", description=help_map.get(k))

    # extra gauges (from DB or runtime)
    for name, desc, val, kind in extra_gauges:
        _emit(name, val, kind or "gauge", description=desc)

    return "\n".join(lines) + "\n"


def content_type() -> str:
    return "text/plain; version=0.0.4; charset=utf-8"


def render_prometheus_with_histograms(counters, gauges,
                                     extra_gauges=(),
                                     help_map=None, type_map=None) -> str:
    """Render counters, gauges, and registered histograms.

    The histogram portion is provided by observability_histograms.
    If that module is unavailable, falls back to counters and gauges
    only, matching the pre-histogram behavior exactly.
    """
    base = render_prometheus(counters, gauges, extra_gauges=extra_gauges,
                             help_map=help_map, type_map=type_map)
    try:
        from observability_histograms import render_histograms
        hist = render_histograms()
    except Exception:
        hist = ""
    return base + hist
