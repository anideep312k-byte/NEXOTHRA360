"""Tor exit node detection with cached refresh. Public data."""
from __future__ import annotations
import logging
import threading
import time
import requests
from .base import EnrichmentProvider, EnrichmentResult

log = logging.getLogger("kavach360.enrichment.tor")
_LIST_URL = "https://check.torproject.org/torbulkexitlist"
_REFRESH_SECONDS = 3600


class TorExitProvider(EnrichmentProvider):
    name = "tor_exit"

    def __init__(self) -> None:
        self._ips: set[str] = set()
        self._loaded_at = 0.0
        self._lock = threading.Lock()

    def _refresh(self) -> None:
        with self._lock:
            if time.time() - self._loaded_at < _REFRESH_SECONDS:
                return
            try:
                r = requests.get(_LIST_URL, timeout=10)
                r.raise_for_status()
                self._ips = set(r.text.splitlines())
                self._loaded_at = time.time()
            except Exception as exc:
                log.warning("Tor list refresh failed: %s", exc)

    def enrich(self, value: str, kind: str) -> EnrichmentResult | None:
        if kind != "ip":
            return None
        self._refresh()
        return EnrichmentResult(self.name, kind, value,
                                data={"is_tor_exit": value in self._ips,
                                      "total_known": len(self._ips)})
