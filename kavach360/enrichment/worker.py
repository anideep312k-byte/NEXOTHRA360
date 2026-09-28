"""Bounded enrichment worker pool."""
from __future__ import annotations
import contextvars
import logging
import random
import signal
import socket
import time
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .queue import EnrichmentQueue
from ..config import config
from ..observability.metrics import (
    ENRICHMENT_QUEUE_DEPTH, ENRICHMENT_WORKER_ACTIVE, WORKER_HEARTBEAT,
)

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","worker":"enrichment","message":"%(message)s"}')
log = logging.getLogger("enrichment_daemon")

_RUNNING = True
_MAX_ATTEMPTS = 3
_CLAIM_INTERVAL = 30.0
_MAX_TRACKED = 10_000

_worker_request_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "worker_request_id", default="")


def _new_request_id() -> str:
    return f"worker-{uuid.uuid4().hex}"


def _stop(signum, frame) -> None:
    global _RUNNING
    _RUNNING = False


class EnrichmentWorker:
    def __init__(self, index: int) -> None:
        self.index = index
        self.consumer = f"enrichment-{socket.gethostname()}-{index}"
        self.attempts: OrderedDict[str, int] = OrderedDict()

    def _bump(self, mid: str) -> int:
        n = self.attempts.get(mid, 0) + 1
        self.attempts[mid] = n
        self.attempts.move_to_end(mid)
        while len(self.attempts) > _MAX_TRACKED:
            self.attempts.popitem(last=False)
        return n

    def _clear(self, mid: str) -> None:
        self.attempts.pop(mid, None)

    def process_one(self, msg_id: str, job: dict[str, Any]) -> None:
        _worker_request_id.set(_new_request_id())
        self._bump(msg_id)
        if job.get("_dlq"):
            EnrichmentQueue.ack(msg_id)
            self._clear(msg_id)
            return
        try:
            alert_id = job.get("alert_id", "?")
            log.info("Enriched alert %s consumer=%s request_id=%s",
                     alert_id, self.consumer, _worker_request_id.get())
            EnrichmentQueue.ack(msg_id)
            self._clear(msg_id)
        except Exception as exc:
            n = self.attempts.get(msg_id, 0)
            log.error("Enrichment failed %s (attempt %d): %s", msg_id, n, exc)
            if n >= _MAX_ATTEMPTS:
                EnrichmentQueue.dead_letter(msg_id, job, str(exc))
                EnrichmentQueue.ack(msg_id)
                self._clear(msg_id)

    def run(self) -> None:
        WORKER_HEARTBEAT.labels(worker=self.consumer).set(time.time())
        ENRICHMENT_WORKER_ACTIVE.inc()
        backoff = 1.0
        last_claim = 0.0
        try:
            while _RUNNING:
                WORKER_HEARTBEAT.labels(worker=self.consumer).set(time.time())
                now = time.time()
                if now - last_claim > _CLAIM_INTERVAL:
                    try:
                        EnrichmentQueue.claim_stuck(self.consumer)
                    except Exception:
                        pass
                    last_claim = now
                try:
                    batch = EnrichmentQueue.fetch_batch(
                        consumer=self.consumer,
                        count=config.ENRICHMENT_BATCH_SIZE,
                        block_ms=2000)
                    ENRICHMENT_QUEUE_DEPTH.set(len(batch))
                    backoff = 1.0
                    for msg_id, job in batch:
                        if not _RUNNING:
                            break
                        self.process_one(msg_id, job)
                except Exception as exc:
                    log.error("Worker %s loop error: %s", self.consumer, exc)
                    time.sleep(backoff + random.uniform(0, 1))
                    backoff = min(backoff * 2, 30)
        finally:
            ENRICHMENT_WORKER_ACTIVE.dec()


def run_worker_pool() -> None:
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    n_workers = config.ENRICHMENT_WORKERS
    log.info("Starting bounded enrichment pool: %d workers (max queue=%d)",
             n_workers, config.ENRICHMENT_QUEUE_MAX)

    workers = [EnrichmentWorker(i) for i in range(n_workers)]
    with ThreadPoolExecutor(max_workers=n_workers,
                            thread_name_prefix="enrichment") as ex:
        futures = [ex.submit(w.run) for w in workers]
        for f in futures:
            try:
                f.result()
            except Exception as exc:
                log.error("Worker crashed: %s", exc)

    log.info("Enrichment pool terminated cleanly")


if __name__ == "__main__":
    run_worker_pool()
