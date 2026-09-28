from __future__ import annotations
import logging
from typing import Any
from ..broker import get_broker, stream_names
from ..web.security.redis_rate_limit import RedisSecurityUnavailableError

log = logging.getLogger("kavach360.enrichment.queue")


class EnrichmentQueue:
    @staticmethod
    def enqueue_alert(alert_id: str, tenant_id: str, payload: dict[str, Any]) -> None:
        broker = get_broker()
        stream = stream_names()["detections"]
        try:
            broker.ensure_group(stream, "enrichment")
            broker.publish(stream, {"alert_id": alert_id, "tenant_id": tenant_id,
                                    "payload": payload})
        except Exception as exc:
            log.error("Enqueue failed: %s", exc)
            raise RedisSecurityUnavailableError("Enrichment queue unavailable") from exc

    @staticmethod
    def fetch_batch(consumer: str, count: int = 50, block_ms: int = 2000):
        broker = get_broker()
        stream = stream_names()["detections"]
        broker.ensure_group(stream, "enrichment")
        return broker.consume(stream, "enrichment", consumer,
                              count=count, block_ms=block_ms)

    @staticmethod
    def ack(msg_id: str) -> None:
        get_broker().ack(stream_names()["detections"], "enrichment", msg_id)

    @staticmethod
    def dead_letter(msg_id: str, payload: dict, reason: str) -> None:
        get_broker().dead_letter(stream_names()["detections"], msg_id, payload, reason)

    @staticmethod
    def claim_stuck(consumer: str, min_idle_ms: int = 60_000) -> int:
        broker = get_broker()
        if hasattr(broker, "claim_stuck"):
            return broker.claim_stuck(stream_names()["detections"], "enrichment",
                                       consumer, min_idle_ms)
        return 0
