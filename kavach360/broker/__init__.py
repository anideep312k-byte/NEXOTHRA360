from __future__ import annotations
from .base import EventBroker
from .redis_streams import RedisStreamBroker


def get_broker() -> EventBroker:
    from ..web.security.redis_rate_limit import security_store
    return RedisStreamBroker(security_store.client)


def stream_names() -> dict[str, str]:
    return {"events": "k360:stream:events",
            "detections": "k360:stream:detections",
            "audit": "k360:stream:audit"}
