from __future__ import annotations
import json
import logging
from typing import Any

from redis.exceptions import ConnectionError, RedisError, ResponseError, TimeoutError

from .base import EventBroker

log = logging.getLogger("kavach360.broker.redis")


class RedisStreamBroker(EventBroker):
    def __init__(self, client) -> None:
        self.client = client

    def ensure_group(self, stream: str, group: str) -> None:
        try:
            self.client.xgroup_create(stream, group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def publish(self, stream: str, payload: dict[str, Any]) -> str:
        try:
            return self.client.xadd(stream,
                                    {"payload": json.dumps(payload,
                                                           separators=(",", ":"))})
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RuntimeError(f"Broker publish failed: {exc}") from exc

    def consume(self, stream: str, group: str, consumer: str, count: int = 10,
                block_ms: int = 5000) -> list[tuple[str, dict[str, Any]]]:
        try:
            res = self.client.xreadgroup(group, consumer, {stream: ">"},
                                         count=count, block=block_ms)
        except (ConnectionError, TimeoutError, RedisError) as exc:
            raise RuntimeError(f"Broker consume failed: {exc}") from exc
        out = []
        for _stream, messages in res or []:
            for msg_id, fields in messages:
                raw = fields.get("payload", "{}")
                try:
                    out.append((msg_id, json.loads(raw)))
                except json.JSONDecodeError:
                    self.dead_letter(stream, msg_id,
                                     {"raw": str(raw)[:4096]}, "malformed_json")
                    out.append((msg_id, {"_dlq": True,
                                         "_reason": "malformed_json"}))
        return out

    def ack(self, stream: str, group: str, msg_id: str) -> None:
        try:
            self.client.xack(stream, group, msg_id)
        except (ConnectionError, TimeoutError, RedisError) as exc:
            log.warning("Broker ack failed for %s: %s", msg_id, exc)

    def dead_letter(self, stream: str, msg_id: str, payload: dict[str, Any],
                    reason: str) -> None:
        try:
            self.client.xadd(f"{stream}:dlq",
                             {"payload": json.dumps(payload),
                              "reason": reason, "orig_id": msg_id})
        except Exception as exc:
            log.error("DLQ write failed: %s", exc)

    def lag(self, stream: str, group: str) -> int:
        try:
            info = self.client.xpending(stream, group)
            return int(info.get("pending", 0)) if isinstance(info, dict) else 0
        except Exception:
            return 0

    def claim_stuck(self, stream: str, group: str, consumer: str,
                    min_idle_ms: int = 60_000, count: int = 10) -> int:
        try:
            res = self.client.xautoclaim(stream, group, consumer,
                                         min_idle_time=min_idle_ms, count=count)
            return len(res[1]) if res and len(res) > 1 else 0
        except Exception:
            return 0
