from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any


class EventBroker(ABC):
    @abstractmethod
    def publish(self, stream: str, payload: dict[str, Any]) -> str: ...
    @abstractmethod
    def consume(self, stream: str, group: str, consumer: str, count: int = 10,
                block_ms: int = 5000) -> list[tuple[str, dict[str, Any]]]: ...
    @abstractmethod
    def ack(self, stream: str, group: str, msg_id: str) -> None: ...
    @abstractmethod
    def dead_letter(self, stream: str, msg_id: str, payload: dict[str, Any],
                    reason: str) -> None: ...
    @abstractmethod
    def lag(self, stream: str, group: str) -> int: ...
    @abstractmethod
    def ensure_group(self, stream: str, group: str) -> None: ...
