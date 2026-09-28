from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(slots=True)
class LLMResponse:
    text: str
    confidence: float
    citations: list[str]


class LLMProvider(ABC):
    name: str = "base"
    @abstractmethod
    def summarize(self, context: str, question: str) -> LLMResponse: ...


class NullLLMProvider(LLMProvider):
    name = "null"
    def summarize(self, context: str, question: str) -> LLMResponse:
        return LLMResponse(
            text="Advisory summary unavailable: no LLM backend configured.",
            confidence=0.0, citations=[])
