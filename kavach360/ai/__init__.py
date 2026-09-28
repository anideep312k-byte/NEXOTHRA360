from __future__ import annotations
from .base import LLMProvider, LLMResponse, NullLLMProvider
from .guard import PromptRejected, guard_input, guard_output
from .triage import TriageOrchestrator


def get_llm_provider() -> LLMProvider:
    from ..config import config
    if config.LLM_BACKEND == "ollama":
        try:
            from .ollama import OllamaProvider
            return OllamaProvider()
        except ImportError:
            pass
    return NullLLMProvider()
