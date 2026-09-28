"""Ollama LLM provider (public HTTP API client)."""
from __future__ import annotations
import json
import logging
import os
import requests

from .base import LLMProvider, LLMResponse
from .guard import PromptRejected, guard_input, guard_output

log = logging.getLogger("kavach360.ai.ollama")

_DEFAULT_SYSTEM = (
    "You are a SOC analyst copilot. Use only the evidence provided. "
    "Never invent IOCs, timestamps, hostnames, or techniques. "
    "Return JSON with keys: verdict, confidence, summary, next_steps, "
    "mitre_techniques, escalation."
)


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, base_url: str | None = None, model: str | None = None,
                 timeout: int = 30, temperature: float = 0.1) -> None:
        self.base_url = (base_url or os.getenv(
            "OLLAMA_BASE_URL", "http://127.0.0.1:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.2:3b")
        self.timeout = timeout
        self.temperature = temperature

    def summarize(self, context: str, question: str) -> LLMResponse:
        try:
            safe_context = guard_input(context)
            safe_question = guard_input(question)
        except PromptRejected as exc:
            return LLMResponse(text=f"input rejected: {exc}",
                               confidence=0.0, citations=[])
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _DEFAULT_SYSTEM},
                {"role": "user", "content": json.dumps(
                    {"context": safe_context, "question": safe_question},
                    separators=(",", ":"))},
            ],
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        try:
            r = requests.post(f"{self.base_url}/api/chat", json=payload,
                              timeout=self.timeout)
            if r.status_code != 200:
                return LLMResponse(text=f"ollama_http_{r.status_code}",
                                   confidence=0.0, citations=[])
            content = r.json().get("message", {}).get("content", "")
            try:
                content = guard_output(content)
            except PromptRejected:
                return LLMResponse(text="output_rejected",
                                   confidence=0.0, citations=[])
            return LLMResponse(text=content, confidence=0.7, citations=[])
        except Exception:
            return LLMResponse(text="ollama_unavailable", confidence=0.0,
                               citations=[])
