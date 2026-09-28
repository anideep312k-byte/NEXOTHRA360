"""Secrets provider interface."""
from __future__ import annotations
from abc import ABC, abstractmethod


class SecretsProvider(ABC):
    @abstractmethod
    def get(self, key: str, default: str | None = None) -> str | None: ...


class EnvProvider(SecretsProvider):
    def get(self, key: str, default: str | None = None) -> str | None:
        import os
        return os.getenv(key, default)


def get_secrets_provider() -> SecretsProvider:
    return EnvProvider()
