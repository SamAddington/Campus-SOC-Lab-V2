from abc import ABC, abstractmethod
from typing import Optional


class LLMProviderError(Exception):
    """Raised when a provider cannot produce a usable response.

    Callers should always catch this and degrade to the bounded fallback;
    a provider error must never propagate to the end user as a 5xx.
    """


class LLMProvider(ABC):
    """Minimal interface every teacher/student backend must implement.

    The contract is intentionally narrow: given a prompt, return a single
    string that the caller will parse as JSON. Schema validation happens in
    ``teacher_student.py`` so every backend is held to the same bounded-output
    shape regardless of vendor.
    """

    #: Short, user-visible identifier ("ollama", "openai", ...). Used for audit.
    name: str = "base"

    def __init__(self, model: str):
        self.model = model

    @property
    def enabled(self) -> bool:
        """Whether this provider has the credentials / reachability it needs."""
        return True

    @abstractmethod
    def generate_json(self, prompt: str, timeout: int = 60) -> str:
        """Return a raw string the caller will parse as JSON.

        Implementations should set temperature low (0.2 or less) and request
        JSON-only output whenever the provider supports it.
        """
        raise NotImplementedError

    def describe(self) -> dict:
        return {"provider": self.name, "model": self.model, "enabled": self.enabled}
