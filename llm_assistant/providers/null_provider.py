from .base import LLMProvider, LLMProviderError


class NullProvider(LLMProvider):
    """Explicitly-disabled provider. Always raises so the router falls back.

    Used when an operator wants to run student-only with teacher absent, or
    vice versa, without triggering warnings about missing credentials.
    """

    name = "none"

    @property
    def enabled(self) -> bool:
        return False

    def generate_json(self, prompt: str, timeout: int = 60) -> str:
        raise LLMProviderError("Provider disabled")
