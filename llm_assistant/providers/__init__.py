from .base import LLMProvider, LLMProviderError
from .ollama_provider import OllamaProvider
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .null_provider import NullProvider

__all__ = [
    "LLMProvider",
    "LLMProviderError",
    "OllamaProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "NullProvider",
    "build_provider",
]


def build_provider(name: str, model: str, ollama_base_url: str | None = None) -> LLMProvider:
    """Factory. ``name`` is one of: ollama, openai, anthropic, none."""
    n = (name or "").strip().lower()
    if n in ("", "none", "off", "disabled"):
        return NullProvider(model=model)
    if n == "ollama":
        return OllamaProvider(model=model, base_url=ollama_base_url)
    if n in ("openai", "openai-compatible", "openai_compatible", "groq", "openrouter"):
        return OpenAIProvider(model=model)
    if n == "anthropic":
        return AnthropicProvider(model=model)
    raise ValueError(f"Unknown LLM provider: {name!r}")
