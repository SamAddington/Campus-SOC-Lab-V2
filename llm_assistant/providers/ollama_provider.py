import os
import requests

from .base import LLMProvider, LLMProviderError


class OllamaProvider(LLMProvider):
    """Local Ollama backend. Preferred for the "student" tier in workshops
    because it runs fully offline on the instructor laptop."""

    name = "ollama"

    def __init__(self, model: str, base_url: str | None = None):
        super().__init__(model=model)
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")

    @property
    def enabled(self) -> bool:
        return bool(self.base_url) and bool(self.model)

    def generate_json(self, prompt: str, timeout: int = 90) -> str:
        if not self.enabled:
            raise LLMProviderError("Ollama not configured")

        url = f"{self.base_url.rstrip('/')}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.2},
        }

        try:
            resp = requests.post(url, json=payload, timeout=timeout)
        except requests.RequestException as e:
            raise LLMProviderError(f"Ollama unreachable at {self.base_url}: {e}") from e

        try:
            data = resp.json()
        except Exception as e:
            raise LLMProviderError(
                f"Ollama returned non-JSON: {resp.text[:200]}"
            ) from e

        if not resp.ok:
            raise LLMProviderError(
                f"Ollama error at {url}: HTTP {resp.status_code}: {data}"
            )

        text = (data.get("response") or "").strip()
        if not text:
            raise LLMProviderError("Ollama returned empty response")
        return text

    def describe(self) -> dict:
        info = super().describe()
        info["base_url"] = self.base_url
        return info
