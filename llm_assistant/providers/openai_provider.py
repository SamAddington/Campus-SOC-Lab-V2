import os
import json
import requests

from .base import LLMProvider, LLMProviderError


class OpenAIProvider(LLMProvider):
    """OpenAI-compatible chat-completions backend.

    Works with api.openai.com, api.groq.com, OpenRouter, and Ollama's
    OpenAI-compat endpoint. The choice is determined by ``OPENAI_BASE_URL``.
    Credentials are read from ``OPENAI_API_KEY`` (never hard-coded).
    """

    name = "openai"

    def __init__(self, model: str):
        super().__init__(model=model)
        self.api_key = os.getenv("OPENAI_API_KEY", "").strip()
        self.base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) and bool(self.model)

    def generate_json(self, prompt: str, timeout: int = 60) -> str:
        if not self.enabled:
            raise LLMProviderError("OpenAI-compatible provider not configured (missing API key).")

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a bounded cybersecurity triage assistant. "
                        "Return valid JSON only matching the requested schema. "
                        "Do not invent facts. Do not recommend autonomous actions."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
        }

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
        except requests.RequestException as e:
            raise LLMProviderError(f"OpenAI-compatible endpoint unreachable: {e}") from e

        try:
            data = resp.json()
        except Exception as e:
            raise LLMProviderError(
                f"OpenAI-compatible endpoint returned non-JSON: {resp.text[:200]}"
            ) from e

        if not resp.ok:
            raise LLMProviderError(f"OpenAI-compatible error: {data}")

        try:
            content = data["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError, AttributeError) as e:
            raise LLMProviderError(f"Unexpected response shape: {json.dumps(data)[:300]}") from e

        if not content:
            raise LLMProviderError("Empty response content.")
        return content
