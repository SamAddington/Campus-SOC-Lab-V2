import os
import json
import requests

from .base import LLMProvider, LLMProviderError


class AnthropicProvider(LLMProvider):
    """Anthropic Messages API backend.

    Credentials come from ``ANTHROPIC_API_KEY``. The provider requests JSON
    by instructing the model in the system prompt; Anthropic's Messages API
    does not (as of v1) expose a response_format constraint, so the caller
    MUST still validate the JSON schema downstream.
    """

    name = "anthropic"

    API_VERSION = "2023-06-01"

    def __init__(self, model: str):
        super().__init__(model=model)
        self.api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        self.base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1").rstrip("/")
        self.max_tokens = int(os.getenv("ANTHROPIC_MAX_TOKENS", "600"))

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) and bool(self.model)

    def generate_json(self, prompt: str, timeout: int = 60) -> str:
        if not self.enabled:
            raise LLMProviderError("Anthropic provider not configured (missing API key).")

        url = f"{self.base_url}/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self.API_VERSION,
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": 0.2,
            "system": (
                "You are a bounded cybersecurity triage assistant for a teaching SOC. "
                "Return valid JSON only, matching the schema requested in the user message. "
                "Do not invent facts. Do not recommend autonomous or destructive actions."
            ),
            "messages": [{"role": "user", "content": prompt}],
        }

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
        except requests.RequestException as e:
            raise LLMProviderError(f"Anthropic endpoint unreachable: {e}") from e

        try:
            data = resp.json()
        except Exception as e:
            raise LLMProviderError(
                f"Anthropic endpoint returned non-JSON: {resp.text[:200]}"
            ) from e

        if not resp.ok:
            raise LLMProviderError(f"Anthropic error: {data}")

        try:
            parts = data.get("content", [])
            text_parts = [p.get("text", "") for p in parts if p.get("type") == "text"]
            content = "".join(text_parts).strip()
        except (KeyError, AttributeError) as e:
            raise LLMProviderError(f"Unexpected response shape: {json.dumps(data)[:300]}") from e

        if not content:
            raise LLMProviderError("Empty response content.")
        return content
