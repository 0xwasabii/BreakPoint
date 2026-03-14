import asyncio

import httpx

from .base import BaseAdapter, ChatMessage


class AnthropicAdapter(BaseAdapter):
    """Adapter for the Anthropic Messages API (no SDK dependency, plain httpx)."""

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str = "https://api.anthropic.com",
        temperature: float = 1.0,
        max_tokens: int = 1024,
        timeout: float = 120,
    ) -> None:
        super().__init__()
        self._key = api_key
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._timeout = timeout

    @property
    def name(self) -> str:
        return f"anthropic/{self._model}"

    async def chat(self, messages: list[ChatMessage], model: str | None = None) -> str:
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        turns = [{"role": m.role, "content": m.content} for m in messages if m.role != "system"]
        payload: dict = {
            "model": model or self._model,
            "messages": turns,
            "max_tokens": self._max_tokens,
            "temperature": min(self._temperature, 1.0),   # API ceiling is 1.0
        }
        if system:
            payload["system"] = system
        headers = {
            "x-api-key": self._key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            for attempt in range(4):
                resp = await client.post(f"{self._base_url}/v1/messages", json=payload, headers=headers)
                if resp.status_code == 429 or resp.status_code == 529:
                    self.stats.rate_limit_retries += 1
                    if attempt == 3:
                        resp.raise_for_status()
                    await asyncio.sleep(5 * (2 ** attempt))
                    continue
                resp.raise_for_status()
                data = resp.json()
                self.stats.calls_made += 1
                usage = data.get("usage") or {}
                self.stats.tokens_used += usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
                return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        return ""
