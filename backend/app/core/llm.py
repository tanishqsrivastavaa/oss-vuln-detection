from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Optional

import httpx

from backend.app.core.config import LLMProvider, Settings


class LLMClient(ABC):
    """Abstract interface for invoking large language models."""

    @abstractmethod
    async def generate(self, prompt: str, *, system_prompt: str = "") -> str:
        """Return the model response for the given prompt."""
        raise NotImplementedError


class OllamaClient(LLMClient):
    """Client that interacts with an on-prem Ollama deployment."""

    def __init__(self, base_url: str, model: str):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=10.0))

    async def generate(self, prompt: str, *, system_prompt: str = "") -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system_prompt:
            payload["system"] = system_prompt

        response = await self._client.post(f"{self.base_url}/api/generate", json=payload)
        response.raise_for_status()

        data = response.json()
        if isinstance(data, dict):
            # Non-streaming responses return the final message under "response"
            return data.get("response", "").strip()

        return ""

    async def aclose(self) -> None:
        await self._client.aclose()


class GroqClient(LLMClient):
    """Client for Groq hosted LLMs (optional)."""

    def __init__(self, api_key: str, model_name: str = "llama-3.3-70b-versatile"):
        self.api_key = api_key
        self.model_name = model_name
        self._client = httpx.AsyncClient(
            base_url="https://api.groq.com/openai/v1",
            timeout=httpx.Timeout(30.0, connect=10.0),
            headers={"Authorization": f"Bearer {self.api_key}"},
        )

    async def generate(self, prompt: str, *, system_prompt: str = "") -> str:
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt or ""},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        response = await self._client.post("/chat/completions", json=payload)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"].strip()

    async def aclose(self) -> None:
        await self._client.aclose()


class MockLLMClient(LLMClient):
    """Fallback client that returns deterministic output for offline testing."""

    async def generate(self, prompt: str, *, system_prompt: str = "") -> str:
        await asyncio.sleep(0)
        return "No additional vulnerabilities identified by LLM."


def get_llm_client(settings: Optional[Settings] = None) -> LLMClient:
    """Factory for selecting the appropriate LLM client."""

    settings = settings or Settings()

    if settings.LLM_PROVIDER == LLMProvider.OLLAMA:
        return OllamaClient(settings.OLLAMA_BASE_URL, settings.OLLAMA_MODEL)

    if settings.LLM_PROVIDER == LLMProvider.GROQ and settings.GROQ_API_KEY:
        return GroqClient(settings.GROQ_API_KEY)

    return MockLLMClient()