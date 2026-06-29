"""
rexdr_core
ai_client.py - Unified AI provider client

Author  : Rayyan Umair
Date    : 2026-06-29
Purpose : Single client every engine can use to call the configured AI
          provider - Groq, OpenAI, Anthropic, Gemini, or Ollama. Reads
          provider/key/model from BaseEngineSettings fields already
          defined platform-wide. Groq is the recommended default since
          it is free and fast. Returns a plain string response or None
          on failure - callers decide how to surface that to the user.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"The foundation everything else is built on."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging

# -- Third Party -------------------------------------------------------------
import httpx

# ============================================================================

logger = logging.getLogger(__name__)

DEFAULT_MODELS = {
    "groq":      "llama-3.3-70b-versatile",
    "openai":    "gpt-4o-mini",
    "anthropic": "claude-3-5-sonnet-20241022",
    "gemini":    "gemini-1.5-flash",
}

PROVIDER_BASE_URLS = {
    "groq":      "https://api.groq.com/openai/v1/chat/completions",
    "openai":    "https://api.openai.com/v1/chat/completions",
    "anthropic": "https://api.anthropic.com/v1/messages",
    "gemini":    "https://generativelanguage.googleapis.com/v1beta/models",
}


class AIClient:
    """
    Calls the configured AI provider with a system prompt and user
    message. Supports Groq, OpenAI, and Ollama via the OpenAI-compatible
    chat completions shape - Anthropic and Gemini use distinct request
    shapes, handled separately below.
    """

    def __init__(
        self,
        provider: str | None,
        api_key: str | None,
        model: str | None = None,
        base_url: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.provider = (provider or "").lower().strip()
        self.api_key = api_key
        self.model = model or DEFAULT_MODELS.get(self.provider)
        self.base_url = base_url
        self.timeout = timeout

    def is_configured(self) -> bool:
        if not self.provider:
            return False
        if self.provider == "ollama":
            return bool(self.base_url)
        return bool(self.api_key)

    async def ask(self, system_prompt: str, user_message: str) -> str | None:
        """
        Send a prompt to the configured provider. Returns the response
        text, or None if not configured or the call fails.
        """
        if not self.is_configured():
            logger.warning("AI client not configured - provider=%s", self.provider)
            return None

        try:
            if self.provider in ("groq", "openai"):
                return await self._call_openai_compatible(
                    PROVIDER_BASE_URLS[self.provider], system_prompt, user_message
                )
            if self.provider == "ollama":
                return await self._call_ollama(system_prompt, user_message)
            if self.provider == "anthropic":
                return await self._call_anthropic(system_prompt, user_message)
            if self.provider == "gemini":
                return await self._call_gemini(system_prompt, user_message)

            logger.warning("Unknown AI provider - provider=%s", self.provider)
            return None

        except Exception as e:
            logger.error("AI call failed - provider=%s error=%s", self.provider, str(e))
            return None

    # -------------------------------------------------------------------------
    # Provider-specific calls
    # -------------------------------------------------------------------------

    async def _call_openai_compatible(
        self, url: str, system_prompt: str, user_message: str
    ) -> str | None:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                    "temperature": 0.3,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    async def _call_ollama(self, system_prompt: str, user_message: str) -> str | None:
        url = f"{self.base_url.rstrip('/')}/api/chat"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                url,
                json={
                    "model": self.model or "llama3",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message},
                    ],
                    "stream": False,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"]

    async def _call_anthropic(self, system_prompt: str, user_message: str) -> str | None:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                PROVIDER_BASE_URLS["anthropic"],
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": 1024,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_message}],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["content"][0]["text"]

    async def _call_gemini(self, system_prompt: str, user_message: str) -> str | None:
        url = f"{PROVIDER_BASE_URLS['gemini']}/{self.model}:generateContent?key={self.api_key}"
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                url,
                json={
                    "contents": [{"parts": [{"text": f"{system_prompt}\n\n{user_message}"}]}],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]