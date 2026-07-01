"""
rexdr - SIEM Correlation Engine
ai_endpoint.py - AI-assisted investigation endpoint

Author  : Rayyan Umair
Date    : 2026-06-29
Purpose : Exposes an endpoint that takes a chain or detection's real
          data and asks the configured AI provider to explain it in
          plain language. Always grounds the prompt in actual REXDR
          data passed in by the frontend - never a hardcoded example.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Context is the only defense."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging

# -- Third Party -------------------------------------------------------------
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

# -- Internal ----------------------------------------------------------------
from rexdr_core.ai_client import AIClient
from siem.config import settings

# ============================================================================

logger = logging.getLogger(__name__)

router = APIRouter()

SYSTEM_PROMPT = (
    "You are the REXDR investigation assistant, embedded in a unified "
    "extended detection and response platform. You are given real "
    "detection or attack chain data from the platform's own engines. "
    "Explain what happened, why it matters, and what the analyst "
    "should investigate or do next. Be concise, concrete, and avoid "
    "generic security advice not tied to the data given. Use the "
    "actual detection codes, entity IDs, and severities provided."
)


class AskRequest(BaseModel):
    context: dict
    question: str | None = None

@router.get("/ai/status")
async def ai_status() -> dict:
    """
    Reports whether an AI provider is currently configured, without
    exposing the API key itself. The frontend uses this instead of a
    build-time flag, so AI availability always reflects the real
    backend configuration.
    """
    client = AIClient(
        provider = settings.ai_provider,
        api_key  = settings.ai_api_key,
        model    = settings.ai_model,
        base_url = settings.ai_base_url,
    )
    return {
        "configured": client.is_configured(),
        "provider": settings.ai_provider or None,
    }

@router.post("/ai/ask")
async def ask_ai(req: AskRequest) -> dict:
    """
    Send a chain or detection's real data to the configured AI provider.
    The frontend passes the exact object currently selected in the
    investigation blade - no example or placeholder data is ever sent.
    """
    client = AIClient(
        provider = settings.ai_provider,
        api_key  = settings.ai_api_key,
        model    = settings.ai_model,
        base_url = settings.ai_base_url,
    )

    if not client.is_configured():
        raise HTTPException(
            status_code=503,
            detail="No AI provider configured. Set AI_PROVIDER and AI_API_KEY in the launcher.",
        )

    user_message = (
        f"Question: {req.question or 'Explain this and what I should do next.'}\n\n"
        f"Data:\n{req.context}"
    )

    answer = await client.ask(SYSTEM_PROMPT, user_message)

    if answer is None:
        raise HTTPException(status_code=502, detail="AI provider call failed.")

    return {"answer": answer}