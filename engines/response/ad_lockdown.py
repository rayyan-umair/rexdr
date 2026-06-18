"""
rexdr - Incident Response Orchestration Engine
ad_lockdown.py - Active Directory account lockdown integration

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : HTTP client for calling back into the Identity engine to
          disable compromised AD accounts and revoke Kerberos tickets
          as part of automated containment playbook execution. This
          is the mechanism that makes coordinated cross-engine response
          possible - response orchestrates, identity executes the
          actual AD-level lockdown.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Verify the threat. Execute the isolation. Preserve the evidence."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging

# -- Third Party -------------------------------------------------------------
import httpx

# -- Internal ----------------------------------------------------------------
from response.config import settings

# ============================================================================

logger = logging.getLogger(__name__)


class AdLockdownClient:
    """
    Client for the Identity engine's account lockdown endpoints.
    Note: the Identity engine must expose /lockdown/disable and
    /lockdown/revoke-tickets endpoints for this client to call.
    These are defined as part of the Identity engine's API surface.
    """

    def __init__(self) -> None:
        self.base_url = settings.identity_engine_url

    async def disable_account(self, username: str) -> bool:
        """
        Call the Identity engine to disable a compromised AD account.
        Returns True on success, False on failure.
        """
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    f"{self.base_url}/lockdown/disable",
                    json={"username": username},
                )
                response.raise_for_status()
                logger.info("AD account disabled - username=%s", username)
                return True
        except Exception as e:
            logger.error(
                "AD account disable failed - username=%s error=%s",
                username, str(e),
            )
            return False

    async def revoke_tickets(self, username: str) -> bool:
        """
        Call the Identity engine to revoke all active Kerberos tickets
        for a compromised account, forcing re-authentication.
        Returns True on success, False on failure.
        """
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    f"{self.base_url}/lockdown/revoke-tickets",
                    json={"username": username},
                )
                response.raise_for_status()
                logger.info("Kerberos tickets revoked - username=%s", username)
                return True
        except Exception as e:
            logger.error(
                "Kerberos ticket revocation failed - username=%s error=%s",
                username, str(e),
            )
            return False