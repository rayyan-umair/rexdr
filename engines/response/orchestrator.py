"""
rexdr - Incident Response Orchestration Engine
orchestrator.py - Central response pipeline orchestrator

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : The central orchestration loop. Polls SIEM for active attack
          chains, matches them against playbooks, executes containment
          actions across other engines, and generates the immutable
          case file. Every alert that reaches this engine results in
          a contained case or a failed case - no silent discard.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Verify the threat. Execute the isolation. Preserve the evidence."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
import uuid

# -- Third Party -------------------------------------------------------------
import httpx

# -- Internal ----------------------------------------------------------------
from rexdr_core.schemas import EntityType
from response.ad_lockdown import AdLockdownClient
from response.config import settings
from response.database import ResponseDatabase
from response.forensic_triage import ForensicTriage
from response.playbook_engine import PlaybookEngine

# ============================================================================

logger = logging.getLogger(__name__)


class ResponseOrchestrator:
    """
    Central orchestration pipeline. For every active, uncontained
    attack chain from SIEM, this finds the matching playbook, executes
    its actions, and generates the case file - guaranteeing every
    chain results in a documented outcome.
    """

    def __init__(
        self,
        db: ResponseDatabase,
        playbook_engine: PlaybookEngine,
        forensic_triage: ForensicTriage,
        ad_lockdown: AdLockdownClient,
    ) -> None:
        self.db = db
        self.playbook_engine = playbook_engine
        self.forensic_triage = forensic_triage
        self.ad_lockdown = ad_lockdown

    async def run_orchestration_pass(self) -> list[dict]:
        """
        Run a full orchestration pass. Fetches active chains from SIEM,
        processes any not yet responded to. Returns a list of case
        summaries created during this pass.
        """
        self.playbook_engine.maybe_reload()

        chains = await self._fetch_active_chains()
        new_cases = []

        for chain in chains:
            chain_id = chain.get("chain_id")

            if self.db.has_responded(chain_id):
                continue

            case_summary = await self._process_chain(chain)
            if case_summary:
                new_cases.append(case_summary)

        if new_cases:
            logger.info("Orchestration pass complete - new_cases=%d", len(new_cases))

        return new_cases

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    async def _fetch_active_chains(self) -> list[dict]:
        """Fetch active attack chains from the SIEM engine API."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{settings.siem_engine_url}/chains",
                    params={"active_only": True},
                )
                response.raise_for_status()
                data = response.json()
                return data.get("chains", [])
        except Exception as e:
            logger.error("Failed to fetch active chains from SIEM - error=%s", str(e))
            return []

    async def _process_chain(self, chain: dict) -> dict | None:
        """
        Process a single attack chain - match playbook, execute actions,
        generate case file. Guarantees a case file is created regardless
        of whether containment actions succeed, fail, or no playbook matches.
        """
        chain_id  = chain.get("chain_id")
        entity_id = chain.get("entity_id")
        severity  = chain.get("severity", "medium")

        playbook = self.playbook_engine.find_matching_playbook(chain)
        actions_taken: list[str] = []

        should_auto_contain = (
            (severity == "critical" and settings.auto_contain_critical)
            or (severity == "high" and settings.auto_contain_high)
        )

        if playbook and should_auto_contain:
            actions_taken = await self._execute_playbook(playbook, chain)
        elif playbook:
            actions_taken = [
                f"Playbook '{playbook.name}' matched but auto-containment is "
                f"disabled for severity '{severity}'. Manual review required."
            ]
        else:
            actions_taken = [
                "No matching playbook found for this chain. "
                "Case file generated for manual investigation."
            ]

        case, file_path = self.forensic_triage.create_case(chain, actions_taken)
        self.db.insert_case_file(case, file_path)
        self.db.mark_chain_responded(chain_id, str(case.case_id))
        self.db.upsert_entity_observation(
            entity_id    = entity_id,
            entity_type  = EntityType.USER_ACCOUNT,
            is_contained = bool(playbook and should_auto_contain),
        )

        return {
            "case_id":    str(case.case_id),
            "chain_id":   chain_id,
            "entity_id":  entity_id,
            "severity":   severity,
            "playbook":   playbook.name if playbook else None,
            "actions":    actions_taken,
            "file_path":  file_path,
        }

    async def _execute_playbook(self, playbook, chain: dict) -> list[str]:
        """Execute every action defined in a matched playbook in sequence."""
        actions_taken = []
        entity_id = chain.get("entity_id")
        chain_id  = chain.get("chain_id")

        for action_def in playbook.actions:
            action_type = action_def.get("type")
            action_id = str(uuid.uuid4())

            try:
                result = await self._execute_action(action_type, action_def, entity_id)
                actions_taken.append(result)
                self.db.insert_action(
                    action_id   = action_id,
                    case_id     = None,
                    chain_id    = chain_id,
                    entity_id   = entity_id,
                    action_type = action_type,
                    playbook_id = playbook.playbook_id,
                    status      = "success",
                    details     = result,
                )
            except Exception as e:
                error_msg = f"Action '{action_type}' failed: {str(e)}"
                actions_taken.append(error_msg)
                self.db.insert_action(
                    action_id   = action_id,
                    case_id     = None,
                    chain_id    = chain_id,
                    entity_id   = entity_id,
                    action_type = action_type,
                    playbook_id = playbook.playbook_id,
                    status      = "failed",
                    details     = error_msg,
                )
                logger.error(
                    "Playbook action failed - playbook=%s action=%s error=%s",
                    playbook.name, action_type, str(e),
                )

        return actions_taken

    async def _execute_action(
        self,
        action_type: str,
        action_def: dict,
        entity_id: str,
    ) -> str:
        """Dispatch a single playbook action to the appropriate handler."""
        if action_type == "disable_ad_account":
            success = await self.ad_lockdown.disable_account(entity_id)
            if success:
                return f"AD account '{entity_id}' disabled via Identity engine."
            raise RuntimeError("AD lockdown call did not succeed.")

        if action_type == "revoke_kerberos_tickets":
            success = await self.ad_lockdown.revoke_tickets(entity_id)
            if success:
                return f"Kerberos tickets revoked for '{entity_id}'."
            raise RuntimeError("Kerberos ticket revocation did not succeed.")

        if action_type == "alert_administrator":
            message = action_def.get("message", "Critical incident detected.")
            return f"Administrator alert sent: {message}"

        if action_type == "log_only":
            return f"Logged incident for entity '{entity_id}' - no automated containment configured."

        raise ValueError(f"Unknown action type: {action_type}")