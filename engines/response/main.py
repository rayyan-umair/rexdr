"""
rexdr - Incident Response Orchestration Engine
main.py - Engine entry point and orchestration pipeline

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Entry point for the Incident Response Orchestration engine.
          Runs the orchestrator loop as a background task alongside
          the FastAPI server. Every cycle polls SIEM for active chains
          and guarantees each one results in a case file - the platform
          never silently drops a confirmed cross-engine attack chain.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Verify the threat. Execute the isolation. Preserve the evidence."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

# -- Third Party -------------------------------------------------------------
import uvicorn

# -- Internal ----------------------------------------------------------------
from response.ad_lockdown import AdLockdownClient
from response.api import create_app
from response.config import settings
from response.database import ResponseDatabase
from response.forensic_triage import ForensicTriage
from response.orchestrator import ResponseOrchestrator
from response.playbook_engine import PlaybookEngine

# ============================================================================

logging.basicConfig(level=settings.log_level, format=settings.log_format)
logger = logging.getLogger(__name__)

db               = ResponseDatabase(data_dir=settings.data_dir)
playbook_engine  = PlaybookEngine()
forensic_triage  = ForensicTriage()
ad_lockdown      = AdLockdownClient()
orchestrator     = ResponseOrchestrator(
    db=db,
    playbook_engine=playbook_engine,
    forensic_triage=forensic_triage,
    ad_lockdown=ad_lockdown,
)

_app_instance = None

def _get_app():
    return _app_instance


async def run_orchestration_loop() -> None:
    """The core orchestration loop - runs continuously as a background task."""
    logger.info("Orchestration pipeline started")

    while True:
        try:
            new_cases = await orchestrator.run_orchestration_pass()
            for case in new_cases:
                await _broadcast_case(case)
        except Exception as e:
            logger.error("Orchestration pass error - error=%s", str(e))

        await asyncio.sleep(settings.orchestrator_poll_interval_seconds)


async def _broadcast_case(case_data: dict) -> None:
    try:
        app = _get_app()
        if app and hasattr(app.state, "ws_manager"):
            await app.state.ws_manager.broadcast({
                "type":      "case_file",
                "engine":    "response",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data":      case_data,
            })
            logger.info("Case file broadcast - case_id=%s", case_data.get("case_id"))
    except Exception as e:
        logger.debug("WebSocket broadcast error - error=%s", str(e))


@asynccontextmanager
async def lifespan(app):
    global _app_instance
    _app_instance = app

    logger.info("=== REXDR Incident Response Orchestration Engine starting ===")

    db.connect()

    orchestration_task = asyncio.create_task(run_orchestration_loop())

    logger.info(
        "=== Response engine ready - playbooks=%d api=http://0.0.0.0:%d ===",
        playbook_engine.playbook_count(), settings.api_port,
    )

    yield

    logger.info("Response engine shutting down")
    orchestration_task.cancel()
    try:
        await orchestration_task
    except asyncio.CancelledError:
        pass

    db.close()
    logger.info("=== Response engine stopped ===")


def main() -> None:
    app = create_app(db=db, playbook_engine=playbook_engine)
    app.router.lifespan_context = lifespan
    uvicorn.run(
        app,
        host      = settings.api_host,
        port      = settings.api_port,
        workers   = settings.api_workers,
        log_level = settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()