"""
rexdr - Entity Store Service
main.py - Service entry point

Author  : Rayyan Umair
Date    : 2026-06-23
Purpose : Entry point for the standalone Entity Store service. Owns
          the single writable EntityStore connection for the entire
          platform. Every other engine connects to this service over
          HTTP via EntityStoreClient rather than opening
          entity_store.duckdb directly.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"One identity. One risk score. Every engine."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
from contextlib import asynccontextmanager
from pathlib import Path

# -- Third Party -------------------------------------------------------------
import uvicorn

# -- Internal ----------------------------------------------------------------
from rexdr_core.entity_store import EntityStore
from entity_store.api import create_app
from entity_store.config import settings

# ============================================================================

logging.basicConfig(level=settings.log_level, format=settings.log_format)
logger = logging.getLogger(__name__)

store = EntityStore(data_dir=Path(settings.data_dir))


@asynccontextmanager
async def lifespan(app):
    logger.info("=== REXDR Entity Store Service starting ===")
    store.connect()
    logger.info("=== Entity Store ready - api=http://0.0.0.0:%d ===", settings.api_port)
    yield
    logger.info("Entity Store Service shutting down")
    store.close()
    logger.info("=== Entity Store Service stopped ===")


def main() -> None:
    app = create_app(store=store)
    app.router.lifespan_context = lifespan
    uvicorn.run(
        app,
        host      = settings.api_host,
        port      = settings.api_port,
        log_level = settings.log_level.lower(),
    )


if __name__ == "__main__":
    main()