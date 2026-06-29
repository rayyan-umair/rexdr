"""
rexdr - SIEM Correlation Engine
api.py - FastAPI REST and WebSocket API for the SIEM engine

Author  : Rayyan Umair
Date    : 2026-06-15
Purpose : Exposes Sigma matches, attack chains, and replay functionality
          to the REXDR frontend and other engines. The WebSocket stream
          pushes live attack chains to the frontend the moment they are
          formed by the correlation engine - this is the highest-value
          real-time signal in the entire platform.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Context is the only defense."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

# -- Third Party -------------------------------------------------------------
from fastapi import APIRouter, FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# -- Internal ----------------------------------------------------------------
from siem.ai_endpoint import router as ai_router
from rexdr_core.identity import METADATA, VERSION, EngineID
from siem.config import settings
from siem.database import SiemDatabase
from siem.replay import ReplayEngine
from siem.sigma_engine import SigmaEngine

# ============================================================================

logger = logging.getLogger(__name__)

# ============================================================================
# Response models
# ============================================================================

class HealthResponse(BaseModel):
    status:      str
    engine:      str
    version:     str
    timestamp:   datetime
    db_healthy:  bool
    rule_count:  int
    stats:       dict[str, Any]


class ChainsResponse(BaseModel):
    engine:    str
    count:     int
    chains:    list[dict[str, Any]]
    timestamp: datetime


class ReplayResponse(BaseModel):
    events_processed: int
    total_matches:    int
    matches_by_rule:  dict[str, int]


class StatsResponse(BaseModel):
    engine:    str
    stats:     dict[str, Any]
    timestamp: datetime


# ============================================================================
# WebSocket connection manager
# ============================================================================

class ConnectionManager:
    """Manages active WebSocket connections to the SIEM engine."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            "WebSocket client connected - total=%d",
            len(self.active_connections),
        )

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(
            "WebSocket client disconnected - total=%d",
            len(self.active_connections),
        )

    async def broadcast(self, message: dict) -> None:
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)

        for connection in disconnected:
            self.disconnect(connection)


# ============================================================================
# App factory
# ============================================================================

def create_app(
    db: SiemDatabase,
    sigma_engine: SigmaEngine,
    replay_engine: ReplayEngine,
) -> FastAPI:
    """Create and configure the FastAPI application for the SIEM engine."""

    app = FastAPI(
        title       = "REXDR - SIEM Correlation Engine",
        description = "Cross-engine attack chain correlation and Sigma matching",
        version     = VERSION,
        docs_url    = "/docs",
        redoc_url   = "/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins = ["*"],
        allow_methods = ["*"],
        allow_headers = ["*"],
    )

    app.include_router(ai_router)

    manager = ConnectionManager()
    app.state.ws_manager = manager
    app.state.db = db

    # -------------------------------------------------------------------------
    # Health
    # -------------------------------------------------------------------------

    @app.get("/health", response_model=HealthResponse, tags=["Platform"])
    async def health() -> HealthResponse:
        """Health check endpoint for Docker and the Tkinter launcher."""
        db_healthy = db.is_healthy()
        stats = db.get_stats() if db_healthy else {}

        return HealthResponse(
            status      = "healthy" if db_healthy else "degraded",
            engine      = EngineID.SIEM.value,
            version     = VERSION,
            timestamp   = datetime.utcnow(),
            db_healthy  = db_healthy,
            rule_count  = sigma_engine.rule_count(),
            stats       = stats,
        )

    # -------------------------------------------------------------------------
    # Attack chains
    # -------------------------------------------------------------------------

    @app.get("/chains", response_model=ChainsResponse, tags=["Chains"])
    async def get_chains(limit: int = 50, active_only: bool = False) -> ChainsResponse:
        """
        Get recent cross-engine attack chains.
        Set active_only=true to get only currently active, uncontained chains.
        This is the primary REXDR output - what no single engine can produce.
        """
        if limit > 500:
            raise HTTPException(status_code=400, detail="Limit cannot exceed 500.")

        chains = db.get_active_chains() if active_only else db.get_recent_chains(limit=limit)

        return ChainsResponse(
            engine    = EngineID.SIEM.value,
            count     = len(chains),
            chains    = chains,
            timestamp = datetime.utcnow(),
        )

    @app.get("/chains/{chain_id}", tags=["Chains"])
    async def get_chain(chain_id: str) -> dict:
        """Get a single attack chain by ID, including its full narrative."""
        chains = db.get_recent_chains(limit=1000)
        for c in chains:
            if c.get("chain_id") == chain_id:
                return c
        raise HTTPException(status_code=404, detail=f"Chain {chain_id} not found.")

    # -------------------------------------------------------------------------
    # Sigma rules
    # -------------------------------------------------------------------------

    @app.get("/rules", tags=["Sigma"])
    async def get_rules() -> dict:
        """Get the count and list of currently loaded Sigma rules."""
        return {
            "rule_count": sigma_engine.rule_count(),
            "rules": [
                {"rule_id": r.rule_id, "title": r.title, "severity": r.severity.value}
                for r in sigma_engine.rules
            ],
        }

    @app.post("/rules/reload", tags=["Sigma"])
    async def reload_rules() -> dict:
        """Force an immediate reload of Sigma rules from disk."""
        sigma_engine.load_rules()
        return {"reloaded": True, "rule_count": sigma_engine.rule_count()}

    # -------------------------------------------------------------------------
    # Replay
    # -------------------------------------------------------------------------

    @app.post("/replay", response_model=ReplayResponse, tags=["Replay"])
    async def run_replay(path: str | None = None) -> ReplayResponse:
        """
        Run the replay engine against the sample attack log or a
        custom path. Used for Sigma rule testing and demonstrations.
        Does not affect the live database.
        """
        replay_path = Path(path) if path else None
        result = replay_engine.run_replay(path=replay_path)
        return ReplayResponse(**result)

    # -------------------------------------------------------------------------
    # Stats
    # -------------------------------------------------------------------------

    @app.get("/stats", response_model=StatsResponse, tags=["Platform"])
    async def get_stats() -> StatsResponse:
        """Get engine statistics."""
        return StatsResponse(
            engine    = EngineID.SIEM.value,
            stats     = db.get_stats(),
            timestamp = datetime.utcnow(),
        )

    # -------------------------------------------------------------------------
    # Platform info
    # -------------------------------------------------------------------------

    @app.get("/info", tags=["Platform"])
    async def get_info() -> dict:
        """Return platform and engine identity information."""
        return {
            "platform": METADATA["name"],
            "engine":   EngineID.SIEM.value,
            "version":  VERSION,
            "port":     settings.api_port,
        }

    # -------------------------------------------------------------------------
    # WebSocket - live chain stream
    # -------------------------------------------------------------------------

    @app.websocket("/ws/chains")
    async def websocket_chains(websocket: WebSocket) -> None:
        """
        WebSocket endpoint for live attack chain streaming.
        The moment the correlation engine forms a new chain, it is
        pushed here in real time. This is the highest-priority signal
        in the entire REXDR platform.
        """
        await manager.connect(websocket)
        try:
            while True:
                await asyncio.sleep(30)
                await websocket.send_json({"type": "ping"})
        except WebSocketDisconnect:
            manager.disconnect(websocket)
        except Exception as e:
            logger.error("WebSocket error - error=%s", str(e))
            manager.disconnect(websocket)

    return app