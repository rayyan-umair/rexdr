"""
rexdr - Incident Response Orchestration Engine
api.py - FastAPI REST and WebSocket API for the Response engine

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Exposes case files, response actions, and playbook status
          to the REXDR frontend. The WebSocket stream pushes new case
          files to the frontend the moment they are created.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Verify the threat. Execute the isolation. Preserve the evidence."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import asyncio
import logging
from datetime import datetime
from typing import Any

# -- Third Party -------------------------------------------------------------
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# -- Internal ----------------------------------------------------------------
from rexdr_core.identity import METADATA, VERSION, EngineID
from response.config import settings
from response.database import ResponseDatabase
from response.playbook_engine import PlaybookEngine

# ============================================================================

logger = logging.getLogger(__name__)


class HealthResponse(BaseModel):
    status:         str
    engine:         str
    version:        str
    timestamp:      datetime
    db_healthy:     bool
    playbook_count: int
    stats:          dict[str, Any]


class CasesResponse(BaseModel):
    engine:    str
    count:     int
    cases:     list[dict[str, Any]]
    timestamp: datetime


class ActionsResponse(BaseModel):
    engine:    str
    count:     int
    actions:   list[dict[str, Any]]
    timestamp: datetime


class StatsResponse(BaseModel):
    engine:    str
    stats:     dict[str, Any]
    timestamp: datetime


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket client connected - total=%d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info("WebSocket client disconnected - total=%d", len(self.active_connections))

    async def broadcast(self, message: dict) -> None:
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        for connection in disconnected:
            self.disconnect(connection)


def create_app(db: ResponseDatabase, playbook_engine: PlaybookEngine) -> FastAPI:
    app = FastAPI(
        title       = "REXDR - Incident Response Orchestration",
        description = "Incident Response Orchestration engine API",
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

    manager = ConnectionManager()
    app.state.ws_manager = manager
    app.state.db = db

    @app.get("/health", response_model=HealthResponse, tags=["Platform"])
    async def health() -> HealthResponse:
        db_healthy = db.is_healthy()
        stats = db.get_stats() if db_healthy else {}
        return HealthResponse(
            status         = "healthy" if db_healthy else "degraded",
            engine         = EngineID.RESPONSE.value,
            version        = VERSION,
            timestamp      = datetime.utcnow(),
            db_healthy     = db_healthy,
            playbook_count = playbook_engine.playbook_count(),
            stats          = stats,
        )

    @app.get("/cases", response_model=CasesResponse, tags=["Cases"])
    async def get_cases(limit: int = 50) -> CasesResponse:
        if limit > 500:
            raise HTTPException(status_code=400, detail="Limit cannot exceed 500.")
        cases = db.get_recent_cases(limit=limit)
        return CasesResponse(
            engine    = EngineID.RESPONSE.value,
            count     = len(cases),
            cases     = cases,
            timestamp = datetime.utcnow(),
        )

    @app.get("/cases/{case_id}", tags=["Cases"])
    async def get_case(case_id: str) -> dict:
        cases = db.get_recent_cases(limit=1000)
        for c in cases:
            if c.get("case_id") == case_id:
                return c
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found.")

    @app.get("/actions", response_model=ActionsResponse, tags=["Actions"])
    async def get_actions(limit: int = 100) -> ActionsResponse:
        if limit > 1000:
            raise HTTPException(status_code=400, detail="Limit cannot exceed 1000.")
        actions = db.get_recent_actions(limit=limit)
        return ActionsResponse(
            engine    = EngineID.RESPONSE.value,
            count     = len(actions),
            actions   = actions,
            timestamp = datetime.utcnow(),
        )

    @app.get("/playbooks", tags=["Playbooks"])
    async def get_playbooks() -> dict:
        return {
            "playbook_count": playbook_engine.playbook_count(),
            "playbooks": [
                {
                    "playbook_id": p.playbook_id,
                    "name": p.name,
                    "min_severity": p.min_severity,
                    "action_count": len(p.actions),
                }
                for p in playbook_engine.playbooks
            ],
        }

    @app.post("/playbooks/reload", tags=["Playbooks"])
    async def reload_playbooks() -> dict:
        playbook_engine.load_playbooks()
        return {"reloaded": True, "playbook_count": playbook_engine.playbook_count()}

    @app.get("/stats", response_model=StatsResponse, tags=["Platform"])
    async def get_stats() -> StatsResponse:
        return StatsResponse(
            engine    = EngineID.RESPONSE.value,
            stats     = db.get_stats(),
            timestamp = datetime.utcnow(),
        )

    @app.get("/info", tags=["Platform"])
    async def get_info() -> dict:
        return {
            "platform": METADATA["name"],
            "engine":   EngineID.RESPONSE.value,
            "version":  VERSION,
            "port":     settings.api_port,
        }

    @app.websocket("/ws/cases")
    async def websocket_cases(websocket: WebSocket) -> None:
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