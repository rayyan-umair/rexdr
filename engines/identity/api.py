"""
rexdr - Active Directory Intelligence Engine
api.py - FastAPI REST and WebSocket API for the Identity engine

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Exposes all Identity engine data to the REXDR frontend and
          other engines via REST endpoints and a WebSocket stream.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Trust, but verify the keys."

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
from rexdr_core.schemas import AlertSeverity
from identity.config import settings
from identity.database import IdentityDatabase

# ============================================================================

logger = logging.getLogger(__name__)


class HealthResponse(BaseModel):
    status:     str
    engine:     str
    version:    str
    timestamp:  datetime
    db_healthy: bool
    stats:      dict[str, Any]


class DetectionsResponse(BaseModel):
    engine:     str
    count:      int
    detections: list[dict[str, Any]]
    timestamp:  datetime


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


def create_app(db: IdentityDatabase) -> FastAPI:
    app = FastAPI(
        title       = "REXDR - Active Directory Intelligence",
        description = "Active Directory Intelligence engine API",
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
            status     = "healthy" if db_healthy else "degraded",
            engine     = EngineID.IDENTITY.value,
            version    = VERSION,
            timestamp  = datetime.utcnow(),
            db_healthy = db_healthy,
            stats      = stats,
        )

    @app.get("/detections", response_model=DetectionsResponse, tags=["Detections"])
    async def get_detections(limit: int = 50, severity: str | None = None) -> DetectionsResponse:
        if limit > 500:
            raise HTTPException(status_code=400, detail="Limit cannot exceed 500.")

        severity_filter = None
        if severity:
            try:
                severity_filter = AlertSeverity(severity.lower())
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}.")

        detections = db.get_recent_detections(limit=limit, severity=severity_filter)
        return DetectionsResponse(
            engine     = EngineID.IDENTITY.value,
            count      = len(detections),
            detections = detections,
            timestamp  = datetime.utcnow(),
        )

    @app.get("/stats", response_model=StatsResponse, tags=["Platform"])
    async def get_stats() -> StatsResponse:
        return StatsResponse(
            engine    = EngineID.IDENTITY.value,
            stats     = db.get_stats(),
            timestamp = datetime.utcnow(),
        )

    @app.get("/info", tags=["Platform"])
    async def get_info() -> dict:
        return {
            "platform": METADATA["name"],
            "engine":   EngineID.IDENTITY.value,
            "version":  VERSION,
            "port":     settings.api_port,
        }

    @app.websocket("/ws/events")
    async def websocket_events(websocket: WebSocket) -> None:
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