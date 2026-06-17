"""
rexdr - Network Flow Intelligence Engine
api.py - FastAPI REST and WebSocket API for the Network Flow engine

Author  : Rayyan Umair
Date    : 2026-06-17
Purpose : Exposes all Network Flow engine data to the REXDR frontend
          and other engines via REST endpoints and a WebSocket stream.
          Every endpoint returns clean, typed responses. The WebSocket
          stream pushes live flows and detections to the frontend in
          real time as they are produced by the intelligence pipeline.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Silence the noise, strike the signal."

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
from network_flow.config import settings
from network_flow.database import NetworkFlowDatabase

# ============================================================================

logger = logging.getLogger(__name__)

# ============================================================================
# Response models
# ============================================================================

class HealthResponse(BaseModel):
    status:     str
    engine:     str
    version:    str
    timestamp:  datetime
    db_healthy: bool
    stats:      dict[str, Any]


class FlowsResponse(BaseModel):
    engine:    str
    count:     int
    flows:     list[dict[str, Any]]
    timestamp: datetime


class DetectionsResponse(BaseModel):
    engine:     str
    count:      int
    detections: list[dict[str, Any]]
    timestamp:  datetime


class StatsResponse(BaseModel):
    engine:    str
    stats:     dict[str, Any]
    timestamp: datetime


# ============================================================================
# WebSocket connection manager
# ============================================================================

class ConnectionManager:
    """Manages active WebSocket connections to the Network Flow engine."""

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

def create_app(db: NetworkFlowDatabase) -> FastAPI:
    """Create and configure the FastAPI application for the Network Flow engine."""

    app = FastAPI(
        title       = "REXDR - Network Flow Intelligence",
        description = "Network Flow Intelligence engine API",
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

    # -------------------------------------------------------------------------
    # Health
    # -------------------------------------------------------------------------

    @app.get("/health", response_model=HealthResponse, tags=["Platform"])
    async def health() -> HealthResponse:
        """Health check endpoint for Docker and the Tkinter launcher."""
        db_healthy = db.is_healthy()
        stats = db.get_stats() if db_healthy else {}

        return HealthResponse(
            status     = "healthy" if db_healthy else "degraded",
            engine     = EngineID.NETWORK_FLOW.value,
            version    = VERSION,
            timestamp  = datetime.utcnow(),
            db_healthy = db_healthy,
            stats      = stats,
        )

    # -------------------------------------------------------------------------
    # Flows
    # -------------------------------------------------------------------------

    @app.get("/flows", response_model=FlowsResponse, tags=["Flows"])
    async def get_flows(limit: int = 100) -> FlowsResponse:
        """Get recent network flow records."""
        if limit > 1000:
            raise HTTPException(status_code=400, detail="Limit cannot exceed 1000.")

        flows = db.get_recent_flows(limit=limit)

        return FlowsResponse(
            engine    = EngineID.NETWORK_FLOW.value,
            count     = len(flows),
            flows     = flows,
            timestamp = datetime.utcnow(),
        )

    # -------------------------------------------------------------------------
    # Detections
    # -------------------------------------------------------------------------

    @app.get("/detections", response_model=DetectionsResponse, tags=["Detections"])
    async def get_detections(
        limit:    int = 50,
        severity: str | None = None,
    ) -> DetectionsResponse:
        """Get recent detections, optionally filtered by severity."""
        if limit > 500:
            raise HTTPException(status_code=400, detail="Limit cannot exceed 500.")

        severity_filter = None
        if severity:
            try:
                severity_filter = AlertSeverity(severity.lower())
            except ValueError:
                raise HTTPException(
                    status_code = 400,
                    detail      = f"Invalid severity: {severity}.",
                )

        detections = db.get_recent_detections(limit=limit, severity=severity_filter)

        return DetectionsResponse(
            engine     = EngineID.NETWORK_FLOW.value,
            count      = len(detections),
            detections = detections,
            timestamp  = datetime.utcnow(),
        )

    # -------------------------------------------------------------------------
    # Stats
    # -------------------------------------------------------------------------

    @app.get("/stats", response_model=StatsResponse, tags=["Platform"])
    async def get_stats() -> StatsResponse:
        """Get engine statistics."""
        return StatsResponse(
            engine    = EngineID.NETWORK_FLOW.value,
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
            "engine":   EngineID.NETWORK_FLOW.value,
            "version":  VERSION,
            "port":     settings.api_port,
        }

    # -------------------------------------------------------------------------
    # WebSocket - live flow stream
    # -------------------------------------------------------------------------

    @app.websocket("/ws/flows")
    async def websocket_flows(websocket: WebSocket) -> None:
        """WebSocket endpoint for live flow and detection streaming."""
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