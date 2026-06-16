"""
rexdr - Windows Event Intelligence Engine
api.py - FastAPI REST and WebSocket API for the Windows Event engine

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Exposes all Windows Event engine data to the REXDR frontend
          and other engines via REST endpoints and a WebSocket stream.
          Every endpoint returns clean, typed responses. No raw DuckDB
          rows are ever returned directly to the caller. The WebSocket
          stream pushes live detections and events to the frontend in
          real time as they are produced by the intelligence pipeline.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Every log tells a story."

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
from windows_event.config import settings
from windows_event.database import WindowsEventDatabase

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


class EventsResponse(BaseModel):
    engine:    str
    count:     int
    events:    list[dict[str, Any]]
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
    """
    Manages active WebSocket connections to the Windows Event engine.
    Broadcasts live detections and events to all connected clients.
    """

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
        """Broadcast a message to all connected WebSocket clients."""
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

def create_app(db: WindowsEventDatabase) -> FastAPI:
    """
    Create and configure the FastAPI application for the Windows Event engine.
    Receives the database instance from main.py via dependency injection.
    """

    app = FastAPI(
        title       = "REXDR - Windows Event Intelligence",
        description = "Windows Event Intelligence engine API",
        version     = VERSION,
        docs_url    = "/docs",
        redoc_url   = "/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins  = ["*"],
        allow_methods  = ["*"],
        allow_headers  = ["*"],
    )

    manager = ConnectionManager()

    # Store manager on app state so main.py can broadcast to it
    app.state.ws_manager = manager
    app.state.db = db

    # -------------------------------------------------------------------------
    # Health
    # -------------------------------------------------------------------------

    @app.get("/health", response_model=HealthResponse, tags=["Platform"])
    async def health() -> HealthResponse:
        """
        Health check endpoint. Used by Docker Compose health checks
        and the Tkinter launcher status dashboard.
        Returns healthy only when the database is connected and responsive.
        """
        db_healthy = db.is_healthy()
        stats = db.get_stats() if db_healthy else {}

        return HealthResponse(
            status     = "healthy" if db_healthy else "degraded",
            engine     = EngineID.WINDOWS_EVENT.value,
            version    = VERSION,
            timestamp  = datetime.utcnow(),
            db_healthy = db_healthy,
            stats      = stats,
        )

    # -------------------------------------------------------------------------
    # Events
    # -------------------------------------------------------------------------

    @app.get("/events", response_model=EventsResponse, tags=["Events"])
    async def get_events(limit: int = 100) -> EventsResponse:
        """
        Get recent normalized Windows events.
        Used by the frontend event stream view.
        """
        if limit > 1000:
            raise HTTPException(
                status_code = 400,
                detail      = "Limit cannot exceed 1000.",
            )

        events = db.get_recent_events(limit=limit)

        return EventsResponse(
            engine    = EngineID.WINDOWS_EVENT.value,
            count     = len(events),
            events    = events,
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
        """
        Get recent detections from the Windows Event engine.
        Optionally filter by severity - info, low, medium, high, critical.
        """
        if limit > 500:
            raise HTTPException(
                status_code = 400,
                detail      = "Limit cannot exceed 500.",
            )

        severity_filter = None
        if severity:
            try:
                severity_filter = AlertSeverity(severity.lower())
            except ValueError:
                raise HTTPException(
                    status_code = 400,
                    detail      = f"Invalid severity: {severity}. "
                                  f"Valid values: info, low, medium, high, critical.",
                )

        detections = db.get_recent_detections(
            limit    = limit,
            severity = severity_filter,
        )

        return DetectionsResponse(
            engine     = EngineID.WINDOWS_EVENT.value,
            count      = len(detections),
            detections = detections,
            timestamp  = datetime.utcnow(),
        )

    @app.get(
        "/detections/{detection_id}",
        tags=["Detections"],
    )
    async def get_detection(detection_id: str) -> dict:
        """Get a single detection by ID."""
        detections = db.get_recent_detections(limit=1000)
        for d in detections:
            if d.get("detection_id") == detection_id:
                return d
        raise HTTPException(
            status_code = 404,
            detail      = f"Detection {detection_id} not found.",
        )

    # -------------------------------------------------------------------------
    # Stats
    # -------------------------------------------------------------------------

    @app.get("/stats", response_model=StatsResponse, tags=["Platform"])
    async def get_stats() -> StatsResponse:
        """
        Get engine statistics.
        Used by the Tkinter launcher and the frontend dashboard.
        """
        return StatsResponse(
            engine    = EngineID.WINDOWS_EVENT.value,
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
            "engine":   EngineID.WINDOWS_EVENT.value,
            "version":  VERSION,
            "port":     settings.api_port,
        }

    # -------------------------------------------------------------------------
    # WebSocket - live event stream
    # -------------------------------------------------------------------------

    @app.websocket("/ws/events")
    async def websocket_events(websocket: WebSocket) -> None:
        """
        WebSocket endpoint for live event streaming.
        The frontend connects here to receive real-time events
        and detections as they are produced by the intelligence pipeline.
        The intelligence pipeline broadcasts to this endpoint via
        app.state.ws_manager.broadcast().
        """
        await manager.connect(websocket)
        try:
            while True:
                # Keep connection alive - actual data is pushed via broadcast()
                await asyncio.sleep(30)
                await websocket.send_json({"type": "ping"})
        except WebSocketDisconnect:
            manager.disconnect(websocket)
        except Exception as e:
            logger.error("WebSocket error - error=%s", str(e))
            manager.disconnect(websocket)

    return app