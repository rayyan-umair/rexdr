"""
rexdr - Active Directory Intelligence Engine
api.py - FastAPI REST and WebSocket API for the Identity engine

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Exposes all Identity engine data to the REXDR frontend and
          other engines via REST endpoints and a WebSocket stream.
          Also exposes the account lockdown endpoints used by the
          Response engine during automated containment - disabling
          compromised accounts and revoking Kerberos tickets via LDAP.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Trust, but verify the keys."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import asyncio
import logging
import secrets
import string
from datetime import datetime
from typing import Any

# -- Third Party -------------------------------------------------------------
import yaml
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
from pydantic import BaseModel

# -- Internal ----------------------------------------------------------------
from rexdr_core.identity import METADATA, VERSION, EngineID
from rexdr_core.schemas import AlertSeverity
from identity.config import settings
from identity.database import IdentityDatabase

# ============================================================================

logger = logging.getLogger(__name__)


# ============================================================================
# Response / request models
# ============================================================================

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


class LockdownRequest(BaseModel):
    username: str


# ============================================================================
# WebSocket connection manager
# ============================================================================

class ConnectionManager:
    """Manages active WebSocket connections to the Identity engine."""

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


# ============================================================================
# Lockdown helpers - shared logic for both endpoints
# ============================================================================

def _load_dc_targets() -> list[str]:
    """Load domain controller IPs from targets.yaml."""
    if not settings.winrm_targets_path.exists():
        return []

    with open(settings.winrm_targets_path, "r") as f:
        data = yaml.safe_load(f) or {}

    targets = data.get("targets", [])
    return [
        t["ip"] for t in targets
        if t.get("enabled") and "DC" in t.get("name", "").upper()
    ]


# ============================================================================
# App factory
# ============================================================================

def create_app(db: IdentityDatabase) -> FastAPI:
    """Create and configure the FastAPI application for the Identity engine."""

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
            engine     = EngineID.IDENTITY.value,
            version    = VERSION,
            timestamp  = datetime.utcnow(),
            db_healthy = db_healthy,
            stats      = stats,
        )

    # -------------------------------------------------------------------------
    # Detections
    # -------------------------------------------------------------------------

    @app.get("/detections", response_model=DetectionsResponse, tags=["Detections"])
    async def get_detections(limit: int = 50, severity: str | None = None) -> DetectionsResponse:
        """Get recent detections, optionally filtered by severity."""
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

    # -------------------------------------------------------------------------
    # Stats
    # -------------------------------------------------------------------------

    @app.get("/stats", response_model=StatsResponse, tags=["Platform"])
    async def get_stats() -> StatsResponse:
        """Get engine statistics."""
        return StatsResponse(
            engine    = EngineID.IDENTITY.value,
            stats     = db.get_stats(),
            timestamp = datetime.utcnow(),
        )

    # -------------------------------------------------------------------------
    # Account lockdown - called by the Response engine during containment
    # -------------------------------------------------------------------------

    @app.post("/lockdown/disable", tags=["Lockdown"])
    async def disable_account(request: LockdownRequest) -> dict:
        """
        Disable an Active Directory account as part of automated
        containment. Called by the Response engine's playbook executor.
        Sets the ACCOUNTDISABLE bit on userAccountControl via LDAP using
        the same credentials configured for domain snapshot collection.
        """
        targets = _load_dc_targets()

        if not targets:
            raise HTTPException(status_code=503, detail="No domain controller targets configured.")

        try:
            server = Server(
                targets[0],
                port=settings.ldap_port,
                use_ssl=settings.ldap_use_ssl,
                get_info=ALL,
            )
            conn = Connection(
                server,
                user=f"{settings.winrm_username}@{settings.ldap_domain}",
                password=settings.winrm_password,
                auto_bind=True,
            )

            search_filter = f"(&(objectClass=user)(sAMAccountName={request.username}))"
            conn.search(
                search_base=settings.ldap_base_dn,
                search_filter=search_filter,
                attributes=["userAccountControl"],
            )

            if not conn.entries:
                conn.unbind()
                raise HTTPException(status_code=404, detail=f"Account {request.username} not found.")

            entry_dn = conn.entries[0].entry_dn
            current_uac = int(conn.entries[0].userAccountControl.value)
            # 0x2 (ACCOUNTDISABLE) bit set - disables the account
            new_uac = current_uac | 2

            conn.modify(entry_dn, {"userAccountControl": [(MODIFY_REPLACE, [new_uac])]})
            conn.unbind()

            logger.warning(
                "AD account disabled via lockdown endpoint - username=%s",
                request.username,
            )
            return {"disabled": True, "username": request.username}

        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                "Account disable failed - username=%s error=%s",
                request.username, str(e),
            )
            raise HTTPException(status_code=500, detail=f"Failed to disable account: {str(e)}")

    @app.post("/lockdown/revoke-tickets", tags=["Lockdown"])
    async def revoke_tickets(request: LockdownRequest) -> dict:
        """
        Revoke all active Kerberos tickets for an account, forcing
        re-authentication on next access attempt. Implemented by
        resetting the account password via LDAPS, which invalidates
        existing TGTs domain-wide on supported AD configurations.
        Called by the Response engine's playbook executor.

        Note: this endpoint requires LDAPS (port 636 with a valid
        certificate on the domain controller) regardless of the
        ldap_use_ssl setting elsewhere, since password modification
        over plain LDAP is rejected by Active Directory.
        """
        targets = _load_dc_targets()

        if not targets:
            raise HTTPException(status_code=503, detail="No domain controller targets configured.")

        try:
            server = Server(targets[0], port=636, use_ssl=True, get_info=ALL)
            conn = Connection(
                server,
                user=f"{settings.winrm_username}@{settings.ldap_domain}",
                password=settings.winrm_password,
                auto_bind=True,
            )

            search_filter = f"(&(objectClass=user)(sAMAccountName={request.username}))"
            conn.search(
                search_base=settings.ldap_base_dn,
                search_filter=search_filter,
                attributes=["distinguishedName"],
            )

            if not conn.entries:
                conn.unbind()
                raise HTTPException(status_code=404, detail=f"Account {request.username} not found.")

            entry_dn = conn.entries[0].entry_dn

            # Random password reset invalidates existing Kerberos tickets
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            new_password = "".join(secrets.choice(alphabet) for _ in range(20))

            conn.extend.microsoft.modify_password(entry_dn, new_password)
            conn.unbind()

            logger.warning(
                "Kerberos tickets revoked via password reset - username=%s",
                request.username,
            )
            return {"revoked": True, "username": request.username}

        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                "Ticket revocation failed - username=%s error=%s",
                request.username, str(e),
            )
            raise HTTPException(status_code=500, detail=f"Failed to revoke tickets: {str(e)}")

    # -------------------------------------------------------------------------
    # Platform info
    # -------------------------------------------------------------------------

    @app.get("/info", tags=["Platform"])
    async def get_info() -> dict:
        """Return platform and engine identity information."""
        return {
            "platform": METADATA["name"],
            "engine":   EngineID.IDENTITY.value,
            "version":  VERSION,
            "port":     settings.api_port,
        }

    # -------------------------------------------------------------------------
    # WebSocket - live event stream
    # -------------------------------------------------------------------------

    @app.websocket("/ws/events")
    async def websocket_events(websocket: WebSocket) -> None:
        """WebSocket endpoint for live event and detection streaming."""
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