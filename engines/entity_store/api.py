"""
rexdr - Entity Store Service
api.py - FastAPI REST API exposing EntityStore over HTTP

Author  : Rayyan Umair
Date    : 2026-06-23
Purpose : Exposes every EntityStore operation - get, upsert, update
          observation, chain membership, timeline - as REST endpoints.
          This is the only process in the platform that holds a
          writable DuckDB connection to entity_store.duckdb. Every
          engine's local EntityStoreClient calls these endpoints
          instead of touching the file directly.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"One identity. One risk score. Every engine."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
from datetime import datetime
from typing import Any

# -- Third Party -------------------------------------------------------------
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# -- Internal ----------------------------------------------------------------
from rexdr_core.entity_store import EntityStore
from rexdr_core.identity import EngineID, VERSION
from rexdr_core.schemas import EngineObservation, EntityType

# ============================================================================

logger = logging.getLogger(__name__)


# ============================================================================
# Request models
# ============================================================================

class UpdateObservationRequest(BaseModel):
    entity_id: str
    entity_type: EntityType
    engine_id: EngineID
    observation: EngineObservation
    network_zone: str | None = None
    hostname: str | None = None
    mac_address: str | None = None
    os_info: str | None = None
    is_critical_asset: bool = False
    additional_usernames: list[str] | None = None
    additional_ips: list[str] | None = None
    tags: list[str] | None = None


class ChainMembershipRequest(BaseModel):
    entity_id: str
    chain_id: str


class TimelineEventRequest(BaseModel):
    entity_id: str
    engine_id: EngineID
    event_type: str
    description: str
    severity: str
    detection_code: str | None = None
    chain_id: str | None = None
    metadata: dict | None = None


# ============================================================================
# App factory
# ============================================================================

def create_app(store: EntityStore) -> FastAPI:
    app = FastAPI(
        title       = "REXDR - Entity Store Service",
        description = "Shared unified entity registry for all REXDR engines",
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

    # -------------------------------------------------------------------------
    # Health
    # -------------------------------------------------------------------------

    @app.get("/health", tags=["Platform"])
    async def health() -> dict[str, Any]:
        healthy = store.is_healthy()
        return {
            "status":     "healthy" if healthy else "degraded",
            "engine":     "entity_store",
            "version":    VERSION,
            "timestamp":  datetime.utcnow(),
            "db_healthy": healthy,
            "stats":      {"tracked_entities": store.count() if healthy else 0},
        }

    # -------------------------------------------------------------------------
    # Write operations
    # -------------------------------------------------------------------------

    @app.post("/observations", tags=["Entities"])
    async def update_observation(req: UpdateObservationRequest) -> dict:
        """
        Record an engine's latest observation of an entity. The single
        write path every engine calls instead of touching DuckDB directly.
        """
        try:
            entity = store.update_observation(
                entity_id             = req.entity_id,
                entity_type           = req.entity_type,
                engine_id             = req.engine_id,
                observation           = req.observation,
                network_zone          = req.network_zone,
                hostname              = req.hostname,
                mac_address           = req.mac_address,
                os_info               = req.os_info,
                is_critical_asset     = req.is_critical_asset,
                additional_usernames  = req.additional_usernames,
                additional_ips        = req.additional_ips,
                tags                  = req.tags,
            )
            return entity.model_dump(mode="json")
        except Exception as e:
            logger.error("update_observation failed - error=%s", str(e))
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/chains/add", tags=["Entities"])
    async def add_to_chain(req: ChainMembershipRequest) -> dict:
        store.add_to_chain(req.entity_id, req.chain_id)
        return {"added": True}

    @app.post("/chains/remove", tags=["Entities"])
    async def remove_from_chain(req: ChainMembershipRequest) -> dict:
        store.remove_from_chain(req.entity_id, req.chain_id)
        return {"removed": True}

    @app.post("/timeline", tags=["Entities"])
    async def add_timeline_event(req: TimelineEventRequest) -> dict:
        store.add_timeline_event(
            entity_id      = req.entity_id,
            engine_id      = req.engine_id,
            event_type     = req.event_type,
            description    = req.description,
            severity       = req.severity,
            detection_code = req.detection_code,
            chain_id       = req.chain_id,
            metadata       = req.metadata,
        )
        return {"added": True}

    # -------------------------------------------------------------------------
    # Read operations
    # -------------------------------------------------------------------------

    @app.get("/entities/{entity_id}", tags=["Entities"])
    async def get_entity(entity_id: str) -> dict:
        entity = store.get(entity_id)
        if entity is None:
            raise HTTPException(status_code=404, detail=f"Entity {entity_id} not found.")
        return entity.model_dump(mode="json")

    @app.get("/entities", tags=["Entities"])
    async def list_entities(
        limit: int = 100,
        min_score: float = 0.0,
        entity_type: EntityType | None = None,
    ) -> dict:
        entities = store.list_by_risk(limit=limit, min_score=min_score, entity_type=entity_type)
        return {"count": len(entities), "entities": [e.model_dump(mode="json") for e in entities]}

    @app.get("/entities/in-chains", tags=["Entities"])
    async def list_chain_entities() -> dict:
        entities = store.list_in_chains()
        return {"count": len(entities), "entities": [e.model_dump(mode="json") for e in entities]}

    @app.get("/entities/{entity_id}/timeline", tags=["Entities"])
    async def get_timeline(entity_id: str, limit: int = 200) -> dict:
        timeline = store.get_timeline(entity_id, limit=limit)
        return {"count": len(timeline), "timeline": timeline}

    @app.get("/stats", tags=["Platform"])
    async def get_stats() -> dict:
        return {"tracked_entities": store.count()}

    return app