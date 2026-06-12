"""
rexdr_core
schemas.py - Universal data contracts for the REXDR platform

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Defines every schema used across all eight engines.
          These are the canonical contracts - no engine defines
          its own schemas. Everything flows through these models.
          No raw dicts cross engine boundaries. Ever.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"The foundation everything else is built on."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

# -- Third Party -------------------------------------------------------------
from pydantic import BaseModel, Field

# -- Internal ----------------------------------------------------------------
from rexdr_core.identity import EngineID


# ============================================================================
# Enumerations
# ============================================================================

class AlertSeverity(str, Enum):
    """Severity levels used across all engines and the correlation layer."""
    INFO     = "info"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class EntityType(str, Enum):
    """The type of a tracked entity in the REXDR entity store."""
    IP_ADDRESS   = "ip_address"
    USER_ACCOUNT = "user_account"
    HOSTNAME     = "hostname"
    MAC_ADDRESS  = "mac_address"
    DOMAIN       = "domain"


class ChainSeverity(str, Enum):
    """Severity of a cross-engine attack chain."""
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class DetectionStatus(str, Enum):
    """Lifecycle status of a detection."""
    OPEN         = "open"
    INVESTIGATING = "investigating"
    CONTAINED    = "contained"
    RESOLVED     = "resolved"
    FALSE_POSITIVE = "false_positive"


# ============================================================================
# Network Zone
# ============================================================================

class NetworkZone(BaseModel):
    """
    A logical network segment in the monitored environment.
    Every event is tagged with a source and destination zone.
    Cross-zone events are automatically elevated in severity.
    """

    zone_id:     str = Field(..., description="Unique zone identifier e.g. staff_vlan, guest_wifi")
    display_name: str = Field(..., description="Human-readable zone name")
    cidr:        str = Field(..., description="CIDR notation for this zone e.g. 10.10.1.0/24")
    is_trusted:  bool = Field(default=True, description="Trusted internal zone or untrusted external/guest")
    is_critical:  bool = Field(default=False, description="Critical infrastructure zone - elevated alert weight")


# ============================================================================
# Normalized Telemetry Payload
# ============================================================================

class NormalizedTelemetryPayload(BaseModel):
    """
    The universal event contract all eight engines use to communicate.
    Every raw event - Windows log, network packet, DNS query, AD event -
    is normalized into this schema before any intelligence processing.
    No raw dicts cross engine boundaries. This is the language of REXDR.
    """

    event_id:        UUID       = Field(default_factory=uuid4)
    engine_id:       EngineID   = Field(..., description="Which engine produced this event")
    timestamp:       datetime   = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip:       str | None = Field(default=None)
    destination_ip:  str | None = Field(default=None)
    source_host:     str | None = Field(default=None)
    destination_host: str | None = Field(default=None)
    username:        str | None = Field(default=None)
    event_type:      str        = Field(..., description="Engine-specific event type identifier")
    event_code:      str | None = Field(default=None, description="Windows Event ID or equivalent")
    description:     str        = Field(..., description="Human-readable event description")
    raw_data:        dict[str, Any] = Field(default_factory=dict, description="Original raw event data")
    zone_source:     str | None = Field(default=None, description="Source network zone ID")
    zone_destination: str | None = Field(default=None, description="Destination network zone ID")
    is_cross_zone:   bool       = Field(default=False, description="True if source and destination zones differ")
    tags:            list[str]  = Field(default_factory=list)
    severity:        AlertSeverity = Field(default=AlertSeverity.INFO)


# ============================================================================
# Detection
# ============================================================================

class Detection(BaseModel):
    """
    A confirmed detection produced by an engine's intelligence layer.
    Detections are what get correlated by SIEMulate into attack chains.
    Every detection has a unique code in ENGINE-NNN format.
    """

    detection_id:   UUID          = Field(default_factory=uuid4)
    detection_code: str           = Field(..., description="Unique code e.g. LC-001, STRIKE-002, DNS-003")
    engine_id:      EngineID      = Field(..., description="Engine that produced this detection")
    timestamp:      datetime      = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity:       AlertSeverity = Field(...)
    title:          str           = Field(..., description="Short detection title")
    description:    str           = Field(..., description="Full detection description")
    entity_id:      str           = Field(..., description="ID of the entity this detection is against")
    entity_type:    EntityType    = Field(...)
    evidence:       list[NormalizedTelemetryPayload] = Field(default_factory=list)
    mitre_tactic:   str | None    = Field(default=None, description="MITRE ATT&CK tactic")
    mitre_technique: str | None   = Field(default=None, description="MITRE ATT&CK technique ID")
    status:         DetectionStatus = Field(default=DetectionStatus.OPEN)
    risk_contribution: float      = Field(default=0.0, description="How much this detection contributes to entity risk score 0-100")


# ============================================================================
# Engine Observation
# ============================================================================

class EngineObservation(BaseModel):
    """
    A single engine's latest observation of an entity.
    Every engine writes its observation to the entity store.
    The entity holds one observation per engine at all times.
    """

    engine_id:       EngineID  = Field(...)
    last_seen:       datetime  = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_count:     int       = Field(default=0)
    detection_count: int       = Field(default=0)
    risk_contribution: float   = Field(default=0.0, description="This engine's contribution to entity risk 0-100")
    behavioral_flags: list[str] = Field(default_factory=list, description="Active behavioral indicators")
    latest_detection_code: str | None = Field(default=None)
    metadata:        dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# Entity
# ============================================================================

class Entity(BaseModel):
    """
    A tracked network participant in REXDR.
    This is the core of the unified entity model - one identity
    across all eight engines with a single composite risk score
    that reflects everything REXDR knows about this entity.
    """

    entity_id:          str        = Field(..., description="Canonical identifier - IP, username, or hostname")
    entity_type:        EntityType = Field(...)
    first_seen:         datetime   = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen:          datetime   = Field(default_factory=lambda: datetime.now(timezone.utc))
    risk_score:         float      = Field(default=0.0, description="Composite risk score 0-100 across all engines")
    engine_observations: dict[str, EngineObservation] = Field(
        default_factory=dict,
        description="Keyed by EngineID value. Each engine writes its latest observation here."
    )
    active_chain_ids:   list[str]  = Field(default_factory=list, description="Attack chain IDs this entity is part of")
    network_zone:       str | None = Field(default=None, description="Last observed network zone ID")
    hostname:           str | None = Field(default=None)
    mac_address:        str | None = Field(default=None)
    os_info:            str | None = Field(default=None)
    known_usernames:    list[str]  = Field(default_factory=list)
    known_ips:          list[str]  = Field(default_factory=list)
    is_critical_asset:  bool       = Field(default=False)
    tags:               list[str]  = Field(default_factory=list)


# ============================================================================
# Attack Chain
# ============================================================================

class AttackChain(BaseModel):
    """
    A correlated sequence of detections from two or more engines
    against the same entity, forming a coherent attack narrative.
    This is REXDR's primary output unit - the thing no individual
    engine could produce on its own.
    """

    chain_id:         UUID           = Field(default_factory=uuid4)
    created_at:       datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at:       datetime       = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity:         ChainSeverity  = Field(...)
    title:            str            = Field(..., description="Short chain title e.g. Credential Theft to Exfiltration")
    narrative:        str            = Field(..., description="Full 5W+H investigation narrative")
    entity_id:        str            = Field(..., description="Primary entity this chain is against")
    contributing_engines: list[EngineID] = Field(..., description="All engines that contributed detections")
    detections:       list[Detection] = Field(..., description="All detections in this chain in chronological order")
    mitre_tactics:    list[str]      = Field(default_factory=list)
    mitre_techniques: list[str]      = Field(default_factory=list)
    is_active:        bool           = Field(default=True)
    is_contained:     bool           = Field(default=False)
    case_file_id:     str | None     = Field(default=None)


# ============================================================================
# Alert
# ============================================================================

class Alert(BaseModel):
    """
    A notification unit surfaced to the REXDR frontend and
    the response engine. Alerts are generated from both
    individual detections and cross-engine attack chains.
    """

    alert_id:    UUID          = Field(default_factory=uuid4)
    timestamp:   datetime      = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity:    AlertSeverity = Field(...)
    title:       str           = Field(...)
    description: str           = Field(...)
    engine_id:   EngineID      = Field(...)
    entity_id:   str           = Field(...)
    detection_id: UUID | None  = Field(default=None)
    chain_id:    UUID | None   = Field(default=None, description="Set if this alert is from a cross-engine chain")
    is_chain:    bool          = Field(default=False)
    acknowledged: bool         = Field(default=False)
    tags:        list[str]     = Field(default_factory=list)


# ============================================================================
# Case File
# ============================================================================

class CaseFile(BaseModel):
    """
    An immutable forensic record of a REXDR incident.
    Generated by the response engine. Written once, never modified.
    Contains the full cross-engine evidence chain with SHA-256 integrity.
    """

    case_id:          UUID      = Field(default_factory=uuid4)
    created_at:       datetime  = Field(default_factory=lambda: datetime.now(timezone.utc))
    chain_id:         UUID      = Field(...)
    entity_id:        str       = Field(...)
    severity:         ChainSeverity = Field(...)
    title:            str       = Field(...)
    narrative:        str       = Field(..., description="Full 5W+H incident narrative")
    analyst:          str       = Field(default="REXDR Automated Response")
    actions_taken:    list[str] = Field(default_factory=list)
    evidence_hashes:  dict[str, str] = Field(default_factory=dict, description="SHA-256 hashes of all evidence artifacts")
    chain_hash:       str       = Field(..., description="SHA-256 hash of the full chain at time of case creation")
    is_closed:        bool      = Field(default=False)
    closed_at:        datetime | None = Field(default=None)
    resolution:       str | None = Field(default=None)