"""
rexdr - Windows Event Intelligence Engine
normalizer.py - Raw Windows event normalization pipeline

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Converts raw Windows Event Log entries received from the
          Go harvester into NormalizedTelemetryPayload objects.
          This is the first intelligence layer - every raw event
          passes through here before any detection logic runs.
          Handles Security, System, and Application log normalization.
          Maps Windows Event IDs to meaningful event types.
          Nothing outside this module touches raw event data.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Every log tells a story."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
from datetime import datetime, timezone

# -- Internal ----------------------------------------------------------------
from rexdr_core.identity import EngineID
from rexdr_core.schemas import AlertSeverity, NormalizedTelemetryPayload

# ============================================================================

logger = logging.getLogger(__name__)

# ============================================================================
# Windows Event ID registry
# Maps Event ID -> (event_type, description, default_severity)
# ============================================================================

SECURITY_EVENT_MAP: dict[int, tuple[str, str, AlertSeverity]] = {

    # -- Authentication events ------------------------------------------------
    4624: ("successful_logon",      "Successful account logon",                     AlertSeverity.INFO),
    4625: ("failed_logon",          "Failed account logon attempt",                 AlertSeverity.LOW),
    4634: ("logoff",                "Account logoff",                               AlertSeverity.INFO),
    4648: ("explicit_credential_logon", "Logon using explicit credentials",         AlertSeverity.MEDIUM),
    4672: ("special_privilege_logon", "Special privileges assigned to new logon",   AlertSeverity.MEDIUM),
    4768: ("kerberos_tgt_request",  "Kerberos TGT authentication ticket requested", AlertSeverity.INFO),
    4769: ("kerberos_service_ticket", "Kerberos service ticket requested",          AlertSeverity.INFO),
    4771: ("kerberos_pre_auth_failed", "Kerberos pre-authentication failed",        AlertSeverity.LOW),
    4776: ("ntlm_logon_attempt",    "NTLM credential validation attempt",           AlertSeverity.LOW),

    # -- Account management events -------------------------------------------
    4720: ("account_created",       "User account created",                         AlertSeverity.MEDIUM),
    4722: ("account_enabled",       "User account enabled",                         AlertSeverity.LOW),
    4723: ("password_change_attempt", "Password change attempt",                    AlertSeverity.LOW),
    4724: ("password_reset",        "Password reset attempt",                       AlertSeverity.MEDIUM),
    4725: ("account_disabled",      "User account disabled",                        AlertSeverity.LOW),
    4726: ("account_deleted",       "User account deleted",                         AlertSeverity.MEDIUM),
    4728: ("member_added_global_group", "Member added to global security group",    AlertSeverity.MEDIUM),
    4732: ("member_added_local_group", "Member added to local security group",      AlertSeverity.MEDIUM),
    4756: ("member_added_universal_group", "Member added to universal security group", AlertSeverity.MEDIUM),
    4738: ("account_changed",       "User account properties changed",              AlertSeverity.LOW),
    4740: ("account_locked_out",    "User account locked out",                      AlertSeverity.MEDIUM),

    # -- Privilege and policy events -----------------------------------------
    4670: ("permissions_changed",   "Permissions on object changed",                AlertSeverity.MEDIUM),
    4673: ("privileged_service_called", "Privileged service called",                AlertSeverity.LOW),
    4674: ("privileged_object_operation", "Operation attempted on privileged object", AlertSeverity.LOW),
    4703: ("token_right_adjusted",  "Token right adjusted",                         AlertSeverity.LOW),
    4704: ("user_right_assigned",   "User right assigned",                          AlertSeverity.MEDIUM),
    4705: ("user_right_removed",    "User right removed",                           AlertSeverity.MEDIUM),

    # -- Process and service events ------------------------------------------
    4688: ("process_created",       "New process created",                          AlertSeverity.INFO),
    4689: ("process_exited",        "Process exited",                               AlertSeverity.INFO),
    4697: ("service_installed",     "Service installed on the system",              AlertSeverity.HIGH),
    7045: ("new_service_installed", "New service installed",                        AlertSeverity.HIGH),

    # -- Logon type specific -------------------------------------------------
    4648: ("runas_logon",           "Explicit credential logon - possible runas",   AlertSeverity.MEDIUM),

    # -- Object access events ------------------------------------------------
    4663: ("object_access_attempt", "Attempt to access object",                     AlertSeverity.INFO),
    4656: ("object_handle_requested", "Handle to object requested",                 AlertSeverity.INFO),

    # -- Network events ------------------------------------------------------
    5140: ("network_share_accessed", "Network share object accessed",               AlertSeverity.LOW),
    5145: ("network_share_checked", "Network share access check",                   AlertSeverity.INFO),

    # -- Audit policy events -------------------------------------------------
    4719: ("audit_policy_changed",  "System audit policy changed",                  AlertSeverity.HIGH),
    4907: ("audit_settings_changed", "Audit settings on object changed",            AlertSeverity.MEDIUM),

    # -- Credential access ---------------------------------------------------
    4782: ("account_password_hash_accessed", "Password hash of account accessed",  AlertSeverity.CRITICAL),
    4793: ("password_policy_checking_api_called", "Password policy checking API called", AlertSeverity.LOW),

    # -- Shadow copy and backup events ---------------------------------------
    4904: ("security_event_source_registered", "Security event source registered", AlertSeverity.LOW),
    524:  ("system_time_changed",   "System time changed",                          AlertSeverity.LOW),
}

SYSTEM_EVENT_MAP: dict[int, tuple[str, str, AlertSeverity]] = {
    7036: ("service_state_changed", "Service entered running or stopped state",     AlertSeverity.INFO),
    7040: ("service_start_type_changed", "Service start type changed",              AlertSeverity.MEDIUM),
    7045: ("new_service_installed", "New service installed",                        AlertSeverity.HIGH),
    104:  ("event_log_cleared",     "Event log cleared",                            AlertSeverity.CRITICAL),
    1102: ("audit_log_cleared",     "Security audit log cleared",                   AlertSeverity.CRITICAL),
}

APPLICATION_EVENT_MAP: dict[int, tuple[str, str, AlertSeverity]] = {
    1000: ("application_error",     "Application error",                            AlertSeverity.LOW),
    1001: ("application_crash",     "Application crash",                            AlertSeverity.LOW),
    1026: ("net_runtime_error",     ".NET runtime error",                           AlertSeverity.INFO),
}

# Logon type codes to human-readable names
LOGON_TYPE_MAP: dict[int, str] = {
    2:  "interactive",
    3:  "network",
    4:  "batch",
    5:  "service",
    7:  "unlock",
    8:  "network_cleartext",
    9:  "new_credentials",
    10: "remote_interactive",
    11: "cached_interactive",
}


# ============================================================================
# Normalizer
# ============================================================================

class WindowsEventNormalizer:
    """
    Converts raw Windows Event Log entries into NormalizedTelemetryPayload.
    One instance per engine. Stateless - safe to call from any context.
    """

    def normalize(
        self,
        raw_event: dict,
        zone_source: str | None = None,
        zone_destination: str | None = None,
    ) -> NormalizedTelemetryPayload | None:
        """
        Normalize a raw Windows event dict into a NormalizedTelemetryPayload.
        Returns None if the event ID is unknown and should be skipped.
        The raw_event dict comes directly from the Go harvester JSON output.
        """
        try:
            return self._normalize(raw_event, zone_source, zone_destination)
        except Exception as e:
            logger.warning(
                "Failed to normalize event - event_id=%s error=%s",
                raw_event.get("event_id"),
                str(e),
            )
            return None

    def _normalize(
        self,
        raw: dict,
        zone_source: str | None,
        zone_destination: str | None,
    ) -> NormalizedTelemetryPayload | None:

        log_name  = raw.get("log_name", "")
        event_id  = int(raw.get("event_id", 0))
        event_map = self._get_event_map(log_name)
        mapping   = event_map.get(event_id)

        if not mapping:
            logger.debug(
                "Unknown event ID - log=%s event_id=%d skipping",
                log_name,
                event_id,
            )
            return None

        event_type, base_description, severity = mapping

        # Extract identity fields from the event data dict
        event_data = raw.get("event_data", {}) or {}

        username        = self._extract_username(event_data)
        source_ip       = self._extract_ip(event_data, "IpAddress") or raw.get("target_ip")
        destination_ip  = raw.get("target_ip")
        source_host     = self._extract_string(event_data, "WorkstationName") or raw.get("computer")
        destination_host = raw.get("target_host") or raw.get("computer")
        logon_type_raw  = event_data.get("LogonType")
        logon_type      = LOGON_TYPE_MAP.get(int(logon_type_raw), "unknown") if logon_type_raw else None

        # Build a richer description where we have the data
        description = self._build_description(
            base_description, username, source_ip, destination_host, logon_type
        )

        # Override severity for audit log clearing regardless of event map
        if event_id in (104, 1102):
            severity = AlertSeverity.CRITICAL

        # Parse timestamp
        timestamp = self._parse_timestamp(raw.get("time_created"))

        is_cross_zone = (
            zone_source is not None
            and zone_destination is not None
            and zone_source != zone_destination
        )

        tags = self._build_tags(event_type, log_name, logon_type, is_cross_zone)

        return NormalizedTelemetryPayload(
            engine_id        = EngineID.WINDOWS_EVENT,
            timestamp        = timestamp,
            source_ip        = source_ip,
            destination_ip   = destination_ip,
            source_host      = source_host,
            destination_host = destination_host,
            username         = username,
            event_type       = event_type,
            event_code       = str(event_id),
            description      = description,
            raw_data         = raw,
            zone_source      = zone_source,
            zone_destination = zone_destination,
            is_cross_zone    = is_cross_zone,
            tags             = tags,
            severity         = severity,
        )

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _get_event_map(self, log_name: str) -> dict:
        log_lower = log_name.lower()
        if "security" in log_lower:
            return SECURITY_EVENT_MAP
        if "system" in log_lower:
            return SYSTEM_EVENT_MAP
        if "application" in log_lower:
            return APPLICATION_EVENT_MAP
        return {}

    def _extract_username(self, event_data: dict) -> str | None:
        for key in ("SubjectUserName", "TargetUserName", "UserName"):
            val = event_data.get(key)
            if val and val not in ("-", "ANONYMOUS LOGON", ""):
                return val
        return None

    def _extract_ip(self, event_data: dict, key: str) -> str | None:
        val = event_data.get(key, "")
        if val and val not in ("-", "::1", "127.0.0.1", ""):
            return val
        return None

    def _extract_string(self, event_data: dict, key: str) -> str | None:
        val = event_data.get(key, "")
        return val if val and val != "-" else None

    def _build_description(
        self,
        base: str,
        username: str | None,
        source_ip: str | None,
        destination_host: str | None,
        logon_type: str | None,
    ) -> str:
        parts = [base]
        if username:
            parts.append(f"user={username}")
        if source_ip:
            parts.append(f"source={source_ip}")
        if destination_host:
            parts.append(f"target={destination_host}")
        if logon_type:
            parts.append(f"logon_type={logon_type}")
        return " | ".join(parts)

    def _parse_timestamp(self, raw_ts) -> datetime:
        if raw_ts is None:
            return datetime.now(timezone.utc)
        if isinstance(raw_ts, datetime):
            return raw_ts.replace(tzinfo=timezone.utc) if raw_ts.tzinfo is None else raw_ts
        try:
            ts = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
            return ts
        except Exception:
            return datetime.now(timezone.utc)

    def _build_tags(
        self,
        event_type: str,
        log_name: str,
        logon_type: str | None,
        is_cross_zone: bool,
    ) -> list[str]:
        tags = [f"log:{log_name.lower()}", f"type:{event_type}"]
        if logon_type:
            tags.append(f"logon_type:{logon_type}")
        if is_cross_zone:
            tags.append("cross_zone")
        return tags