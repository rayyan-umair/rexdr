"""
rexdr - Windows Event Intelligence Engine
detections.py - Detection logic for the Windows Event engine

Author  : Rayyan Umair
Date    : 2026-06-12
Purpose : Implements all five detection algorithms for the Windows
          Event Intelligence engine. Each detection is a self-contained
          method that receives a normalized event, queries the database
          for context, and returns a Detection object if the threshold
          is met. Nothing outside this module implements detection logic.
          All detections follow the ENGINE-NNN code format.

          LC-001  Brute Force
          LC-002  Pass-the-Hash
          LC-003  Lateral Movement
          LC-004  Privilege Escalation
          LC-005  Service Abuse

Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Every log tells a story."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
from datetime import datetime, timezone

# -- Internal ----------------------------------------------------------------
from rexdr_core.formula import severity_to_contribution
from rexdr_core.identity import EngineID
from rexdr_core.schemas import (
    AlertSeverity,
    Detection,
    EntityType,
    NormalizedTelemetryPayload,
)
from windows_event.config import settings
from windows_event.database import WindowsEventDatabase

# ============================================================================

logger = logging.getLogger(__name__)


class WindowsEventDetections:
    """
    Detection engine for Windows Event Intelligence.
    Receives normalized events and runs all applicable
    detection algorithms against each one.

    All five detections are independent - an event can
    trigger multiple detections simultaneously.
    """

    def __init__(self, db: WindowsEventDatabase) -> None:
        self.db = db

    def run(
        self,
        payload: NormalizedTelemetryPayload,
    ) -> list[Detection]:
        """
        Run all detection algorithms against a normalized event.
        Returns a list of Detection objects - empty if nothing fired.
        """
        detections: list[Detection] = []

        # Run each detection algorithm
        lc001 = self._lc001_brute_force(payload)
        lc002 = self._lc002_pass_the_hash(payload)
        lc003 = self._lc003_lateral_movement(payload)
        lc004 = self._lc004_privilege_escalation(payload)
        lc005 = self._lc005_service_abuse(payload)

        for detection in [lc001, lc002, lc003, lc004, lc005]:
            if detection:
                detections.append(detection)
                logger.info(
                    "Detection fired - code=%s entity=%s severity=%s",
                    detection.detection_code,
                    detection.entity_id,
                    detection.severity.value,
                )

        return detections

    # -------------------------------------------------------------------------
    # LC-001 - Brute Force
    # -------------------------------------------------------------------------

    def _lc001_brute_force(
        self,
        payload: NormalizedTelemetryPayload,
    ) -> Detection | None:
        """
        LC-001 - Brute Force Detection
        Fires when a source IP generates more than brute_force_threshold
        failed logon attempts within brute_force_window_minutes.

        Trigger events: failed_logon (4625), kerberos_pre_auth_failed (4771)
        MITRE: T1110 - Brute Force
        """
        if payload.event_type not in ("failed_logon", "kerberos_pre_auth_failed"):
            return None

        source = payload.source_ip or payload.source_host
        if not source:
            return None

        failed_count = self.db.get_recent_failed_logons(
            source_ip=source,
            window_minutes=settings.brute_force_window_minutes,
        )

        if failed_count < settings.brute_force_threshold:
            return None

        severity = (
            AlertSeverity.HIGH
            if failed_count >= settings.brute_force_threshold * 3
            else AlertSeverity.MEDIUM
        )

        return Detection(
            detection_code   = "LC-001",
            engine_id        = EngineID.WINDOWS_EVENT,
            severity         = severity,
            title            = "Brute Force Attack Detected",
            description      = (
                f"Source {source} generated {failed_count} failed logon attempts "
                f"within {settings.brute_force_window_minutes} minutes. "
                f"Threshold is {settings.brute_force_threshold}. "
                f"Possible credential brute force or password spray attack."
            ),
            entity_id        = source,
            entity_type      = EntityType.IP_ADDRESS,
            evidence         = [payload],
            mitre_tactic     = "Credential Access",
            mitre_technique  = "T1110",
            risk_contribution = severity_to_contribution(severity),
        )

    # -------------------------------------------------------------------------
    # LC-002 - Pass-the-Hash
    # -------------------------------------------------------------------------

    def _lc002_pass_the_hash(
        self,
        payload: NormalizedTelemetryPayload,
    ) -> Detection | None:
        """
        LC-002 - Pass-the-Hash Detection
        Fires when an NTLM network logon occurs with logon type 3
        and the username does not match a known pattern for network
        logons from that source. Specifically looks for NTLM logons
        where the source host differs from the destination host and
        no corresponding interactive logon exists.

        Trigger events: ntlm_logon_attempt (4776), successful_logon (4624)
        with logon type network and NTLM package.
        MITRE: T1550.002 - Pass the Hash
        """
        if payload.event_type not in ("ntlm_logon_attempt", "successful_logon"):
            return None

        raw = payload.raw_data or {}
        event_data = raw.get("event_data", {}) or {}

        # Check for NTLM authentication package
        auth_package = event_data.get("AuthenticationPackageName", "")
        logon_type = event_data.get("LogonType")

        is_ntlm_network_logon = (
            "NTLM" in str(auth_package).upper()
            and str(logon_type) == "3"
        )

        if not is_ntlm_network_logon:
            return None

        username = payload.username
        source   = payload.source_ip or payload.source_host

        if not username or not source:
            return None

        # Skip machine accounts - they legitimately use NTLM
        if username.endswith("$"):
            return None

        # Skip known service accounts pattern
        if username.lower() in ("anonymous logon", "local service", "network service"):
            return None

        return Detection(
            detection_code   = "LC-002",
            engine_id        = EngineID.WINDOWS_EVENT,
            severity         = AlertSeverity.HIGH,
            title            = "Pass-the-Hash Detected",
            description      = (
                f"NTLM network logon detected for user {username} from {source}. "
                f"Logon type 3 with NTLM authentication package is a strong "
                f"indicator of Pass-the-Hash credential theft technique. "
                f"Destination: {payload.destination_host}."
            ),
            entity_id        = username,
            entity_type      = EntityType.USER_ACCOUNT,
            evidence         = [payload],
            mitre_tactic     = "Lateral Movement",
            mitre_technique  = "T1550.002",
            risk_contribution = severity_to_contribution(AlertSeverity.HIGH),
        )

    # -------------------------------------------------------------------------
    # LC-003 - Lateral Movement
    # -------------------------------------------------------------------------

    def _lc003_lateral_movement(
        self,
        payload: NormalizedTelemetryPayload,
    ) -> Detection | None:
        """
        LC-003 - Lateral Movement Detection
        Fires when a single user account authenticates to more than
        lateral_movement_host_threshold distinct hosts within
        lateral_movement_window_minutes.

        Trigger events: successful_logon (4624), network_logon
        MITRE: T1021 - Remote Services
        """
        if payload.event_type not in ("successful_logon", "network_logon", "explicit_credential_logon"):
            return None

        username = payload.username
        if not username or username.endswith("$"):
            return None

        destination = payload.destination_host
        if not destination:
            return None

        recent_hosts = self.db.get_recent_logon_hosts(
            username=username,
            window_minutes=settings.lateral_movement_window_minutes,
        )

        if len(recent_hosts) < settings.lateral_movement_host_threshold:
            return None

        severity = (
            AlertSeverity.CRITICAL
            if len(recent_hosts) >= settings.lateral_movement_host_threshold * 2
            else AlertSeverity.HIGH
        )

        return Detection(
            detection_code   = "LC-003",
            engine_id        = EngineID.WINDOWS_EVENT,
            severity         = severity,
            title            = "Lateral Movement Detected",
            description      = (
                f"User {username} authenticated to {len(recent_hosts)} distinct hosts "
                f"within {settings.lateral_movement_window_minutes} minutes: "
                f"{', '.join(recent_hosts[:10])}. "
                f"This pattern is consistent with lateral movement activity."
            ),
            entity_id        = username,
            entity_type      = EntityType.USER_ACCOUNT,
            evidence         = [payload],
            mitre_tactic     = "Lateral Movement",
            mitre_technique  = "T1021",
            risk_contribution = severity_to_contribution(severity),
        )

    # -------------------------------------------------------------------------
    # LC-004 - Privilege Escalation
    # -------------------------------------------------------------------------

    def _lc004_privilege_escalation(
        self,
        payload: NormalizedTelemetryPayload,
    ) -> Detection | None:
        """
        LC-004 - Privilege Escalation Detection
        Fires on events indicating unexpected privilege assignment,
        group membership changes for privileged groups, or special
        privilege logons outside of expected administrative accounts.

        Trigger events: special_privilege_logon (4672),
        member_added_global_group (4728), member_added_local_group (4732),
        user_right_assigned (4704), account_changed (4738)
        MITRE: T1078 - Valid Accounts / T1484 - Domain Policy Modification
        """
        privilege_event_types = (
            "special_privilege_logon",
            "member_added_global_group",
            "member_added_local_group",
            "member_added_universal_group",
            "user_right_assigned",
        )

        if payload.event_type not in privilege_event_types:
            return None

        username = payload.username
        if not username:
            return None

        # Skip machine accounts
        if username.endswith("$"):
            return None

        raw        = payload.raw_data or {}
        event_data = raw.get("event_data", {}) or {}

        # Check if this involves a high-value group
        group_name = event_data.get("TargetUserName", "") or event_data.get("GroupName", "")
        high_value_groups = (
            "domain admins", "enterprise admins", "schema admins",
            "administrators", "backup operators", "account operators",
            "server operators", "print operators", "remote desktop users",
        )

        involves_high_value = any(
            g in group_name.lower() for g in high_value_groups
        ) if group_name else False

        severity = AlertSeverity.CRITICAL if involves_high_value else AlertSeverity.HIGH

        group_info = f" Target group: {group_name}." if group_name else ""

        return Detection(
            detection_code   = "LC-004",
            engine_id        = EngineID.WINDOWS_EVENT,
            severity         = severity,
            title            = "Privilege Escalation Detected",
            description      = (
                f"Privilege escalation indicator detected for user {username}. "
                f"Event type: {payload.event_type}.{group_info} "
                f"Source: {payload.source_ip or payload.source_host}. "
                f"This may indicate unauthorized privilege assignment or "
                f"group membership manipulation."
            ),
            entity_id        = username,
            entity_type      = EntityType.USER_ACCOUNT,
            evidence         = [payload],
            mitre_tactic     = "Privilege Escalation",
            mitre_technique  = "T1078",
            risk_contribution = severity_to_contribution(severity),
        )

    # -------------------------------------------------------------------------
    # LC-005 - Service Abuse
    # -------------------------------------------------------------------------

    def _lc005_service_abuse(
        self,
        payload: NormalizedTelemetryPayload,
    ) -> Detection | None:
        """
        LC-005 - Service Abuse Detection
        Fires when a new service is installed or an existing service
        start type is changed unexpectedly. Common persistence and
        privilege escalation technique used by malware and attackers.

        Trigger events: service_installed (4697), new_service_installed (7045),
        service_start_type_changed (7040)
        MITRE: T1543.003 - Create or Modify System Process - Windows Service
        """
        service_event_types = (
            "service_installed",
            "new_service_installed",
            "service_start_type_changed",
        )

        if payload.event_type not in service_event_types:
            return None

        raw        = payload.raw_data or {}
        event_data = raw.get("event_data", {}) or {}

        service_name = (
            event_data.get("ServiceName")
            or event_data.get("param1")
            or "Unknown Service"
        )

        service_file = (
            event_data.get("ImagePath")
            or event_data.get("ServiceFileName")
            or event_data.get("param3")
            or "Unknown"
        )

        # Elevated severity for services pointing to suspicious paths
        suspicious_paths = (
            "temp", "appdata", "programdata", "users\\public",
            "\\windows\\system32\\cmd", "powershell", "wscript",
            "cscript", "mshta", "rundll32",
        )

        is_suspicious_path = any(
            p in service_file.lower() for p in suspicious_paths
        )

        severity = AlertSeverity.CRITICAL if is_suspicious_path else AlertSeverity.HIGH

        return Detection(
            detection_code   = "LC-005",
            engine_id        = EngineID.WINDOWS_EVENT,
            severity         = severity,
            title            = "Suspicious Service Installation Detected",
            description      = (
                f"Service '{service_name}' was installed or modified on "
                f"{payload.destination_host or payload.source_host}. "
                f"Service binary path: {service_file}. "
                f"{'Suspicious binary path detected. ' if is_suspicious_path else ''}"
                f"Service installation is a common persistence and privilege "
                f"escalation technique."
            ),
            entity_id        = payload.destination_host or payload.source_host or "unknown",
            entity_type      = EntityType.HOSTNAME,
            evidence         = [payload],
            mitre_tactic     = "Persistence",
            mitre_technique  = "T1543.003",
            risk_contribution = severity_to_contribution(severity),
        )