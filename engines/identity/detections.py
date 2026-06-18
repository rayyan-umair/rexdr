"""
rexdr - Active Directory Intelligence Engine
detections.py - Detection logic for the Identity engine

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Implements all four detection algorithms for the Active
          Directory Intelligence engine. Each detection is a
          self-contained method that receives a normalized event or
          a group diff, queries the database for context, and returns
          a Detection object if the threshold is met. All detections
          follow the ENGINE-NNN code format.

          AD-001  Kerberos Abuse
          AD-002  Group Membership Drift
          AD-003  Anomalous Authentication
          AD-004  ACL Abuse

Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Trust, but verify the keys."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging

# -- Internal ----------------------------------------------------------------
from rexdr_core.formula import severity_to_contribution
from rexdr_core.identity import EngineID
from rexdr_core.schemas import AlertSeverity, Detection, EntityType, NormalizedTelemetryPayload
from identity.config import settings
from identity.database import IdentityDatabase
from identity.domain_snapshot import GroupDiff

# ============================================================================

logger = logging.getLogger(__name__)

# Weak Kerberos encryption types - RC4 and DES are considered crackable
WEAK_ENCRYPTION_TYPES = {"0x17", "0x18", "0x1", "0x3", "23", "24", "1", "3"}


class IdentityDetections:
    """
    Detection engine for Active Directory Intelligence.
    Two entry points: run() for normalized events, and
    run_group_diff() for domain snapshot diffs.
    """

    def __init__(self, db: IdentityDatabase) -> None:
        self.db = db

    def run(self, payload: NormalizedTelemetryPayload) -> list[Detection]:
        """Run event-based detection algorithms against a normalized event."""
        detections: list[Detection] = []

        ad001 = self._ad001_kerberos_abuse(payload)
        ad003 = self._ad003_anomalous_authentication(payload)
        ad004 = self._ad004_acl_abuse(payload)

        for detection in [ad001, ad003, ad004]:
            if detection:
                detections.append(detection)
                logger.info(
                    "Detection fired - code=%s entity=%s severity=%s",
                    detection.detection_code, detection.entity_id, detection.severity.value,
                )

        return detections

    def run_group_diff(self, diff: GroupDiff) -> list[Detection]:
        """Run AD-002 against a domain snapshot group diff."""
        detection = self._ad002_group_membership_drift(diff)
        if detection:
            logger.info(
                "Detection fired - code=%s entity=%s severity=%s",
                detection.detection_code, detection.entity_id, detection.severity.value,
            )
            return [detection]
        return []

    # -------------------------------------------------------------------------
    # AD-001 - Kerberos Abuse
    # -------------------------------------------------------------------------

    def _ad001_kerberos_abuse(self, payload: NormalizedTelemetryPayload) -> Detection | None:
        """
        AD-001 - Kerberos Abuse Detection
        Fires on Kerberoasting (excessive TGS requests for service accounts)
        and AS-REP roasting attempts, with elevated severity for weak
        encryption types known to be crackable offline.

        MITRE: T1558 - Steal or Forge Kerberos Tickets
        """
        if payload.event_type not in ("kerberos_service_ticket", "kerberos_pre_auth_failed"):
            return None

        username = payload.username
        if not username:
            return None

        raw = payload.raw_data or {}
        encryption_type = str(raw.get("encryption_type", ""))
        is_weak_encryption = encryption_type in WEAK_ENCRYPTION_TYPES

        if payload.event_type == "kerberos_service_ticket":
            ticket_count = self.db.get_recent_tgs_requests(
                username=username,
                window_minutes=settings.kerberoast_window_minutes,
            )

            if ticket_count < settings.kerberoast_ticket_threshold:
                return None

            severity = AlertSeverity.CRITICAL if is_weak_encryption else AlertSeverity.HIGH

            return Detection(
                detection_code   = "AD-001",
                engine_id        = EngineID.IDENTITY,
                severity         = severity,
                title            = "Kerberoasting Detected",
                description      = (
                    f"User {username} requested {ticket_count} Kerberos service "
                    f"tickets within {settings.kerberoast_window_minutes} minutes."
                    f"{' Weak encryption type detected, ticket is crackable offline.' if is_weak_encryption else ''} "
                    f"Pattern consistent with Kerberoasting credential theft."
                ),
                entity_id        = username,
                entity_type      = EntityType.USER_ACCOUNT,
                evidence         = [payload],
                mitre_tactic     = "Credential Access",
                mitre_technique  = "T1558.003",
                risk_contribution = severity_to_contribution(severity),
            )

        # AS-REP roasting - pre-auth failure pattern
        return Detection(
            detection_code   = "AD-001",
            engine_id        = EngineID.IDENTITY,
            severity         = AlertSeverity.HIGH,
            title            = "AS-REP Roasting Attempt Detected",
            description      = (
                f"Kerberos pre-authentication failure for user {username}. "
                f"This pattern is consistent with AS-REP roasting against "
                f"accounts with pre-authentication disabled."
            ),
            entity_id        = username,
            entity_type      = EntityType.USER_ACCOUNT,
            evidence         = [payload],
            mitre_tactic     = "Credential Access",
            mitre_technique  = "T1558.004",
            risk_contribution = severity_to_contribution(AlertSeverity.HIGH),
        )

    # -------------------------------------------------------------------------
    # AD-002 - Group Membership Drift
    # -------------------------------------------------------------------------

    def _ad002_group_membership_drift(self, diff: GroupDiff) -> Detection | None:
        """
        AD-002 - Group Membership Drift Detection
        Fires when a domain snapshot diff shows additions or removals
        from a tracked group. Severity escalates for high-value groups
        and for covert removals, which can indicate an attacker hiding
        their tracks after gaining and then relinquishing access.

        MITRE: T1098 - Account Manipulation
        """
        if not diff.added_members and not diff.removed_members:
            return None

        severity = AlertSeverity.MEDIUM
        if diff.is_high_value:
            severity = AlertSeverity.CRITICAL if diff.added_members else AlertSeverity.HIGH

        changes = []
        if diff.added_members:
            changes.append(f"added: {', '.join(diff.added_members)}")
        if diff.removed_members:
            changes.append(f"removed: {', '.join(diff.removed_members)}")

        entity_id = diff.added_members[0] if diff.added_members else diff.removed_members[0]

        return Detection(
            detection_code   = "AD-002",
            engine_id        = EngineID.IDENTITY,
            severity         = severity,
            title            = "Group Membership Drift Detected",
            description      = (
                f"Membership change detected in group '{diff.group_name}'"
                f"{' (high-value group)' if diff.is_high_value else ''}: "
                f"{'; '.join(changes)}. Unauthorized or unexpected privileged "
                f"group changes are a primary indicator of privilege escalation "
                f"or persistence establishment."
            ),
            entity_id        = entity_id,
            entity_type      = EntityType.USER_ACCOUNT,
            evidence         = [],
            mitre_tactic     = "Persistence",
            mitre_technique  = "T1098",
            risk_contribution = severity_to_contribution(severity),
        )

    # -------------------------------------------------------------------------
    # AD-003 - Anomalous Authentication
    # -------------------------------------------------------------------------

    def _ad003_anomalous_authentication(
        self,
        payload: NormalizedTelemetryPayload,
    ) -> Detection | None:
        """
        AD-003 - Anomalous Authentication Detection
        Fires when a user authenticates to a host they have never
        authenticated to before, and this happens for more than
        anomalous_auth_new_host_threshold distinct new hosts -
        indicating lateral movement via legitimate AD credentials.

        MITRE: T1078 - Valid Accounts
        """
        if payload.event_type not in ("successful_logon", "network_logon"):
            return None

        username = payload.username
        destination = payload.destination_host

        if not username or not destination or username.endswith("$"):
            return None

        known_hosts = self.db.get_known_auth_hosts(username)

        if destination in known_hosts:
            return None

        # This is a new host for this user - check how many new hosts recently
        new_host_count = len([h for h in known_hosts]) 

        if len(known_hosts) == 0:
            # First time we have ever seen this user - not anomalous, just new baseline
            return None

        return Detection(
            detection_code   = "AD-003",
            engine_id        = EngineID.IDENTITY,
            severity         = AlertSeverity.MEDIUM,
            title            = "Anomalous Authentication Detected",
            description      = (
                f"User {username} authenticated to {destination}, a host not "
                f"present in their established authentication baseline of "
                f"{len(known_hosts)} known hosts. May indicate lateral movement "
                f"using compromised but valid credentials."
            ),
            entity_id        = username,
            entity_type      = EntityType.USER_ACCOUNT,
            evidence         = [payload],
            mitre_tactic     = "Lateral Movement",
            mitre_technique  = "T1078",
            risk_contribution = severity_to_contribution(AlertSeverity.MEDIUM),
        )

    # -------------------------------------------------------------------------
    # AD-004 - ACL Abuse
    # -------------------------------------------------------------------------

    def _ad004_acl_abuse(self, payload: NormalizedTelemetryPayload) -> Detection | None:
        """
        AD-004 - ACL Abuse Detection
        Fires on AdminSDHolder modifications, delegation changes, and
        other ACL manipulation events that can be used to establish
        stealthy persistent access without privileged group membership.

        MITRE: T1484.001 - Domain Policy Modification - Group Policy Modification
        """
        acl_event_types = (
            "permissions_changed",
            "user_right_assigned",
            "user_right_removed",
            "audit_policy_changed",
        )

        if payload.event_type not in acl_event_types:
            return None

        username = payload.username
        if not username:
            return None

        raw = payload.raw_data or {}
        event_data = raw.get("event_data", {}) or {}
        target_object = event_data.get("ObjectName", "unknown object")

        is_adminsdholder = "adminsdholder" in str(target_object).lower()
        severity = AlertSeverity.CRITICAL if is_adminsdholder else AlertSeverity.HIGH

        return Detection(
            detection_code   = "AD-004",
            engine_id        = EngineID.IDENTITY,
            severity         = severity,
            title            = "ACL Abuse Detected",
            description      = (
                f"User {username} modified permissions on {target_object}."
                f"{' AdminSDHolder modification detected - this is a well-known persistence technique.' if is_adminsdholder else ''} "
                f"ACL manipulation can establish stealthy access that survives "
                f"removal from privileged groups."
            ),
            entity_id        = username,
            entity_type      = EntityType.USER_ACCOUNT,
            evidence         = [payload],
            mitre_tactic     = "Persistence",
            mitre_technique  = "T1484.001",
            risk_contribution = severity_to_contribution(severity),
        )