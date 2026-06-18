"""
rexdr - Active Directory Intelligence Engine
domain_snapshot.py - Domain group membership snapshot engine

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Takes point-in-time snapshots of Active Directory group
          membership via LDAP and diffs consecutive snapshots to
          detect unauthorized additions and covert removals from
          high-value groups. This is the core mechanism behind
          AD-002 Group Membership Drift detection.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Trust, but verify the keys."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
import uuid
from dataclasses import dataclass

# -- Third Party -------------------------------------------------------------
from ldap3 import Server, Connection, ALL, SUBTREE

# -- Internal ----------------------------------------------------------------
from identity.config import settings
from identity.database import IdentityDatabase

# ============================================================================

logger = logging.getLogger(__name__)


@dataclass
class GroupDiff:
    """Represents the difference between two consecutive snapshots of a group."""
    group_name: str
    added_members:   list[str]
    removed_members: list[str]
    is_high_value:   bool


class DomainSnapshotEngine:
    """
    Manages LDAP connections, takes group membership snapshots,
    and diffs consecutive snapshots to surface membership drift.
    """

    def __init__(self, db: IdentityDatabase) -> None:
        self.db = db

    # -------------------------------------------------------------------------
    # LDAP connection
    # -------------------------------------------------------------------------

    def _get_connection(self, target_ip: str) -> Connection:
        """Open an LDAP connection to a domain controller."""
        server = Server(
            target_ip,
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
        return conn

    # -------------------------------------------------------------------------
    # Snapshot taking
    # -------------------------------------------------------------------------

    def take_snapshot(self, target_ip: str) -> list[GroupDiff]:
        """
        Take a fresh snapshot of all configured high-value groups,
        store it, and diff against the previous snapshot. Returns
        a list of GroupDiff objects for groups that changed.
        """
        diffs: list[GroupDiff] = []

        try:
            conn = self._get_connection(target_ip)
        except Exception as e:
            logger.error(
                "LDAP connection failed - target=%s error=%s",
                target_ip, str(e),
            )
            return diffs

        try:
            for group_name in settings.high_value_groups:
                members = self._fetch_group_members(conn, group_name)
                snapshot_id = str(uuid.uuid4())
                self.db.insert_snapshot(snapshot_id, group_name, members)

                diff = self._diff_against_previous(group_name, members)
                if diff:
                    diffs.append(diff)

        finally:
            conn.unbind()

        if diffs:
            logger.info("Domain snapshot complete - changed_groups=%d", len(diffs))

        return diffs

    def _fetch_group_members(self, conn: Connection, group_name: str) -> list[str]:
        """Query LDAP for the current member list of a group by name."""
        search_filter = f"(&(objectClass=group)(cn={group_name}))"

        conn.search(
            search_base=settings.ldap_base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["member"],
        )

        if not conn.entries:
            logger.warning("Group not found in LDAP - group=%s", group_name)
            return []

        entry = conn.entries[0]
        members_raw = entry.member.values if hasattr(entry, "member") else []

        # Extract just the CN from the full distinguished name
        members = []
        for dn in members_raw:
            cn = self._extract_cn(dn)
            if cn:
                members.append(cn)

        return members

    def _extract_cn(self, dn: str) -> str | None:
        """Extract the CN component from a distinguished name string."""
        parts = dn.split(",")
        for part in parts:
            part = part.strip()
            if part.upper().startswith("CN="):
                return part[3:]
        return None

    # -------------------------------------------------------------------------
    # Diffing
    # -------------------------------------------------------------------------

    def _diff_against_previous(
        self,
        group_name: str,
        current_members: list[str],
    ) -> GroupDiff | None:
        """
        Compare the current member list against the previous snapshot.
        Returns None if no previous snapshot exists or no changes detected.
        """
        previous = self.db.get_previous_snapshot(group_name)

        if previous is None:
            return None

        previous_members = set(previous["members"])
        current_set = set(current_members)

        added   = list(current_set - previous_members)
        removed = list(previous_members - current_set)

        if not added and not removed:
            return None

        is_high_value = group_name.lower() in [g.lower() for g in settings.high_value_groups]

        return GroupDiff(
            group_name      = group_name,
            added_members   = added,
            removed_members = removed,
            is_high_value   = is_high_value,
        )