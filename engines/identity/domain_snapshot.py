"""
rexdr - Active Directory Intelligence Engine
domain_snapshot.py - Domain group membership snapshot engine

Author  : Rayyan Umair
Date    : 2026-06-18
Updated : 2026-08-01 - Added enumerate_computers(). The engine could see
          group membership but had no idea what machines were actually
          joined to the domain, so there was no way to tell a managed host
          from an unmanaged one on the same network. Also decodes
          userAccountControl into named flags - unconstrained delegation on
          a workstation is a credential theft vector and was invisible.
Purpose : Takes point-in-time snapshots of Active Directory group
          membership via LDAP and diffs consecutive snapshots to
          detect unauthorized additions and covert removals from
          high-value groups. This is the core mechanism behind
          AD-002 Group Membership Drift detection. Also enumerates
          domain-joined computers for the inventory view.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Trust, but verify the keys."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
import uuid
from dataclasses import dataclass
import json

# -- Third Party -------------------------------------------------------------
from ldap3 import Server, Connection, ALL, SUBTREE

# -- Internal ----------------------------------------------------------------
from identity.config import settings
from identity.database import IdentityDatabase

# ============================================================================

logger = logging.getLogger(__name__)

# userAccountControl bit flags, per Microsoft's documented values. Only the
# ones meaningful for a computer object are listed - the full set also covers
# user-specific states this engine reads elsewhere.
UAC_FLAGS = {
    0x0002:    "ACCOUNTDISABLE",
    0x0020:    "PASSWD_NOTREQD",
    0x0080:    "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x1000:    "WORKSTATION_TRUST_ACCOUNT",
    0x2000:    "SERVER_TRUST_ACCOUNT",
    0x10000:   "DONT_EXPIRE_PASSWORD",
    0x80000:   "TRUSTED_FOR_DELEGATION",
    0x100000:  "NOT_DELEGATED",
    0x200000:  "USE_DES_KEY_ONLY",
    0x400000:  "DONT_REQ_PREAUTH",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
}

COMPUTER_ATTRIBUTES = [
    "cn",
    "dNSHostName",
    "operatingSystem",
    "operatingSystemVersion",
    "userAccountControl",
    "servicePrincipalName",
    "whenCreated",
    "lastLogonTimestamp",
    "distinguishedName",
]


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
    Also enumerates domain-joined computer objects.
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
            auto_referrals=False,
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
    # Computer enumeration
    # -------------------------------------------------------------------------

    def enumerate_computers(self, target_ip: str) -> int:
        """
        Enumerate every computer object joined to the domain and store it.
        This is the authoritative list of managed machines - comparing it
        against what the network discovery engine actually observes is how
        an unmanaged device on a domain network becomes visible.

        Returns the number of computers written.
        """
        try:
            conn = self._get_connection(target_ip)
        except Exception as e:
            logger.error(
                "LDAP connection failed during computer enumeration - target=%s error=%s",
                target_ip, str(e),
            )
            return 0

        count = 0

        try:
            conn.search(
                search_base=settings.ldap_base_dn,
                search_filter="(objectClass=computer)",
                search_scope=SUBTREE,
                attributes=COMPUTER_ATTRIBUTES,
            )

            for entry in conn.entries:
                try:
                    self.db.upsert_computer(self._parse_computer(entry))
                    count += 1
                except Exception as e:
                    logger.error(
                        "Failed to store computer object - dn=%s error=%s",
                        entry.entry_dn, str(e),
                    )

        finally:
            conn.unbind()

        logger.info("Computer enumeration complete - computers=%d", count)
        return count

    def _parse_computer(self, entry) -> dict:
        """Turn a raw LDAP computer entry into the internal record shape."""
        def value(attr):
            return entry[attr].value if attr in entry.entry_attributes else None

        uac = value("userAccountControl") or 0
        try:
            uac = int(uac)
        except (TypeError, ValueError):
            uac = 0

        spns = value("servicePrincipalName") or []
        if isinstance(spns, str):
            spns = [spns]

        dn = entry.entry_dn

        return {
            "computer_name":             value("cn"),
            "dns_hostname":              value("dNSHostName"),
            "distinguished_name":        dn,
            "container_path":            self._container_path(dn),
            "operating_system":          value("operatingSystem"),
            "operating_system_version":  value("operatingSystemVersion"),
            "user_account_control":      uac,
            # ACCOUNTDISABLE inverted - a computer is enabled unless the bit is set
            "is_enabled":                not bool(uac & 0x0002),
            "is_domain_controller":      bool(uac & 0x2000),
            # Unconstrained delegation. Expected on a domain controller, but on
            # a workstation or member server this is a credential theft vector.
            "is_trusted_for_delegation": bool(uac & 0x80000),
            "uac_flags":                 self._decode_uac(uac),
            "service_principal_names":   list(spns),
            "when_created":              value("whenCreated"),
            "last_logon":                value("lastLogonTimestamp"),
        }

    @staticmethod
    def _decode_uac(value: int) -> list[str]:
        """Decode a userAccountControl integer into its named flags."""
        return sorted(name for bit, name in UAC_FLAGS.items() if value & bit)

    @staticmethod
    def _container_path(dn: str) -> str:
        """
        Human-readable container path from a DN, outermost first. The DC=
        components are dropped since they are the same for every object.
        'CN=SRV01,OU=Servers,OU=Prod,DC=x,DC=y' becomes 'Prod / Servers'.
        """
        parts = [p.strip() for p in dn.split(",")]
        containers = [
            p.split("=", 1)[1]
            for p in parts[1:]
            if "=" in p and not p.upper().startswith("DC=")
        ]
        return " / ".join(reversed(containers)) if containers else "(domain root)"

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

        # Guard against members arriving as a raw JSON string. set() on a
        # string iterates it character by character, which silently produced
        # phantom "removed members" like '[', '"', 'A' and fired AD-002 on
        # every snapshot cycle.
        previous_raw = previous["members"]
        if isinstance(previous_raw, str):
            previous_raw = json.loads(previous_raw)
        previous_members = set(previous_raw)
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