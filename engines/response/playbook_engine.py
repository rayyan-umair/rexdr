"""
rexdr - Incident Response Orchestration Engine
playbook_engine.py - YAML playbook loading and matching

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Loads YAML playbook files and matches incoming attack chains
          against the appropriate playbook based on detection codes
          and MITRE techniques present in the chain. Supports hot-reload
          without requiring a restart. A playbook defines the sequence
          of containment actions to execute for a given threat pattern.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Verify the threat. Execute the isolation. Preserve the evidence."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
from datetime import datetime, timezone
from pathlib import Path

# -- Third Party -------------------------------------------------------------
import yaml

# -- Internal ----------------------------------------------------------------
from response.config import settings

# ============================================================================

logger = logging.getLogger(__name__)


class Playbook:
    """A loaded and parsed response playbook ready for matching and execution."""

    def __init__(
        self,
        playbook_id: str,
        name: str,
        match_detection_codes: list[str],
        match_mitre_techniques: list[str],
        min_severity: str,
        actions: list[dict],
    ):
        self.playbook_id            = playbook_id
        self.name                   = name
        self.match_detection_codes  = match_detection_codes
        self.match_mitre_techniques = match_mitre_techniques
        self.min_severity           = min_severity
        self.actions                = actions

    def matches(self, chain: dict) -> bool:
        """
        Check if this playbook applies to a given attack chain.
        Matches on detection code overlap or MITRE technique overlap,
        gated by minimum severity.
        """
        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        chain_rank = severity_rank.get(chain.get("severity", "low"), 1)
        required_rank = severity_rank.get(self.min_severity, 1)

        if chain_rank < required_rank:
            return False

        chain_codes = self._extract_detection_codes(chain)
        chain_techniques = chain.get("mitre_techniques", [])

        if self.match_detection_codes and any(c in chain_codes for c in self.match_detection_codes):
            return True

        if self.match_mitre_techniques and any(t in chain_techniques for t in self.match_mitre_techniques):
            return True

        return False

    def _extract_detection_codes(self, chain: dict) -> list[str]:
        detections = chain.get("detections", [])
        return [d.get("detection_code", "") for d in detections if isinstance(d, dict)]


class PlaybookEngine:
    """
    Loads and manages response playbooks. Matches incoming attack
    chains against the active playbook set. Supports hot-reload.
    """

    def __init__(self) -> None:
        self.playbooks: list[Playbook] = []
        self.last_loaded: datetime | None = None
        self.load_playbooks()

    # -------------------------------------------------------------------------
    # Loading
    # -------------------------------------------------------------------------

    def load_playbooks(self) -> None:
        """Load all YAML playbook files from the configured directory."""
        playbooks_dir = settings.playbooks_path

        if not playbooks_dir.exists():
            logger.warning("Playbooks directory not found - path=%s", playbooks_dir)
            self.playbooks = []
            return

        loaded: list[Playbook] = []
        skipped = 0

        for pattern in ("*.yml", "*.yaml"):
            for file_path in playbooks_dir.rglob(pattern):
                pb = self._load_playbook_file(file_path)
                if pb:
                    loaded.append(pb)
                else:
                    skipped += 1

        self.playbooks = loaded
        self.last_loaded = datetime.now(timezone.utc)

        logger.info("Playbooks loaded - loaded=%d skipped=%d", len(loaded), skipped)

    def _load_playbook_file(self, path: Path) -> Playbook | None:
        """Parse a single playbook YAML file. Returns None on parse failure."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or not isinstance(data, dict):
                return None

            return Playbook(
                playbook_id            = data.get("playbook_id", path.stem),
                name                   = data.get("name", path.stem),
                match_detection_codes  = data.get("match", {}).get("detection_codes", []),
                match_mitre_techniques = data.get("match", {}).get("mitre_techniques", []),
                min_severity           = data.get("match", {}).get("min_severity", "high"),
                actions                = data.get("actions", []),
            )

        except Exception as e:
            logger.debug("Skipping unparseable playbook - path=%s error=%s", path, str(e))
            return None

    def maybe_reload(self) -> None:
        """Reload playbooks if the hot-reload interval has elapsed."""
        if self.last_loaded is None:
            self.load_playbooks()
            return

        elapsed = (datetime.now(timezone.utc) - self.last_loaded).total_seconds()
        if elapsed >= settings.playbook_hot_reload_seconds:
            self.load_playbooks()

    # -------------------------------------------------------------------------
    # Matching
    # -------------------------------------------------------------------------

    def find_matching_playbook(self, chain: dict) -> Playbook | None:
        """
        Find the first playbook that matches the given attack chain.
        Returns None if no playbook matches - the chain still gets a
        case file via the default fallback, just no automated actions.
        """
        for playbook in self.playbooks:
            if playbook.matches(chain):
                return playbook
        return None

    def playbook_count(self) -> int:
        return len(self.playbooks)