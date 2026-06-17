"""
rexdr - SIEM Correlation Engine
sigma_engine.py - Sigma rule loading and matching engine

Author  : Rayyan Umair
Date    : 2026-06-15
Purpose : Loads Sigma YAML rules from the configured rules directory,
          compiles them via pySigma, and matches incoming normalized
          events against the active rule set. Supports hot-reload on
          a configurable interval without requiring a restart.
          Handles multi-document YAML files gracefully - only the
          first document in any file is loaded, consistent with
          yaml.safe_load() behavior. Nothing outside this module
          touches Sigma rule files directly.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Context is the only defense."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

# -- Third Party -------------------------------------------------------------
import yaml

# -- Internal ----------------------------------------------------------------
from rexdr_core.schemas import AlertSeverity
from siem.config import settings

# ============================================================================

logger = logging.getLogger(__name__)

SIGMA_SEVERITY_MAP: dict[str, AlertSeverity] = {
    "informational": AlertSeverity.INFO,
    "low":           AlertSeverity.LOW,
    "medium":        AlertSeverity.MEDIUM,
    "high":          AlertSeverity.HIGH,
    "critical":      AlertSeverity.CRITICAL,
}


class SigmaRule:
    """A loaded and parsed Sigma rule ready for matching."""

    def __init__(self, rule_id: str, title: str, severity: AlertSeverity, detection: dict, logsource: dict):
        self.rule_id   = rule_id
        self.title     = title
        self.severity  = severity
        self.detection = detection
        self.logsource = logsource

    def matches(self, event: dict) -> dict | None:
        """
        Check if a normalized event matches this rule's selection criteria.
        Returns the matched fields dict if matched, None otherwise.

        Supports the common Sigma selection patterns:
        - Exact field match
        - Contains (field|contains)
        - Starts with (field|startswith)
        - Ends with (field|endswith)
        """
        selection = self.detection.get("selection", {})
        if not selection:
            return None

        matched_fields = {}

        for field, expected in selection.items():
            base_field = field.split("|")[0]
            modifier   = field.split("|")[1] if "|" in field else None

            actual = self._get_event_field(event, base_field)
            if actual is None:
                return None

            if not self._field_matches(actual, expected, modifier):
                return None

            matched_fields[base_field] = actual

        return matched_fields

    def _get_event_field(self, event: dict, field: str) -> str | None:
        """Resolve a field name to its value in the event dict or raw_data."""
        if field in event:
            return event[field]
        raw_data = event.get("raw_data", {}) or {}
        return raw_data.get(field)

    def _field_matches(self, actual, expected, modifier: str | None) -> bool:
        actual_str = str(actual).lower()

        if isinstance(expected, list):
            values = [str(v).lower() for v in expected]
        else:
            values = [str(expected).lower()]

        if modifier == "contains":
            return any(v in actual_str for v in values)
        if modifier == "startswith":
            return any(actual_str.startswith(v) for v in values)
        if modifier == "endswith":
            return any(actual_str.endswith(v) for v in values)

        return actual_str in values


class SigmaEngine:
    """
    Loads and manages Sigma rules. Matches normalized events
    against the active rule set. Supports hot-reload.
    """

    def __init__(self) -> None:
        self.rules: list[SigmaRule] = []
        self.last_loaded: datetime | None = None
        self.load_rules()

    # -------------------------------------------------------------------------
    # Loading
    # -------------------------------------------------------------------------

    def load_rules(self) -> None:
        """
        Load all Sigma YAML rule files from the configured rules directory.
        Files that fail to parse are skipped with a warning - this is
        expected behavior for the multi-document YAML files found in
        some community Sigma rule sets.
        """
        rules_dir = settings.sigma_rules_path

        if not rules_dir.exists():
            logger.warning("Sigma rules directory not found - path=%s", rules_dir)
            self.rules = []
            return

        loaded_rules: list[SigmaRule] = []
        skipped = 0

        for rule_file in rules_dir.rglob("*.yml"):
            rule = self._load_rule_file(rule_file)
            if rule:
                loaded_rules.append(rule)
            else:
                skipped += 1

        for rule_file in rules_dir.rglob("*.yaml"):
            rule = self._load_rule_file(rule_file)
            if rule:
                loaded_rules.append(rule)
            else:
                skipped += 1

        self.rules = loaded_rules
        self.last_loaded = datetime.now(timezone.utc)

        logger.info(
            "Sigma rules loaded - loaded=%d skipped=%d",
            len(loaded_rules), skipped,
        )

    def _load_rule_file(self, path: Path) -> SigmaRule | None:
        """
        Parse a single Sigma YAML file into a SigmaRule.
        Only reads the first document in multi-document files,
        consistent with yaml.safe_load() behavior. Returns None
        on any parse failure - logged at debug level to avoid noise.
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or not isinstance(data, dict):
                return None

            rule_id   = data.get("id", str(uuid.uuid4()))
            title     = data.get("title", path.stem)
            level     = data.get("level", "medium")
            detection = data.get("detection", {})
            logsource = data.get("logsource", {})

            if not detection:
                return None

            severity = SIGMA_SEVERITY_MAP.get(level.lower(), AlertSeverity.MEDIUM)

            return SigmaRule(
                rule_id   = rule_id,
                title     = title,
                severity  = severity,
                detection = detection,
                logsource = logsource,
            )

        except Exception as e:
            logger.debug(
                "Skipping unparseable Sigma rule - path=%s error=%s",
                path, str(e),
            )
            return None

    def maybe_reload(self) -> None:
        """
        Reload rules if sigma_hot_reload_seconds has elapsed since
        the last load. Called periodically by the pipeline.
        """
        if self.last_loaded is None:
            self.load_rules()
            return

        elapsed = (datetime.now(timezone.utc) - self.last_loaded).total_seconds()
        if elapsed >= settings.sigma_hot_reload_seconds:
            self.load_rules()

    # -------------------------------------------------------------------------
    # Matching
    # -------------------------------------------------------------------------

    def match_event(self, event: dict) -> list[dict]:
        """
        Match a normalized event against all loaded Sigma rules.
        Returns a list of match dicts for any rules that fired.
        """
        matches = []

        for rule in self.rules:
            matched_fields = rule.matches(event)
            if matched_fields is not None:
                matches.append({
                    "match_id":        str(uuid.uuid4()),
                    "rule_id":         rule.rule_id,
                    "rule_title":      rule.title,
                    "source_engine":   event.get("engine_id"),
                    "source_event_id": event.get("event_id"),
                    "severity":        rule.severity.value,
                    "entity_id":       (
                        event.get("source_ip")
                        or event.get("username")
                        or event.get("destination_host")
                        or "unknown"
                    ),
                    "timestamp":       event.get("timestamp", datetime.now(timezone.utc)),
                    "matched_fields":  matched_fields,
                })

        return matches

    def rule_count(self) -> int:
        """Return the number of currently loaded rules."""
        return len(self.rules)