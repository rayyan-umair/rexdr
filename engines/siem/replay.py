"""
rexdr - SIEM Correlation Engine
replay.py - Historic log replay for rule testing and demonstration

Author  : Rayyan Umair
Date    : 2026-06-15
Purpose : Replays a sample attack log through the Sigma matching engine
          and chain builder without requiring live engine data. Used for
          Sigma rule regression testing and for demonstrating REXDR's
          correlation capability without a live monitored environment.
          The replay log format mirrors NormalizedTelemetryPayload so
          it can be fed directly into the same matching pipeline used
          for live events.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Context is the only defense."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import json
import logging
from pathlib import Path

# -- Internal ----------------------------------------------------------------
from siem.config import settings
from siem.sigma_engine import SigmaEngine

# ============================================================================

logger = logging.getLogger(__name__)


class ReplayEngine:
    """
    Loads and replays a sample attack log through the Sigma engine.
    Used for rule testing, regression validation, and demonstration
    purposes - not part of the live production pipeline.
    """

    def __init__(self, sigma_engine: SigmaEngine) -> None:
        self.sigma_engine = sigma_engine

    def load_replay_log(self, path: Path | None = None) -> list[dict]:
        """
        Load the replay log from disk. Expects a JSON array of event dicts
        in the same shape as normalized engine events.
        """
        replay_path = path or settings.replay_path

        if not replay_path.exists():
            logger.warning("Replay log not found - path=%s", replay_path)
            return []

        try:
            with open(replay_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, list):
                logger.warning("Replay log is not a JSON array - path=%s", replay_path)
                return []

            logger.info("Replay log loaded - events=%d", len(data))
            return data

        except Exception as e:
            logger.error("Failed to load replay log - error=%s", str(e))
            return []

    def run_replay(self, path: Path | None = None) -> dict:
        """
        Run a full replay pass and return a summary of results.
        Does not write to the live database - this is a dry-run
        validation tool. Used by the /replay API endpoint.
        """
        events = self.load_replay_log(path)

        if not events:
            return {
                "events_processed": 0,
                "total_matches":    0,
                "matches_by_rule":  {},
            }

        total_matches = 0
        matches_by_rule: dict[str, int] = {}

        for event in events:
            matches = self.sigma_engine.match_event(event)
            for match in matches:
                total_matches += 1
                rule_title = match["rule_title"]
                matches_by_rule[rule_title] = matches_by_rule.get(rule_title, 0) + 1

        logger.info(
            "Replay complete - events=%d matches=%d",
            len(events), total_matches,
        )

        return {
            "events_processed": len(events),
            "total_matches":    total_matches,
            "matches_by_rule":  matches_by_rule,
        }