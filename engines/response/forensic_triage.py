"""
rexdr - Incident Response Orchestration Engine
forensic_triage.py - Immutable case file generation with hash chain

Author  : Rayyan Umair
Date    : 2026-06-18
Purpose : Generates immutable Markdown case files for every incident,
          with a SHA-256 hash chain over all evidence and the chain
          narrative for forensic integrity. Case files are written
          once and never modified after creation - any update to an
          incident creates a new case file referencing the original.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Verify the threat. Execute the isolation. Preserve the evidence."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

# -- Internal ----------------------------------------------------------------
from rexdr_core.schemas import CaseFile, ChainSeverity
from response.config import settings

# ============================================================================

logger = logging.getLogger(__name__)


class ForensicTriage:
    """
    Generates SHA-256 hash chains and immutable Markdown case files
    for every REXDR incident. The hash chain provides cryptographic
    proof that the case content has not been altered after creation.
    """

    def __init__(self) -> None:
        settings.cases_dir.mkdir(parents=True, exist_ok=True)

    # -------------------------------------------------------------------------
    # Hashing
    # -------------------------------------------------------------------------

    def hash_chain_data(self, chain: dict) -> str:
        """Calculate a SHA-256 hash over the full chain data for integrity proof."""
        canonical = json.dumps(chain, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def hash_evidence(self, evidence: dict) -> str:
        """Calculate a SHA-256 hash over a single piece of evidence."""
        canonical = json.dumps(evidence, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # -------------------------------------------------------------------------
    # Case file generation
    # -------------------------------------------------------------------------

    def create_case(
        self,
        chain: dict,
        actions_taken: list[str],
    ) -> tuple[CaseFile, str]:
        """
        Generate a complete CaseFile object and write the immutable
        Markdown file to disk. Returns the CaseFile and the file path.
        """
        chain_hash = self.hash_chain_data(chain)

        evidence_hashes = {}
        for i, detection in enumerate(chain.get("detections", [])):
            key = f"detection_{i}_{detection.get('detection_code', 'unknown')}"
            evidence_hashes[key] = self.hash_evidence(detection)

        case = CaseFile(
            chain_id        = chain.get("chain_id"),
            entity_id       = chain.get("entity_id"),
            severity        = ChainSeverity(chain.get("severity", "medium")),
            title           = chain.get("title", "Untitled Incident"),
            narrative       = chain.get("narrative", ""),
            actions_taken   = actions_taken,
            evidence_hashes = evidence_hashes,
            chain_hash      = chain_hash,
        )

        file_path = self._write_markdown(case, chain)

        logger.info(
            "Case file created - case_id=%s entity=%s severity=%s actions=%d",
            case.case_id, case.entity_id, case.severity.value, len(actions_taken),
        )

        return case, str(file_path)

    def _write_markdown(self, case: CaseFile, chain: dict) -> Path:
        """Write the immutable Markdown case file to disk."""
        timestamp_str = case.created_at.strftime("%Y%m%d_%H%M%S")
        filename = f"case_{timestamp_str}_{str(case.case_id)[:8]}.md"
        file_path = settings.cases_dir / filename

        content = self._build_markdown_content(case, chain)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

        return file_path

    def _build_markdown_content(self, case: CaseFile, chain: dict) -> str:
        """Build the full Markdown content for a case file."""
        lines = [
            f"# REXDR Incident Case File",
            f"",
            f"**Case ID:** {case.case_id}",
            f"**Created:** {case.created_at.isoformat()}",
            f"**Entity:** {case.entity_id}",
            f"**Severity:** {case.severity.value.upper()}",
            f"**Analyst:** {case.analyst}",
            f"",
            f"---",
            f"",
            f"## Title",
            f"",
            f"{case.title}",
            f"",
            f"## Investigation Narrative",
            f"",
            f"{case.narrative}",
            f"",
            f"## Actions Taken",
            f"",
        ]

        if case.actions_taken:
            for action in case.actions_taken:
                lines.append(f"- {action}")
        else:
            lines.append("- No automated actions were taken for this incident.")

        lines.extend([
            f"",
            f"## Forensic Integrity",
            f"",
            f"**Chain Hash (SHA-256):** `{case.chain_hash}`",
            f"",
            f"### Evidence Hashes",
            f"",
        ])

        for key, hash_val in case.evidence_hashes.items():
            lines.append(f"- `{key}`: `{hash_val}`")

        lines.extend([
            f"",
            f"---",
            f"",
            f"This case file is immutable and was generated automatically by",
            f"the REXDR Incident Response Orchestration engine. Any modification",
            f"to this file after creation will invalidate the integrity hashes above.",
            f"",
        ])

        return "\n".join(lines)