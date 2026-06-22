"""
rexdr - Launcher
rexdr_launcher.py - Launcher entry point

Author  : Rayyan Umair
Date    : 2026-06-21
Purpose : The single command users run to start REXDR. Resolves the
          repo root, configures logging, and launches the Tkinter
          window. Everything else lives in launcher_ui.py,
          config_writer.py, engine_manager.py, and targets_editor.py -
          this file only wires them together and starts the app.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"The foundation everything else is built on."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import logging
import sys
from pathlib import Path

# -- Internal ----------------------------------------------------------------
from launcher.launcher_ui import RexdrLauncher

# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


def find_repo_root() -> Path:
    """
    Resolve the REXDR repo root. The launcher script lives in
    launcher/ at the repo root, so the parent of this file's directory
    is the root - validated by checking docker-compose.yml exists there.
    """
    candidate = Path(__file__).resolve().parent.parent

    if not (candidate / "docker-compose.yml").exists():
        logger.error(
            "Could not locate docker-compose.yml relative to launcher. "
            "Run this from within the REXDR repository."
        )
        sys.exit(1)

    return candidate


def main() -> None:
    repo_root = find_repo_root()
    logger.info("REXDR repo root resolved - path=%s", repo_root)

    app = RexdrLauncher(repo_root)
    app.mainloop()


if __name__ == "__main__":
    main()