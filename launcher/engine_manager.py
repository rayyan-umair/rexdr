"""
rexdr - Launcher
engine_manager.py - Docker Compose process control and status tracking

Author  : Rayyan Umair
Date    : 2026-06-21
Purpose : Wraps docker compose commands - up, down, restart, logs - and
          parses container status into a structured per-engine state map
          the UI can render. This is the only module that shells out to
          Docker. Nothing in the UI layer calls subprocess directly.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"The foundation everything else is built on."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import json
import logging
import subprocess
import threading
from pathlib import Path
from enum import Enum

# ============================================================================

logger = logging.getLogger(__name__)

ENGINE_SERVICE_NAMES = [
    "windows-event",
    "network-flow",
    "siem",
    "dns",
    "identity",
    "response",
    "asset-discovery",
    "vulnerability",
    "frontend",
    "nginx",
]


class EngineStatus(str, Enum):
    STOPPED   = "stopped"
    STARTING  = "starting"
    HEALTHY   = "healthy"
    DEGRADED  = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN   = "unknown"


class EngineManager:
    """
    Controls the REXDR Docker Compose stack and reports structured
    status for every service. Long-running commands (build, up) run
    in a background thread with a callback for streaming log lines
    back to the UI without blocking the Tkinter main loop.
    """

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root

    # -------------------------------------------------------------------------
    # Compose commands
    # -------------------------------------------------------------------------

    def prepare_build(self, on_output=None) -> None:
        """
        Run the wheel-distribution script before building. This must
        run after any core-shared change and before every docker
        compose build, per the established build sequence.
        """
        script = self.repo_root / "scripts" / "prepare_build.ps1"
        self._run_streamed(
            ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script)],
            on_output=on_output,
        )

    def build(self, on_output=None) -> None:
        """Run docker compose build for the full stack."""
        self._run_streamed(
            ["docker", "compose", "build"],
            on_output=on_output,
        )

    def start(self, on_output=None) -> None:
        """Start the full REXDR stack in detached mode."""
        self._run_streamed(
            ["docker", "compose", "up", "-d"],
            on_output=on_output,
        )

    def stop(self, on_output=None) -> None:
        """Stop the full REXDR stack without removing volumes."""
        self._run_streamed(
            ["docker", "compose", "down"],
            on_output=on_output,
        )

    def restart_service(self, service_name: str, on_output=None) -> None:
        """Restart a single engine service by its compose service name."""
        self._run_streamed(
            ["docker", "compose", "restart", service_name],
            on_output=on_output,
        )

    def stop_service(self, service_name: str, on_output=None) -> None:
        """Stop a single engine service without affecting the others."""
        self._run_streamed(
            ["docker", "compose", "stop", service_name],
            on_output=on_output,
        )

    def start_service(self, service_name: str, on_output=None) -> None:
        """Start a single previously-stopped engine service."""
        self._run_streamed(
            ["docker", "compose", "start", service_name],
            on_output=on_output,
        )

    def get_logs(self, service_name: str, lines: int = 200) -> str:
        """Get the last N log lines for a single service."""
        result = subprocess.run(
            ["docker", "compose", "logs", "--tail", str(lines), service_name],
            cwd=self.repo_root,
            capture_output=True,
            text=True,
        )
        return result.stdout + result.stderr

    # -------------------------------------------------------------------------
    # Status
    # -------------------------------------------------------------------------

    def get_status(self) -> dict[str, EngineStatus]:
        """
        Query docker compose ps for the current state of every service
        and map Docker's health status into REXDR's EngineStatus enum.
        Returns a dict keyed by service name. Services that have not
        been started yet are reported as STOPPED rather than omitted,
        so the dashboard always shows all ten rows.
        """
        statuses = {name: EngineStatus.STOPPED for name in ENGINE_SERVICE_NAMES}

        try:
            result = subprocess.run(
                ["docker", "compose", "ps", "--format", "json"],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error("docker compose ps failed - error=%s", str(e))
            return {name: EngineStatus.UNKNOWN for name in ENGINE_SERVICE_NAMES}

        if result.returncode != 0:
            logger.warning("docker compose ps returned non-zero - stderr=%s", result.stderr)
            return statuses

        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                container = json.loads(line)
            except json.JSONDecodeError:
                continue

            service = container.get("Service")
            if service not in statuses:
                continue

            statuses[service] = self._map_docker_state(container)

        return statuses

    def _map_docker_state(self, container: dict) -> EngineStatus:
        state = container.get("State", "").lower()
        health = container.get("Health", "").lower()

        if state != "running":
            return EngineStatus.STOPPED

        if health == "healthy":
            return EngineStatus.HEALTHY
        if health == "starting":
            return EngineStatus.STARTING
        if health == "unhealthy":
            return EngineStatus.UNHEALTHY
        if not health:
            # No health check defined on this service - running is good enough
            return EngineStatus.HEALTHY

        return EngineStatus.UNKNOWN

    # -------------------------------------------------------------------------
    # Internal - streamed subprocess execution
    # -------------------------------------------------------------------------

    def _run_streamed(self, command: list[str], on_output=None) -> None:
        """
        Run a command and stream its stdout/stderr line by line to the
        on_output callback in real time. Used for build/up/down so the
        launch monitor can show live progress rather than a frozen UI
        until the command finally finishes.
        """
        process = subprocess.Popen(
            command,
            cwd=self.repo_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        for line in process.stdout:
            line = line.rstrip()
            logger.debug(line)
            if on_output:
                on_output(line)

        process.wait()

        if process.returncode != 0:
            message = f"Command failed with exit code {process.returncode}: {' '.join(command)}"
            logger.error(message)
            if on_output:
                on_output(f"ERROR: {message}")

    def run_async(self, fn, *args, **kwargs) -> threading.Thread:
        """
        Run any of this class's methods on a background thread so the
        Tkinter main loop never blocks during long-running Docker
        operations. The UI layer calls this wrapper rather than
        invoking build()/start()/stop() directly.
        """
        thread = threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True)
        thread.start()
        return thread