"""
rexdr - Launcher
engine_manager.py - Docker Compose process control and status tracking

Author  : Rayyan Umair
Date    : 2026-06-21
Updated : 2026-07-30 - prepare_build() now picks a script that actually
          exists for the host OS instead of hardcoding PowerShell, which
          silently failed on Linux. _run_streamed() catches launch errors
          rather than dying inside a daemon thread with no UI feedback.
          Added entity-store to the service list - it was missing despite
          being the dependency every other engine relies on. ps parsing
          handles both the JSONL and JSON-array shapes Compose v2 has
          emitted across versions, and a restarting container is now
          reported as unhealthy rather than stopped.
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
import platform
import shutil
import subprocess
import threading
from pathlib import Path
from enum import Enum

# ============================================================================

logger = logging.getLogger(__name__)

ENGINE_SERVICE_NAMES = [
    "entity-store",
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
        Run the wheel-distribution script before building. Picks the
        script that matches the host - the launcher runs on the Docker
        host, which is Linux in this deployment, so hardcoding
        PowerShell meant the Build button failed before it started.
        """
        ps_script = self.repo_root / "scripts" / "prepare_build.ps1"
        sh_script = self.repo_root / "scripts" / "prepare_build.sh"

        if platform.system() == "Windows" and ps_script.exists():
            command = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(ps_script)]
        elif sh_script.exists():
            command = ["bash", str(sh_script)]
        elif ps_script.exists() and shutil.which("pwsh"):
            command = ["pwsh", "-ExecutionPolicy", "Bypass", "-File", str(ps_script)]
        else:
            message = (
                "No usable prepare_build script found. Expected "
                f"{sh_script} on Linux or {ps_script} on Windows. Skipping."
            )
            logger.warning(message)
            if on_output:
                on_output(f"WARNING: {message}")
            return

        self._run_streamed(command, on_output=on_output)

    def build(self, on_output=None) -> None:
        """Run docker compose build for the full stack."""
        self._run_streamed(["docker", "compose", "build"], on_output=on_output)

    def start(self, on_output=None) -> None:
        """Start the full REXDR stack in detached mode."""
        self._run_streamed(["docker", "compose", "up", "-d"], on_output=on_output)

    def stop(self, on_output=None) -> None:
        """Stop the full REXDR stack without removing volumes."""
        self._run_streamed(["docker", "compose", "down"], on_output=on_output)

    def restart_service(self, service_name: str, on_output=None) -> None:
        """Restart a single engine service by its compose service name."""
        self._run_streamed(["docker", "compose", "restart", service_name], on_output=on_output)

    def stop_service(self, service_name: str, on_output=None) -> None:
        """Stop a single engine service without affecting the others."""
        self._run_streamed(["docker", "compose", "stop", service_name], on_output=on_output)

    def start_service(self, service_name: str, on_output=None) -> None:
        """Start a single previously-stopped engine service."""
        self._run_streamed(["docker", "compose", "start", service_name], on_output=on_output)

    def get_logs(self, service_name: str, lines: int = 200) -> str:
        """Get the last N log lines for a single service."""
        try:
            result = subprocess.run(
                ["docker", "compose", "logs", "--tail", str(lines), service_name],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError:
            return "ERROR: docker not found on PATH."
        except subprocess.TimeoutExpired:
            return "ERROR: docker compose logs timed out."

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
        so the dashboard always shows every row.
        """
        statuses = {name: EngineStatus.STOPPED for name in ENGINE_SERVICE_NAMES}

        try:
            result = subprocess.run(
                ["docker", "compose", "ps", "--all", "--format", "json"],
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error("docker compose ps failed - error=%s", str(e))
            return {name: EngineStatus.UNKNOWN for name in ENGINE_SERVICE_NAMES}

        if result.returncode != 0:
            logger.warning(
                "docker compose ps returned non-zero - stderr=%s",
                result.stderr.strip()[:200],
            )
            return statuses

        for container in self._parse_ps_output(result.stdout):
            service = container.get("Service")
            if service in statuses:
                statuses[service] = self._map_docker_state(container)

        return statuses

    @staticmethod
    def _parse_ps_output(stdout: str) -> list[dict]:
        """
        Parse `docker compose ps --format json`. Compose v2 changed this
        output partway through its life - older builds emit a single JSON
        array, newer ones emit one object per line. Handle both rather
        than assuming, since a mismatch here silently blanks the whole
        dashboard.
        """
        text = stdout.strip()
        if not text:
            return []

        containers: list[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, list):
                containers.extend(c for c in parsed if isinstance(c, dict))
            elif isinstance(parsed, dict):
                containers.append(parsed)

        if containers:
            return containers

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Could not parse docker compose ps output")
            return []

        if isinstance(parsed, list):
            return [c for c in parsed if isinstance(c, dict)]
        if isinstance(parsed, dict):
            return [parsed]
        return []

    def _map_docker_state(self, container: dict) -> EngineStatus:
        state = str(container.get("State", "")).lower()
        health = str(container.get("Health", "")).lower()

        # A crash-looping container reports state=restarting. Showing that
        # as "stopped" hides the most important failure mode there is.
        if state == "restarting":
            return EngineStatus.UNHEALTHY

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
        on_output callback in real time. Failures to even launch the
        command are reported through the same callback - previously they
        raised inside a daemon thread, so the UI just sat there looking
        like the button did nothing.
        """
        def emit(line: str) -> None:
            logger.debug(line)
            if on_output:
                on_output(line)

        try:
            process = subprocess.Popen(
                command,
                cwd=self.repo_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            emit(f"ERROR: command not found: {command[0]}")
            return
        except OSError as e:
            emit(f"ERROR: could not run {' '.join(command)}: {e}")
            return

        try:
            for line in process.stdout:
                emit(line.rstrip())
            process.wait()
        except Exception as e:
            emit(f"ERROR: while running {command[0]}: {e}")
            return

        if process.returncode != 0:
            emit(f"ERROR: exit code {process.returncode}: {' '.join(command)}")

    def run_async(self, fn, *args, **kwargs) -> threading.Thread:
        """
        Run any of this class's methods on a background thread so the
        Tkinter main loop never blocks during long-running Docker
        operations. Exceptions are logged rather than lost silently,
        which is what a bare daemon thread would otherwise do.
        """
        def safe_target():
            try:
                fn(*args, **kwargs)
            except Exception:
                logger.exception("Background launcher task failed")

        thread = threading.Thread(target=safe_target, daemon=True)
        thread.start()
        return thread