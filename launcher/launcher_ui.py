"""
rexdr - Launcher
launcher_ui.py - Tkinter UI - configuration wizard, monitor, dashboard

Author  : Rayyan Umair
Date    : 2026-06-20
Purpose : The actual Tkinter window. Three views in one window: the
          first-run configuration wizard, the launch monitor showing
          live Docker output, and the persistent status dashboard with
          per-engine controls. This is the single entry point every
          REXDR user interacts with - it has to feel considered, not
          like a thin wrapper around a shell script.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"The foundation everything else is built on."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

# -- Internal ----------------------------------------------------------------
from launcher.config_writer import ConfigWriter
from launcher.engine_manager import EngineManager, EngineStatus, ENGINE_SERVICE_NAMES
from launcher.targets_editor import TargetsEditorWindow

# ============================================================================

COLORS = {
    "bg":             "#0A0A0C",
    "surface":        "#13131A",
    "surface_raised": "#1A1A24",
    "border":         "#26262F",
    "text":           "#F4F4F8",
    "text_secondary": "#8E8EA3",
    "text_tertiary":  "#5C5C6C",
    "accent":         "#00FFD1",
    "success":        "#3DDC84",
    "warning":        "#FFD23F",
    "danger":         "#FF4D5E",
}

STATUS_COLORS = {
    EngineStatus.HEALTHY:   COLORS["success"],
    EngineStatus.STARTING:  COLORS["warning"],
    EngineStatus.DEGRADED:  COLORS["warning"],
    EngineStatus.UNHEALTHY: COLORS["danger"],
    EngineStatus.STOPPED:   COLORS["text_tertiary"],
    EngineStatus.UNKNOWN:   COLORS["text_tertiary"],
}

ENGINE_DISPLAY_NAMES = {
    "windows-event":   "Windows Event Intelligence",
    "network-flow":    "Network Flow Intelligence",
    "siem":            "SIEM Correlation",
    "dns":             "DNS Behavioral Intelligence",
    "identity":        "Active Directory Intelligence",
    "response":        "Incident Response Orchestration",
    "asset-discovery": "Network Discovery",
    "vulnerability":   "Vulnerability Intelligence",
    "frontend":        "Frontend",
    "nginx":           "Gateway",
}


class RexdrLauncher(tk.Tk):
    """The main REXDR launcher window."""

    def __init__(self, repo_root: Path) -> None:
        super().__init__()
        self.repo_root = repo_root
        self.config_writer = ConfigWriter(repo_root)
        self.engine_manager = EngineManager(repo_root)

        self.title("REXDR Launcher")
        self.geometry("760x640")
        self.minsize(680, 560)
        self.configure(bg=COLORS["bg"])

        self._build_style()
        self._build_layout()

        self._dashboard_active = False

        existing_env = self.config_writer.read_env()
        if existing_env.get("WINRM_USERNAME"):
            self._show_dashboard()
        else:
            self._show_wizard()

    # -------------------------------------------------------------------------
    # Style
    # -------------------------------------------------------------------------

    def _build_style(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(
            "TFrame", background=COLORS["bg"],
        )
        style.configure(
            "Card.TFrame", background=COLORS["surface"],
        )
        style.configure(
            "TLabel", background=COLORS["bg"], foreground=COLORS["text"],
            font=("Segoe UI", 10),
        )
        style.configure(
            "Header.TLabel", background=COLORS["bg"], foreground=COLORS["text"],
            font=("Segoe UI", 16, "bold"),
        )
        style.configure(
            "Sub.TLabel", background=COLORS["bg"], foreground=COLORS["text_secondary"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "TEntry", fieldbackground=COLORS["surface_raised"], foreground=COLORS["text"],
            insertcolor=COLORS["text"], borderwidth=1,
        )
        style.configure(
            "Accent.TButton", background=COLORS["accent"], foreground="#0A0A0C",
            font=("Segoe UI", 10, "bold"), borderwidth=0, padding=10,
        )
        style.map("Accent.TButton", background=[("active", "#00E0BA")])
        style.configure(
            "Secondary.TButton", background=COLORS["surface_raised"], foreground=COLORS["text"],
            font=("Segoe UI", 9), borderwidth=1, padding=8,
        )

    def _build_layout(self) -> None:
        self.container = ttk.Frame(self, style="TFrame")
        self.container.pack(fill="both", expand=True)

    def _clear_container(self) -> None:
        for widget in self.container.winfo_children():
            widget.destroy()

    # -------------------------------------------------------------------------
    # Wizard
    # -------------------------------------------------------------------------

    def _show_wizard(self) -> None:
        self._dashboard_active = False
        self._clear_container()
        existing = self.config_writer.read_env()

        wrapper = ttk.Frame(self.container, style="TFrame", padding=28)
        wrapper.pack(fill="both", expand=True)

        ttk.Label(wrapper, text="Configure REXDR", style="Header.TLabel").pack(anchor="w")
        ttk.Label(
            wrapper,
            text="These values are written to .env and used by every engine on startup.",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(2, 20))

        fields_frame = ttk.Frame(wrapper, style="TFrame")
        fields_frame.pack(fill="both", expand=True)

        self.wizard_vars = {}

        sections = [
            ("Active Directory", [
                ("WINRM_USERNAME", "Domain admin username", False),
                ("WINRM_PASSWORD", "Password", True),
                ("LDAP_BASE_DN", "LDAP base DN (e.g. DC=corp,DC=local)", False),
                ("LDAP_DOMAIN", "Domain name (e.g. corp.local)", False),
            ]),
            ("Network Capture", [
                ("CAPTURE_INTERFACE", "Capture interface (e.g. eth0)", False),
            ]),
            ("AI Assistant (optional)", [
                ("AI_PROVIDER", "Provider - groq, openai, anthropic, gemini, ollama", False),
                ("AI_API_KEY", "API key", True),
            ]),
            ("Vulnerability Intelligence (optional)", [
                ("NVD_API_KEY", "NVD API key", True),
            ]),
        ]

        for section_title, fields in sections:
            ttk.Label(fields_frame, text=section_title, style="TLabel",
                      font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(12, 6))

            for key, label, is_secret in fields:
                row = ttk.Frame(fields_frame, style="TFrame")
                row.pack(fill="x", pady=3)
                ttk.Label(row, text=label, style="Sub.TLabel", width=42, anchor="w").pack(side="left")

                var = tk.StringVar(value=existing.get(key, ""))
                self.wizard_vars[key] = var
                entry = ttk.Entry(row, textvariable=var, show="*" if is_secret else "")
                entry.pack(side="left", fill="x", expand=True)

        button_row = ttk.Frame(wrapper, style="TFrame")
        button_row.pack(fill="x", pady=(20, 0))

        ttk.Button(
            button_row, text="Edit Network Targets",
            style="Secondary.TButton",
            command=self._open_targets_editor,
        ).pack(side="left")

        ttk.Button(
            button_row, text="Save and Continue",
            style="Accent.TButton",
            command=self._save_wizard,
        ).pack(side="right")

    def _open_targets_editor(self) -> None:
        TargetsEditorWindow(self, self.config_writer)

    def _save_wizard(self) -> None:
        values = {key: var.get().strip() for key, var in self.wizard_vars.items()}

        try:
            self.config_writer.write_env(values)
        except ValueError as e:
            messagebox.showerror("Missing configuration", str(e))
            return

        self._show_dashboard()

    # -------------------------------------------------------------------------
    # Dashboard
    # -------------------------------------------------------------------------

    def _show_dashboard(self) -> None:
        self._dashboard_active = True
        self._clear_container()

        top = ttk.Frame(self.container, style="TFrame", padding=(24, 20, 24, 12))
        top.pack(fill="x")

        ttk.Label(top, text="REXDR", style="Header.TLabel").pack(side="left")

        button_group = ttk.Frame(top, style="TFrame")
        button_group.pack(side="right")

        ttk.Button(button_group, text="Reconfigure", style="Secondary.TButton",
                   command=self._show_wizard).pack(side="left", padx=4)
        ttk.Button(button_group, text="Build", style="Secondary.TButton",
                   command=self._on_build).pack(side="left", padx=4)
        ttk.Button(button_group, text="Start All", style="Accent.TButton",
                   command=self._on_start_all).pack(side="left", padx=4)
        ttk.Button(button_group, text="Stop All", style="Secondary.TButton",
                   command=self._on_stop_all).pack(side="left", padx=4)

        # -- Status rows ----------------------------------------------------------
        status_frame = ttk.Frame(self.container, style="TFrame", padding=(24, 4, 24, 4))
        status_frame.pack(fill="both", expand=True)

        self.status_rows = {}
        for service in ENGINE_SERVICE_NAMES:
            row = self._build_status_row(status_frame, service)
            row.pack(fill="x", pady=3)

        # -- Log monitor ------------------------------------------------------------
        log_frame = ttk.Frame(self.container, style="Card.TFrame", padding=10)
        log_frame.pack(fill="both", expand=False, padx=24, pady=(8, 16))

        ttk.Label(log_frame, text="Launch Monitor", style="TLabel",
                  font=("Segoe UI", 9, "bold"), background=COLORS["surface"]).pack(anchor="w")

        self.log_text = tk.Text(
            log_frame, height=8, bg=COLORS["surface_raised"], fg=COLORS["text_secondary"],
            insertbackground=COLORS["text"], borderwidth=0, font=("Consolas", 9),
            wrap="word",
        )
        self.log_text.pack(fill="both", expand=True, pady=(6, 0))

        self._poll_status()

    def _build_status_row(self, parent, service: str) -> ttk.Frame:
        row = ttk.Frame(parent, style="Card.TFrame", padding=10)

        dot = tk.Canvas(row, width=12, height=12, bg=COLORS["surface"], highlightthickness=0)
        dot.pack(side="left", padx=(2, 10))
        dot_id = dot.create_oval(2, 2, 10, 10, fill=COLORS["text_tertiary"], outline="")

        name_label = ttk.Label(
            row, text=ENGINE_DISPLAY_NAMES.get(service, service),
            background=COLORS["surface"], foreground=COLORS["text"],
            font=("Segoe UI", 10),
        )
        name_label.pack(side="left")

        status_label = ttk.Label(
            row, text="stopped", background=COLORS["surface"], foreground=COLORS["text_tertiary"],
            font=("Segoe UI", 9),
        )
        status_label.pack(side="left", padx=12)

        controls = ttk.Frame(row, style="Card.TFrame")
        controls.pack(side="right")

        ttk.Button(controls, text="Restart", style="Secondary.TButton",
                   command=lambda: self._on_restart_service(service)).pack(side="left", padx=2)
        ttk.Button(controls, text="Logs", style="Secondary.TButton",
                   command=lambda: self._show_logs(service)).pack(side="left", padx=2)

        self.status_rows[service] = {"dot": dot, "dot_id": dot_id, "label": status_label}
        return row

    # -------------------------------------------------------------------------
    # Actions
    # -------------------------------------------------------------------------

    def _append_log(self, line: str) -> None:
        self.log_text.insert("end", line + "\n")
        self.log_text.see("end")

    def _on_build(self) -> None:
        self._append_log("Preparing build - distributing rexdr_core wheel...")
        self.engine_manager.run_async(
            self._build_sequence
        )

    def _build_sequence(self) -> None:
        self.engine_manager.prepare_build(on_output=self._append_log)
        self._append_log("Building all engine images...")
        self.engine_manager.build(on_output=self._append_log)
        self._append_log("Build complete.")

    def _on_start_all(self) -> None:
        self._append_log("Starting REXDR platform...")
        self.engine_manager.run_async(
            self.engine_manager.start, on_output=self._append_log
        )

    def _on_stop_all(self) -> None:
        self._append_log("Stopping REXDR platform...")
        self.engine_manager.run_async(
            self.engine_manager.stop, on_output=self._append_log
        )

    def _on_restart_service(self, service: str) -> None:
        self._append_log(f"Restarting {service}...")
        self.engine_manager.run_async(
            self.engine_manager.restart_service, service, on_output=self._append_log
        )

    def _show_logs(self, service: str) -> None:
        logs = self.engine_manager.get_logs(service, lines=300)

        window = tk.Toplevel(self)
        window.title(f"Logs - {ENGINE_DISPLAY_NAMES.get(service, service)}")
        window.geometry("700x500")
        window.configure(bg=COLORS["bg"])

        text = tk.Text(
            window, bg=COLORS["surface_raised"], fg=COLORS["text_secondary"],
            font=("Consolas", 9), wrap="word",
        )
        text.pack(fill="both", expand=True, padx=12, pady=12)
        text.insert("end", logs or "(no log output yet)")
        text.config(state="disabled")

    # -------------------------------------------------------------------------
    # Status polling
    # -------------------------------------------------------------------------

    def _poll_status(self) -> None:
        if not self._dashboard_active:
            return

        statuses = self.engine_manager.get_status()

        if not self._dashboard_active:
            return

        for service, status in statuses.items():
            row = self.status_rows.get(service)
            if not row:
                continue
            color = STATUS_COLORS.get(status, COLORS["text_tertiary"])
            row["dot"].itemconfig(row["dot_id"], fill=color)
            row["label"].config(text=status.value, foreground=color)

        self.after(5000, self._poll_status)