"""
rexdr - Launcher
targets_editor.py - GUI editor for targets.yaml and zones.yaml

Author  : Rayyan Umair
Date    : 2026-06-21
Purpose : A secondary Tkinter window for managing the list of Windows
          machines REXDR collects from, and the network zones used for
          cross-zone detection. Opened from the main wizard rather than
          embedded inline, since this list can grow long in a real
          enterprise environment and deserves its own focused space.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"The foundation everything else is built on."

--- Part of the REXDR platform. ---
"""

# -- Standard Library --------------------------------------------------------
import tkinter as tk
from tkinter import ttk, messagebox

# ============================================================================

COLORS = {
    "bg":             "#0A0A0C",
    "surface":        "#13131A",
    "surface_raised":  "#1A1A24",
    "text":           "#F4F4F8",
    "text_secondary": "#8E8EA3",
    "accent":         "#00FFD1",
    "danger":         "#FF4D5E",
}

PRIORITIES = ["critical", "high", "normal"]


class TargetsEditorWindow(tk.Toplevel):
    """Secondary window for editing targets.yaml and zones.yaml."""

    def __init__(self, parent, config_writer) -> None:
        super().__init__(parent)
        self.config_writer = config_writer

        self.title("Network Targets and Zones")
        self.geometry("680x560")
        self.configure(bg=COLORS["bg"])

        self.targets = config_writer.read_targets()
        self.zones = config_writer.read_zones()

        self._build_notebook()

    def _build_notebook(self) -> None:
        style = ttk.Style(self)
        style.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=COLORS["surface"], foreground=COLORS["text"], padding=10)

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=12, pady=12)

        self.targets_tab = ttk.Frame(notebook)
        self.zones_tab = ttk.Frame(notebook)

        notebook.add(self.targets_tab, text="Windows Targets")
        notebook.add(self.zones_tab, text="Network Zones")

        self._build_targets_tab()
        self._build_zones_tab()

    # -------------------------------------------------------------------------
    # Targets tab
    # -------------------------------------------------------------------------

    def _build_targets_tab(self) -> None:
        self.targets_tab.configure(style="TFrame")

        list_frame = tk.Frame(self.targets_tab, bg=COLORS["bg"])
        list_frame.pack(fill="both", expand=True, padx=8, pady=8)

        self.targets_listbox = tk.Listbox(
            list_frame, bg=COLORS["surface_raised"], fg=COLORS["text"],
            selectbackground=COLORS["accent"], selectforeground="#0A0A0C",
            font=("Consolas", 10), height=14, borderwidth=0,
        )
        self.targets_listbox.pack(fill="both", expand=True)
        self._refresh_targets_list()

        form = tk.Frame(self.targets_tab, bg=COLORS["bg"])
        form.pack(fill="x", padx=8, pady=(0, 8))

        self.target_name = tk.StringVar()
        self.target_ip = tk.StringVar()
        self.target_priority = tk.StringVar(value="normal")

        self._labeled_entry(form, "Name (DC01)", self.target_name, 0)
        self._labeled_entry(form, "IP Address", self.target_ip, 1)

        tk.Label(form, text="Priority", bg=COLORS["bg"], fg=COLORS["text_secondary"]).grid(row=2, column=0, sticky="w", pady=4)
        priority_menu = ttk.Combobox(form, textvariable=self.target_priority, values=PRIORITIES, state="readonly")
        priority_menu.grid(row=2, column=1, sticky="ew", pady=4)

        form.columnconfigure(1, weight=1)

        button_row = tk.Frame(self.targets_tab, bg=COLORS["bg"])
        button_row.pack(fill="x", padx=8, pady=(0, 8))

        tk.Button(button_row, text="Add Target", command=self._add_target,
                   bg=COLORS["accent"], fg="#0A0A0C", borderwidth=0, padx=12, pady=6).pack(side="left")
        tk.Button(button_row, text="Remove Selected", command=self._remove_target,
                   bg=COLORS["surface_raised"], fg=COLORS["text"], borderwidth=0, padx=12, pady=6).pack(side="left", padx=6)
        tk.Button(button_row, text="Save", command=self._save_targets,
                   bg=COLORS["surface_raised"], fg=COLORS["accent"], borderwidth=0, padx=12, pady=6).pack(side="right")

    def _refresh_targets_list(self) -> None:
        self.targets_listbox.delete(0, "end")
        for t in self.targets:
            self.targets_listbox.insert(
                "end", f"{t['name']:<16} {t['ip']:<16} {t.get('priority', 'normal')}"
            )

    def _add_target(self) -> None:
        name = self.target_name.get().strip()
        ip = self.target_ip.get().strip()
        priority = self.target_priority.get()

        if not name or not ip:
            messagebox.showerror("Missing fields", "Name and IP address are required.")
            return

        self.targets.append({
            "name": name,
            "ip": ip,
            "method": "winrm",
            "credentials": "domain_admin",
            "logs": ["Security", "System", "Application"],
            "priority": priority,
            "enabled": True,
        })

        self.target_name.set("")
        self.target_ip.set("")
        self._refresh_targets_list()

    def _remove_target(self) -> None:
        selection = self.targets_listbox.curselection()
        if not selection:
            return
        del self.targets[selection[0]]
        self._refresh_targets_list()

    def _save_targets(self) -> None:
        try:
            self.config_writer.write_targets(self.targets)
            messagebox.showinfo("Saved", "targets.yaml has been updated.")
        except ValueError as e:
            messagebox.showerror("Invalid target", str(e))

    # -------------------------------------------------------------------------
    # Zones tab
    # -------------------------------------------------------------------------

    def _build_zones_tab(self) -> None:
        list_frame = tk.Frame(self.zones_tab, bg=COLORS["bg"])
        list_frame.pack(fill="both", expand=True, padx=8, pady=8)

        self.zones_listbox = tk.Listbox(
            list_frame, bg=COLORS["surface_raised"], fg=COLORS["text"],
            selectbackground=COLORS["accent"], selectforeground="#0A0A0C",
            font=("Consolas", 10), height=14, borderwidth=0,
        )
        self.zones_listbox.pack(fill="both", expand=True)
        self._refresh_zones_list()

        form = tk.Frame(self.zones_tab, bg=COLORS["bg"])
        form.pack(fill="x", padx=8, pady=(0, 8))

        self.zone_id = tk.StringVar()
        self.zone_name = tk.StringVar()
        self.zone_cidr = tk.StringVar()
        self.zone_trusted = tk.BooleanVar(value=True)
        self.zone_critical = tk.BooleanVar(value=False)

        self._labeled_entry(form, "Zone ID (staff_vlan)", self.zone_id, 0)
        self._labeled_entry(form, "Display Name", self.zone_name, 1)
        self._labeled_entry(form, "CIDR (10.10.3.0/24)", self.zone_cidr, 2)

        tk.Checkbutton(form, text="Trusted zone", variable=self.zone_trusted,
                       bg=COLORS["bg"], fg=COLORS["text"], selectcolor=COLORS["surface_raised"],
                       activebackground=COLORS["bg"]).grid(row=3, column=0, sticky="w", pady=4)
        tk.Checkbutton(form, text="Critical zone", variable=self.zone_critical,
                       bg=COLORS["bg"], fg=COLORS["text"], selectcolor=COLORS["surface_raised"],
                       activebackground=COLORS["bg"]).grid(row=3, column=1, sticky="w", pady=4)

        form.columnconfigure(1, weight=1)

        button_row = tk.Frame(self.zones_tab, bg=COLORS["bg"])
        button_row.pack(fill="x", padx=8, pady=(0, 8))

        tk.Button(button_row, text="Add Zone", command=self._add_zone,
                   bg=COLORS["accent"], fg="#0A0A0C", borderwidth=0, padx=12, pady=6).pack(side="left")
        tk.Button(button_row, text="Remove Selected", command=self._remove_zone,
                   bg=COLORS["surface_raised"], fg=COLORS["text"], borderwidth=0, padx=12, pady=6).pack(side="left", padx=6)
        tk.Button(button_row, text="Save", command=self._save_zones,
                   bg=COLORS["surface_raised"], fg=COLORS["accent"], borderwidth=0, padx=12, pady=6).pack(side="right")

    def _refresh_zones_list(self) -> None:
        self.zones_listbox.delete(0, "end")
        for z in self.zones:
            self.zones_listbox.insert(
                "end", f"{z['zone_id']:<16} {z['cidr']:<18} {z['display_name']}"
            )

    def _add_zone(self) -> None:
        zone_id = self.zone_id.get().strip()
        name = self.zone_name.get().strip()
        cidr = self.zone_cidr.get().strip()

        if not zone_id or not name or not cidr:
            messagebox.showerror("Missing fields", "Zone ID, display name, and CIDR are required.")
            return

        self.zones.append({
            "zone_id": zone_id,
            "display_name": name,
            "cidr": cidr,
            "is_trusted": self.zone_trusted.get(),
            "is_critical": self.zone_critical.get(),
        })

        self.zone_id.set("")
        self.zone_name.set("")
        self.zone_cidr.set("")
        self._refresh_zones_list()

    def _remove_zone(self) -> None:
        selection = self.zones_listbox.curselection()
        if not selection:
            return
        del self.zones[selection[0]]
        self._refresh_zones_list()

    def _save_zones(self) -> None:
        try:
            self.config_writer.write_zones(self.zones)
            messagebox.showinfo("Saved", "zones.yaml has been updated.")
        except ValueError as e:
            messagebox.showerror("Invalid zone", str(e))

    # -------------------------------------------------------------------------
    # Helper
    # -------------------------------------------------------------------------

    def _labeled_entry(self, parent, label: str, var: tk.StringVar, row: int) -> None:
        tk.Label(parent, text=label, bg=COLORS["bg"], fg=COLORS["text_secondary"]).grid(
            row=row, column=0, sticky="w", pady=4
        )
        entry = tk.Entry(
            parent, textvariable=var, bg=COLORS["surface_raised"], fg=COLORS["text"],
            insertbackground=COLORS["text"], borderwidth=0,
        )
        entry.grid(row=row, column=1, sticky="ew", pady=4, padx=(8, 0))