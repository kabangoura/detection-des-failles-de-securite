"""Collecte Linux : processeur, mémoire, température, applications au démarrage de session."""

from __future__ import annotations

import configparser
import shutil
from pathlib import Path

from kmb_library.collectors.common import performance_snapshot
from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, run_cmd

NAME = "performance"
LABEL = "Performance"


def parse_desktop_entry(text: str) -> dict | None:
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        cp.read_string(text)
    except configparser.Error:
        return None
    if "Desktop Entry" not in cp:
        return None
    e = cp["Desktop Entry"]
    disabled = e.get("Hidden", "false").lower() == "true" or e.get("X-GNOME-Autostart-enabled", "true").lower() == "false"
    return {"name": e.get("Name", "?"), "command": e.get("Exec", "")[:200], "enabled": not disabled}


def _autostart() -> list[dict]:
    items: dict[str, dict] = {}
    # Les entrées de l'utilisateur remplacent celles du système portant le même nom de fichier
    for folder, source in ((Path("/etc/xdg/autostart"), "système"), (Path.home() / ".config/autostart", "utilisateur")):
        if folder.is_dir():
            for f in folder.glob("*.desktop"):
                e = parse_desktop_entry(f.read_text(encoding="utf-8", errors="replace"))
                if e:
                    items[f.name] = {**e, "source": f"autostart ({source})", "scope": source}
    return list(items.values())


def _cpu_temperature() -> float | None:
    import psutil

    temps = getattr(psutil, "sensors_temperatures", lambda: {})() or {}
    values = [t.current for key in ("coretemp", "k10temp", "zenpower", "cpu_thermal", "acpitz") for t in temps.get(key, []) if t.current]
    return max(values) if values else None


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    data = attempt(errors, "cpu", performance_snapshot, {}) or {}
    if data.get("cpu"):
        data["cpu"]["temperature_c"] = attempt(errors, "temperature", _cpu_temperature)
    data["startup"] = attempt(errors, "startup", _autostart)
    if shutil.which("systemctl"):
        out = attempt(errors, "services", lambda: run_cmd(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend"]))
        data["services_enabled"] = len([line for line in (out or "").splitlines() if line.strip()]) if out else None
    data["_errors"] = errors
    return data
