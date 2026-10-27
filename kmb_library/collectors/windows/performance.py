"""Collecte : processeur, mémoire, processus gourmands, programmes au démarrage, batterie."""

from __future__ import annotations

import os
from pathlib import Path

from kmb_library.collectors.common import performance_snapshot
from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, read_reg

NAME = "performance"
LABEL = "Performance"

_RUN_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "machine"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "machine"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "utilisateur"),
]
_APPROVED = {
    "HKLM": [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"],
    "HKCU": [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder"],
}


def _disabled_startup() -> set[str]:
    """Le gestionnaire des tâches marque les entrées désactivées dans StartupApproved (1er octet impair)."""
    disabled = set()
    for hive, paths in _APPROVED.items():
        for path in paths:
            try:
                values = read_reg(hive, path) or {}
            except OSError:
                continue
            for name, blob in values.items():
                if isinstance(blob, bytes) and blob and blob[0] % 2 == 1:
                    disabled.add(name.lower())
    return disabled


def _startup_programs() -> list[dict]:
    disabled = _disabled_startup()
    items = []
    for hive, path, scope in _RUN_KEYS:
        try:
            values = read_reg(hive, path) or {}
        except OSError:
            continue
        for name, cmd in values.items():
            items.append({"name": name, "command": str(cmd)[:200], "source": f"{hive}\\Run", "scope": scope,
                          "enabled": name.lower() not in disabled})
    folders = [
        (Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup", "utilisateur"),
        (Path(os.environ.get("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\StartUp", "machine"),
    ]
    for folder, scope in folders:
        if folder.is_dir():
            for f in folder.iterdir():
                if f.name.lower() == "desktop.ini":
                    continue
                items.append({"name": f.stem, "command": f.name, "source": "Dossier Démarrage", "scope": scope,
                              "enabled": f.name.lower() not in disabled})
    return items


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    data = attempt(errors, "cpu", performance_snapshot, {}) or {}
    if data.get("cpu"):
        data["cpu"]["temperature_c"] = None  # non exposé par Windows sans pilote ou outil tiers
    data["startup"] = attempt(errors, "startup", _startup_programs)
    data["_errors"] = errors
    return data
