"""Collecte macOS : processeur, mémoire, agents et démons lancés au démarrage (hors Apple)."""

from __future__ import annotations

import plistlib
from pathlib import Path

from kmb_library.collectors.common import performance_snapshot
from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt

NAME = "performance"
LABEL = "Performance"

LAUNCH_DIRS = [
    (Path.home() / "Library/LaunchAgents", "utilisateur"),
    (Path("/Library/LaunchAgents"), "machine"),
    (Path("/Library/LaunchDaemons"), "machine (démon)"),
]


def read_launch_item(path: Path) -> dict | None:
    try:
        plist = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None
    label = str(plist.get("Label", path.stem))
    if label.startswith("com.apple."):
        return None
    program = plist.get("Program") or " ".join(plist.get("ProgramArguments", [])[:3])
    return {"name": label, "command": str(program)[:200], "enabled": not plist.get("Disabled", False),
            "run_at_load": bool(plist.get("RunAtLoad") or plist.get("KeepAlive"))}


def _startup() -> list[dict]:
    items = []
    for folder, scope in LAUNCH_DIRS:
        if folder.is_dir():
            for f in folder.glob("*.plist"):
                item = read_launch_item(f)
                if item:
                    items.append({**item, "source": str(folder).replace(str(Path.home()), "~"), "scope": scope})
    return items


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    data = attempt(errors, "cpu", performance_snapshot, {}) or {}
    if data.get("cpu"):
        data["cpu"]["temperature_c"] = None  # capteurs non accessibles sans outil tiers
    data["startup"] = attempt(errors, "startup", _startup)
    data["_errors"] = errors
    return data
