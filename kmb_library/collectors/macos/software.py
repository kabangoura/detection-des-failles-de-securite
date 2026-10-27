"""Collecte macOS : applications (.app dans /Applications) et paquets Homebrew."""

from __future__ import annotations

import plistlib
import shutil
from pathlib import Path

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, run_cmd

NAME = "software"
LABEL = "Logiciels installés"


def read_app(app: Path) -> dict | None:
    info = app / "Contents" / "Info.plist"
    try:
        plist = plistlib.loads(info.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None
    bundle = str(plist.get("CFBundleIdentifier", ""))
    vendor = bundle.split(".")[1].capitalize() if bundle.count(".") >= 2 else None
    return {"name": plist.get("CFBundleDisplayName") or plist.get("CFBundleName") or app.stem,
            "version": plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion"),
            "publisher": vendor, "bundle_id": bundle, "size_mb": None, "source": "app", "install_location": str(app),
            "install_date": None, "scope": "utilisateur" if str(app).startswith(str(Path.home())) else "machine", "arch": None}


def parse_brew(text: str) -> list[dict]:
    return [{"name": c[0], "version": c[-1], "publisher": "Homebrew", "size_mb": None, "source": "brew",
             "install_date": None, "scope": "machine", "arch": None}
            for c in (line.split() for line in text.splitlines()) if len(c) >= 2]


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    apps, raw = [], 0
    for folder in (Path("/Applications"), Path("/Applications/Utilities"), Path.home() / "Applications"):
        if folder.is_dir():
            for app in folder.glob("*.app"):
                raw += 1
                info = read_app(app)
                if info:
                    apps.append(info)
    if shutil.which("brew"):
        apps += attempt(errors, "brew", lambda: parse_brew(run_cmd(["brew", "list", "--versions"], timeout=60)), []) or []
    seen, unique = set(), []
    for a in apps:
        if (a["name"], a["version"]) not in seen:
            seen.add((a["name"], a["version"]))
            unique.append(a)
    unique.sort(key=lambda a: str(a["name"]).lower())
    ctx.shared["installed_apps"] = unique
    stats = {"raw_entries": raw + sum(1 for a in apps if a["source"] == "brew"), "without_name": 0, "system_components": 0,
             "updates": 0, "duplicates": len(apps) - len(unique), "kept": len(unique), "package_manager": "app+brew"}
    return {"installed": unique, "cleaning": stats, "_errors": errors}
