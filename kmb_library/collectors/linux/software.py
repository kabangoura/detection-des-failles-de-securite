"""Collecte Linux : paquets installés (dpkg, rpm, pacman) et applications Flatpak / Snap."""

from __future__ import annotations

import re
import shutil

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, run_cmd

NAME = "software"
LABEL = "Logiciels installés"


def parse_dpkg(text: str) -> list[dict]:
    """dpkg-query -W -f='${Package}\\t${Version}\\t${Installed-Size}\\t${db:Status-Abbrev}\\n' (taille en Ko)."""
    apps = []
    for line in text.splitlines():
        cols = line.split("\t")
        if len(cols) < 4 or not cols[3].startswith("ii"):
            continue
        size = int(cols[2]) if cols[2].isdigit() else None
        apps.append({"name": cols[0], "version": cols[1], "size_mb": round(size / 1024, 1) if size else None, "source": "dpkg"})
    return apps


def parse_rpm(text: str) -> list[dict]:
    """rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{SIZE}\\n' (taille en octets)."""
    apps = []
    for line in text.splitlines():
        cols = line.split("\t")
        if len(cols) >= 3 and cols[0] != "gpg-pubkey":
            size = int(cols[2]) if cols[2].isdigit() else None
            apps.append({"name": cols[0], "version": cols[1], "size_mb": round(size / 1048576, 1) if size else None, "source": "rpm"})
    return apps


def parse_pacman(text: str) -> list[dict]:
    return [{"name": c[0], "version": c[1], "size_mb": None, "source": "pacman"}
            for c in (line.split() for line in text.splitlines()) if len(c) >= 2]


def parse_flatpak(text: str) -> list[dict]:
    return [{"name": c[0], "version": c[1] or None, "size_mb": None, "source": "flatpak"}
            for c in (line.split("\t") for line in text.splitlines()) if len(c) >= 2]


def parse_snap(text: str) -> list[dict]:
    lines = text.splitlines()[1:]
    return [{"name": c[0], "version": c[1], "size_mb": None, "source": "snap"}
            for c in (re.split(r"\s+", line.strip()) for line in lines) if len(c) >= 2]


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    apps: list[dict] = []
    manager = None
    if shutil.which("dpkg-query"):
        manager = "dpkg"
        apps += attempt(errors, "dpkg", lambda: parse_dpkg(run_cmd(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Installed-Size}\t${db:Status-Abbrev}\n"], timeout=60)), []) or []
    elif shutil.which("rpm"):
        manager = "rpm"
        apps += attempt(errors, "rpm", lambda: parse_rpm(run_cmd(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{SIZE}\n"], timeout=60)), []) or []
    elif shutil.which("pacman"):
        manager = "pacman"
        apps += attempt(errors, "pacman", lambda: parse_pacman(run_cmd(["pacman", "-Q"], timeout=60)), []) or []
    raw_count = len(apps)
    if shutil.which("flatpak"):
        apps += attempt(errors, "flatpak", lambda: parse_flatpak(run_cmd(["flatpak", "list", "--app", "--columns=name,version"])), []) or []
    if shutil.which("snap"):
        apps += attempt(errors, "snap", lambda: parse_snap(run_cmd(["snap", "list"])), []) or []
    seen, unique = set(), []
    for a in apps:
        key = (a["name"], a["version"])
        if key not in seen:
            seen.add(key)
            unique.append({**a, "publisher": None, "install_date": None, "scope": "machine", "arch": None})
    unique.sort(key=lambda a: a["name"].lower())
    ctx.shared["installed_apps"] = unique
    stats = {"raw_entries": len(apps), "system_packages": raw_count, "duplicates": len(apps) - len(unique),
             "without_name": 0, "system_components": 0, "updates": 0, "kept": len(unique), "package_manager": manager}
    return {"installed": unique, "cleaning": stats, "_errors": errors}
