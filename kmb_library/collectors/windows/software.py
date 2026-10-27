"""Collecte : inventaire des logiciels installés (registre Uninstall), avec nettoyage.

Les entrées brutes du registre contiennent des composants système, des mises à jour et
des doublons (64 bits / 32 bits / utilisateur). On les filtre ici et on garde les statistiques
du nettoyage pour pouvoir montrer l'avant/après.
"""

from __future__ import annotations

import re

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, iso

NAME = "software"
LABEL = "Logiciels installés"

_UNINSTALL = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "machine", "64"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "machine", "32"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "utilisateur", ""),
]
_SKIP_RELEASE = {"update", "hotfix", "security update", "service pack"}


def _read_entries() -> list[dict]:
    import winreg

    roots = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    entries = []
    for hive, path, scope, arch in _UNINSTALL:
        try:
            key = winreg.OpenKey(roots[hive], path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except OSError:
            continue
        with key:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(key, sub) as sk:
                        vals = {}
                        j = 0
                        while True:
                            try:
                                n, v, _ = winreg.EnumValue(sk, j)
                            except OSError:
                                break
                            vals[n] = v
                            j += 1
                except OSError:
                    continue
                vals["_scope"], vals["_arch"] = scope, arch
                entries.append(vals)
    return entries


def clean_entries(entries: list[dict]) -> tuple[list[dict], dict]:
    """Filtre et normalise les entrées brutes. Retourne (logiciels, statistiques)."""
    stats = {"raw_entries": len(entries), "without_name": 0, "system_components": 0, "updates": 0, "duplicates": 0}
    seen: set[tuple[str, str]] = set()
    apps: list[dict] = []
    for e in entries:
        name = str(e.get("DisplayName") or "").strip()
        if not name:
            stats["without_name"] += 1
            continue
        if e.get("SystemComponent") == 1:
            stats["system_components"] += 1
            continue
        if e.get("ParentKeyName") or str(e.get("ReleaseType") or "").lower() in _SKIP_RELEASE or re.match(r"^(Security )?Update for|^Mise à jour", name):
            stats["updates"] += 1
            continue
        version = str(e.get("DisplayVersion") or "").strip() or None
        ident = (name.lower(), (version or "").lower())
        if ident in seen:
            stats["duplicates"] += 1
            continue
        seen.add(ident)
        size_kb = e.get("EstimatedSize")
        apps.append({
            "name": re.sub(r"\s+", " ", name),
            "version": version,
            "publisher": (str(e.get("Publisher")).strip() or None) if e.get("Publisher") else None,
            "install_date": iso(e.get("InstallDate")),
            "size_mb": round(size_kb / 1024, 1) if isinstance(size_kb, int) and size_kb > 0 else None,
            "scope": e["_scope"],
            "arch": e["_arch"] or None,
            "install_location": (str(e.get("InstallLocation") or "").strip().strip('"') or None),
        })
    apps.sort(key=lambda a: a["name"].lower())
    stats["kept"] = len(apps)
    return apps, stats


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    entries = attempt(errors, "registry", _read_entries, []) or []
    apps, stats = clean_entries(entries)
    ctx.shared["installed_apps"] = apps
    return {"installed": apps, "cleaning": stats, "_errors": errors}
