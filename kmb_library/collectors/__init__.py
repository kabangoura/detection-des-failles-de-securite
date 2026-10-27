"""Collecteurs : chacun lit une partie du poste et retourne des données brutes (aucun jugement).

Les collecteurs propres à un système sont dans windows/, linux/ et macos/ ; ils produisent
des données de même forme, ce qui permet de réutiliser les mêmes règles sur les trois systèmes.
"""

from __future__ import annotations

import importlib
import sys
from types import ModuleType

SUPPORTED = ("windows", "linux", "macos")
PER_OS = ["system", "accounts", "network", "firewall", "antivirus", "encryption", "software", "performance", "storage"]
SHARED = ["wifi", "hardware", "duplicates"]


def detect_os_family(platform: str | None = None) -> str:
    p = platform or sys.platform
    if p == "win32":
        return "windows"
    if p == "darwin":
        return "macos"
    if p.startswith("linux"):
        return "linux"
    return "unsupported"


def collectors_for(os_family: str) -> list[ModuleType]:
    if os_family not in SUPPORTED:
        raise RuntimeError(f"Système non pris en charge : {os_family}")
    mods = [importlib.import_module(f"kmb_library.collectors.{os_family}.{name}") for name in PER_OS]
    return mods + [importlib.import_module(f"kmb_library.collectors.{name}") for name in SHARED]
