"""Collecte macOS : chiffrement FileVault du disque de démarrage."""

from __future__ import annotations

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, run_cmd

NAME = "encryption"
LABEL = "Chiffrement"


def parse_fdesetup(text: str) -> dict:
    t = text.strip()
    low = t.lower()
    if "filevault is on" in low:
        state = "on"
    elif "in progress" in low:
        state = "in_progress"
    elif "filevault is off" in low:
        state = "off"
    else:
        state = "unsupported"
    return {"drive": "/", "state": state, "label": t.splitlines()[0] if t else "inconnu", "method": "fdesetup"}


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    vol = attempt(errors, "filevault", lambda: parse_fdesetup(run_cmd(["fdesetup", "status"])))
    return {"volumes": [vol] if vol else None, "system_drive": "/", "_errors": errors}
