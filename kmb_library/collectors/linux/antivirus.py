"""Collecte Linux : antivirus installés (ClamAV et solutions commerciales courantes)."""

from __future__ import annotations

import shutil
import time
from pathlib import Path

from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, run_cmd

NAME = "antivirus"
LABEL = "Antivirus"

COMMERCIAL = {
    "/opt/sophos-spl": "Sophos", "/opt/eset": "ESET", "/opt/CrowdStrike": "CrowdStrike Falcon",
    "/opt/microsoft/mdatp": "Microsoft Defender for Endpoint", "/opt/kaspersky": "Kaspersky", "/opt/bitdefender": "Bitdefender",
}


def _active(unit: str) -> bool:
    return run_cmd(["systemctl", "is-active", unit], ok_codes=(0, 3, 4)).strip() == "active"


def _clamav() -> dict | None:
    if not (shutil.which("clamscan") or shutil.which("clamd")):
        return None
    sigs = [p for p in Path("/var/lib/clamav").glob("daily.c?d")] if Path("/var/lib/clamav").is_dir() else []
    age = round((time.time() - max(p.stat().st_mtime for p in sigs)) / 86400) if sigs else None
    enabled = shutil.which("systemctl") is not None and (_active("clamav-daemon") or _active("clamav-freshclam"))
    return {"name": "ClamAV", "enabled": enabled, "up_to_date": age is not None and age <= 7, "signature_age_days": age}


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    products = []
    clam = attempt(errors, "clamav", _clamav)
    if clam:
        products.append(clam)
    for path, name in COMMERCIAL.items():
        if Path(path).exists():
            products.append({"name": name, "enabled": True, "up_to_date": None})
    return {"products": products, "defender": None, "_errors": errors}
