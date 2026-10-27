"""Collecte macOS : partitions, disque de démarrage (SSD, état SMART), dossiers personnels."""

from __future__ import annotations

import plistlib

from kmb_library.collectors.common import storage_common
from kmb_library.core.context import ScanContext
from kmb_library.core.utils import GB, attempt, run_cmd

NAME = "storage"
LABEL = "Stockage"


def parse_diskutil_info(plist: dict) -> dict:
    smart = plist.get("SMARTStatus")
    return {
        "name": plist.get("MediaName") or plist.get("DeviceIdentifier") or "Disque de démarrage",
        "media_type": "SSD" if plist.get("SolidState") else "HDD",
        "bus": plist.get("BusProtocol"),
        "health": {"Verified": "Healthy", "Failing": "Unhealthy"}.get(smart, None) if smart else None,
        "status": smart,
        "size_gb": round((plist.get("TotalSize") or plist.get("Size") or 0) / GB, 1),
    }


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    data = storage_common(ctx, errors)
    info = attempt(errors, "physical_disks", lambda: parse_diskutil_info(plistlib.loads(run_cmd(["diskutil", "info", "-plist", "/"]).encode())))
    data["physical_disks"] = [info] if info else None
    data["_errors"] = errors
    return data
