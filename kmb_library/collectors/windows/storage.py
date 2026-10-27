"""Collecte : partitions, disques physiques, taille des dossiers personnels et gros fichiers."""

from __future__ import annotations

from kmb_library.collectors.common import storage_common
from kmb_library.core.context import ScanContext
from kmb_library.core.utils import GB, attempt, ps_json

NAME = "storage"
LABEL = "Stockage"


def _physical_disks() -> list[dict]:
    disks = ps_json(
        "Get-PhysicalDisk | Select-Object FriendlyName,MediaType,BusType,HealthStatus,OperationalStatus,Size"
    )
    return [{
        "name": d.get("FriendlyName"), "media_type": d.get("MediaType"), "bus": d.get("BusType"),
        "health": d.get("HealthStatus"), "status": d.get("OperationalStatus"),
        "size_gb": round((d.get("Size") or 0) / GB, 1),
    } for d in disks]


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    data = storage_common(ctx, errors)
    data["physical_disks"] = attempt(errors, "physical_disks", _physical_disks)
    data["_errors"] = errors
    return data
