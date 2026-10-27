"""Collecte Linux : partitions, disques physiques (SSD/HDD), dossiers personnels, gros fichiers."""

from __future__ import annotations

import json
import shutil

from kmb_library.collectors.common import storage_common
from kmb_library.core.context import ScanContext
from kmb_library.core.utils import attempt, is_admin, run_cmd

NAME = "storage"
LABEL = "Stockage"


def parse_lsblk_disks(doc: dict) -> list[dict]:
    disks = []
    for d in doc.get("blockdevices", []):
        if d.get("type") != "disk" or str(d.get("name", "")).startswith(("loop", "zram", "ram")):
            continue
        rota = d.get("rota")
        rota = rota if isinstance(rota, bool) else str(rota) in ("1", "true")
        disks.append({"name": (d.get("model") or d.get("name") or "").strip(), "device": d.get("name"),
                      "media_type": "HDD" if rota else "SSD", "size": d.get("size"), "health": None})
    return disks


def parse_smartctl_health(text: str) -> str | None:
    if "PASSED" in text or "SMART Health Status: OK" in text:
        return "Healthy"
    if "FAILED" in text:
        return "Unhealthy"
    return None


def _disks() -> list[dict]:
    disks = parse_lsblk_disks(json.loads(run_cmd(["lsblk", "-d", "-J", "-o", "NAME,TYPE,ROTA,SIZE,MODEL"])))
    if is_admin() and shutil.which("smartctl"):
        for d in disks:
            out = run_cmd(["smartctl", "-H", f"/dev/{d['device']}"], ok_codes=tuple(range(256)))
            d["health"] = parse_smartctl_health(out)
    return disks


def collect(ctx: ScanContext) -> dict:
    errors: dict[str, str] = {}
    data = storage_common(ctx, errors)
    data["physical_disks"] = attempt(errors, "physical_disks", _disks)
    data["_errors"] = errors
    return data
